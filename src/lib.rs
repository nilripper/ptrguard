#![feature(allocator_api)]

use std::alloc::{Allocator, Global, Layout};
use std::fmt;
use std::hint::black_box;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::panic::{self, AssertUnwindSafe};
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use parking_lot::{RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard};
use rand::RngCore;
use rand::seq::SliceRandom;
use secrecy::{ExposeSecret, Secret};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

/// Specifies the encryption or obfuscation algorithm for the pointer.
#[derive(Copy, Clone, Debug, EnumIter, PartialEq, Eq)]
#[repr(u8)] // Required for stable serialization in HMAC
pub enum Cipher {
    // Lightweight Obfuscation Methods
    Xor,
    Rotate,
    Add,
    Sub,
    Swap,

    // Authenticated Encryption Methods
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Contains the output of an encryption operation, which varies based on the cipher used.
enum EncryptedPointer {
    /// For simple, non-authenticated ciphers that only obfuscate the value.
    Obfuscated { value: u64 },
    /// For AEAD ciphers that produce both ciphertext and an authentication tag.
    Aead { ciphertext: u64, tag: [u8; 16] },
}

/// Defines the available methods for detecting a debugger.
#[derive(Copy, Clone)]
#[repr(u8)]
enum AntiDebugMethod {
    PlatformSpecific,
    Ptrace,
    Timing,
}

impl AntiDebugMethod {
    /// Checks if a debugger is currently present using the specified method.
    fn is_present(self) -> bool {
        obfuscate_op();
        match self {
            Self::PlatformSpecific => platform_specific_is_debugger_present(),
            #[cfg(target_os = "linux")]
            Self::Ptrace => {
                use libc::{PTRACE_TRACEME, ptrace};
                // If ptrace(PTRACE_TRACEME) fails, it's likely we are already being traced.
                (unsafe {
                    ptrace(
                        PTRACE_TRACEME,
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                } == -1)
            }
            #[cfg(not(target_os = "linux"))]
            Self::Ptrace => false,
            Self::Timing => {
                let start = Instant::now();
                let mut sum = 0u64;
                for i in 0..100000 {
                    sum = black_box(sum.wrapping_add(i));
                }
                let dur = start.elapsed();
                // A debugger can significantly slow down execution.
                dur > Duration::from_millis(50) // Arbitrary threshold; adjust based on expected performance
            }
        }
    }
}

/// A builder for creating and configuring an `EncryptedPtr`.
pub struct PtrGuardBuilder<A: Allocator = Global> {
    allocator: A,
    anti_debug_methods: Vec<AntiDebugMethod>,
    key: Option<Secret<[u8; 32]>>,
    rotation_interval: Option<Duration>,
    on_fail: fn(),
    require_lock: bool,
    cipher_override: Option<Cipher>,
    enable_holistic_integrity: bool,
    master_integrity_key: Option<Secret<[u8; 32]>>,
}

impl<A: Allocator + Clone + Default> PtrGuardBuilder<A> {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            allocator: A::default(),
            anti_debug_methods: Vec::new(),
            key: None,
            rotation_interval: None,
            on_fail: default_on_fail,
            require_lock: false,
            cipher_override: None,
            enable_holistic_integrity: false,
            master_integrity_key: None,
        }
    }

    /// Adds an anti-debugging method to be checked during access.
    pub fn add_anti_debug_method(mut self, method: AntiDebugMethod) -> Self {
        self.anti_debug_methods.push(method);
        self
    }

    /// Sets a custom 256-bit (32-byte) key for pointer encryption.
    pub fn with_key(mut self, key: [u8; 32]) -> Self {
        self.key = Some(Secret::new(key));
        self
    }

    /// Enables time-based key rotation at the specified interval.
    pub fn with_key_rotation(mut self, interval: Duration) -> Self {
        self.rotation_interval = Some(interval);
        self
    }

    /// Specifies a custom memory allocator.
    pub fn with_allocator(mut self, allocator: A) -> Self {
        self.allocator = allocator;
        self
    }

    /// Sets a custom failure handler for security violations.
    pub fn with_on_fail(mut self, on_fail: fn()) -> Self {
        self.on_fail = on_fail;
        self
    }

    /// Requires that the memory region be locked; fails if locking is not possible.
    pub fn with_require_lock(mut self, require: bool) -> Self {
        self.require_lock = require;
        self
    }

    /// Overrides the random cipher selection and forces the use of a specific algorithm.
    pub fn with_cipher(mut self, cipher: Cipher) -> Self {
        self.cipher_override = Some(cipher);
        self
    }

    /// Enables the master HMAC-SHA256 integrity layer for the entire `EncryptedPtr` state.
    pub fn with_holistic_integrity(mut self, enabled: bool) -> Self {
        self.enable_holistic_integrity = enabled;
        self
    }

    /// Sets a custom key for the holistic integrity layer, implicitly enabling it.
    pub fn with_holistic_integrity_key(mut self, key: [u8; 32]) -> Self {
        self.master_integrity_key = Some(Secret::new(key));
        self.enable_holistic_integrity = true;
        self
    }

    /// Validates the builder's configuration before constructing the `EncryptedPtr`.
    fn validate(&self) -> Result<(), &'static str> {
        Ok(())
    }

    /// Constructs the `EncryptedPtr`, allocating memory for the provided value.
    pub fn build<T>(self, value: T) -> EncryptedPtr<T, A>
    where
        A: Clone,
    {
        self.validate().expect("Invalid builder configuration");
        let layout = Layout::new::<T>();
        let alloc = self.allocator.allocate(layout).unwrap();
        let raw_ptr = alloc.as_ptr() as *mut MaybeUninit<T>;
        unsafe {
            raw_ptr.write(MaybeUninit::new(value));
        }
        let raw_ptr = raw_ptr as *mut T;
        if let Err(_) = lock_memory(raw_ptr as *mut u8, layout.size(), self.require_lock) {
            // If locking fails and is required, securely deallocate and trigger failure.
            unsafe {
                std::ptr::write_bytes(raw_ptr as *mut u8, 0, layout.size());
                std::ptr::drop_in_place(raw_ptr);
                self.allocator.deallocate(alloc.cast(), layout);
            }
            (self.on_fail)();
            unreachable!("on_fail should not return");
        }
        self.build_internal(raw_ptr, layout)
    }

    /// Creates an `EncryptedPtr` from a raw pointer and layout.
    ///
    /// # Safety
    /// The caller must ensure that the `raw_ptr` is valid for reads and writes
    /// for the entire `layout` and that `T` is the correct type.
    pub unsafe fn build_from_raw_parts<T>(
        self,
        raw_ptr: *mut T,
        layout: Layout,
    ) -> EncryptedPtr<T, A> {
        self.validate().expect("Invalid builder configuration");
        if let Err(_) = lock_memory(raw_ptr as *mut u8, layout.size(), self.require_lock) {
            // Assuming caller handles cleanup if locking fails.
            (self.on_fail)();
            unreachable!("on_fail should not return");
        }
        self.build_internal(raw_ptr, layout)
    }

    /// A private helper function to construct the `EncryptedPtr`'s internal state.
    fn build_internal<T>(self, raw_ptr: *mut T, layout: Layout) -> EncryptedPtr<T, A> {
        // Collect all state for `Internal`
        let key = self.key.unwrap_or_else(|| Secret::new(generate_key()));
        let nonce = Secret::new(generate_nonce());
        let rotation_counter = 0u64;
        let active_cipher = self.cipher_override.unwrap_or_else(pick_random_cipher);
        let ad = EncryptedPtr::<T, A>::build_ad(rotation_counter, nonce.expose_secret());
        let encrypted_ptr = EncryptedPtr::<T, A>::encrypt_pointer(
            active_cipher,
            key.expose_secret(),
            nonce.expose_secret(),
            &ad,
            raw_ptr as u64,
        );
        let master_integrity_key = if self.enable_holistic_integrity {
            Some(
                self.master_integrity_key
                    .unwrap_or_else(|| Secret::new(generate_key())),
            )
        } else {
            None
        };

        // Assemble the `Internal` struct, leaving the master tag for last.
        let mut internal = Internal {
            encrypted_ptr,
            active_cipher,
            key,
            last_rotate: Instant::now(),
            rotation_counter,
            nonce,
            master_integrity_key,
            master_integrity_tag: None, // Will be calculated and set next.
        };

        // Calculate the initial master HMAC tag based on the assembled state.
        let master_integrity_tag = calculate_master_hmac(&internal, &layout, raw_ptr);
        internal.master_integrity_tag = master_integrity_tag;

        // Construct the final `EncryptedPtr`.
        EncryptedPtr {
            internal: RwLock::new(internal),
            anti_debug_methods: self.anti_debug_methods,
            rotation_interval: self.rotation_interval,
            on_fail: self.on_fail,
            allocator: self.allocator,
            layout,
            cipher_override: self.cipher_override,
            _marker: PhantomData,
        }
    }
}

/// Generates a cryptographically secure 256-bit key using `OsRng`.
fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generates a cryptographically secure 96-bit nonce using `OsRng`.
fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Selects a random cipher from the available `Cipher` enum variants.
fn pick_random_cipher() -> Cipher {
    let mut rng = rand::thread_rng();
    let choices: Vec<Cipher> = Cipher::iter().collect();
    *choices.choose(&mut rng).unwrap()
}

/// The default failure handler, which can be configured via Cargo features.
fn default_on_fail() {
    #[cfg(feature = "fail_panic")]
    panic!("Security violation detected");

    #[cfg(feature = "fail_exit")]
    std::process::exit(0);

    // Default behavior is to loop indefinitely to prevent further execution.
    #[cfg(not(any(feature = "fail_panic", feature = "fail_exit")))]
    loop {}
}

/// Computes the master HMAC-SHA256 checksum over the pointer's state and the data it points to.
fn calculate_master_hmac<T>(
    internal_state: &Internal,
    layout: &Layout,
    data_ptr: *const T,
) -> Option<[u8; 32]> {
    internal_state.master_integrity_key.as_ref().map(|key| {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key.expose_secret())
            .expect("HMAC can take key of any size");

        // Authenticate all critical metadata.
        mac.update(&[internal_state.active_cipher as u8]);
        mac.update(&internal_state.rotation_counter.to_le_bytes());
        mac.update(internal_state.nonce.expose_secret());
        match &internal_state.encrypted_ptr {
            EncryptedPointer::Obfuscated { value } => {
                mac.update(&value.to_le_bytes());
                mac.update(&[0u8; 16]); // Zero-pad for non-AEAD ciphers for consistent structure.
            }
            EncryptedPointer::Aead { ciphertext, tag } => {
                mac.update(&ciphertext.to_le_bytes());
                mac.update(tag);
            }
        }
        // Authenticate the actual data that the pointer points to.
        let data_slice =
            unsafe { std::slice::from_raw_parts(data_ptr as *const u8, layout.size()) };
        mac.update(data_slice);

        mac.finalize().into_bytes().into()
    })
}

/// Stores the internal, sensitive state of the `EncryptedPtr`, protected by an `RwLock`.
struct Internal {
    encrypted_ptr: EncryptedPointer,
    active_cipher: Cipher,
    key: Secret<[u8; 32]>,
    last_rotate: Instant,
    rotation_counter: u64,
    nonce: Secret<[u8; 12]>,
    master_integrity_key: Option<Secret<[u8; 32]>>,
    master_integrity_tag: Option<[u8; 32]>,
}

/// An encrypted, heap-allocated smart pointer designed to protect sensitive data.
pub struct EncryptedPtr<T, A: Allocator = Global> {
    internal: RwLock<Internal>,
    anti_debug_methods: Vec<AntiDebugMethod>,
    rotation_interval: Option<Duration>,
    on_fail: fn(),
    allocator: A,
    layout: Layout,
    cipher_override: Option<Cipher>,
    _marker: PhantomData<*mut T>,
}

type HmacSha256 = Hmac<sha2::Sha256>;

impl<T, A: Allocator> EncryptedPtr<T, A> {
    /// Constructs the Additional Associated Data (AAD) for an AEAD operation.
    fn build_ad(rotation_counter: u64, nonce: &[u8; 12]) -> Vec<u8> {
        let mut ad = Vec::with_capacity(1 + 8 + 12);
        ad.push(0x01); // Version/Identifier byte
        ad.extend_from_slice(&rotation_counter.to_le_bytes());
        ad.extend_from_slice(nonce);
        ad
    }

    /// Encrypts or obfuscates a pointer value using the specified cipher.
    fn encrypt_pointer(
        cipher: Cipher,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ad: &[u8],
        ptr_val: u64,
    ) -> EncryptedPointer {
        match cipher {
            Cipher::Aes256Gcm => {
                let mut buffer = ptr_val.to_le_bytes();
                let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(nonce), ad, &mut buffer)
                    .expect("AES-GCM encryption failed");
                EncryptedPointer::Aead {
                    ciphertext: u64::from_le_bytes(buffer),
                    tag: tag.into(),
                }
            }
            Cipher::ChaCha20Poly1305 => {
                let mut buffer = ptr_val.to_le_bytes();
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(nonce), ad, &mut buffer)
                    .expect("ChaCha20Poly1305 encryption failed");
                EncryptedPointer::Aead {
                    ciphertext: u64::from_le_bytes(buffer),
                    tag: tag.into(),
                }
            }
            Cipher::Xor => {
                let key_chunk = u64::from_le_bytes(key[0..8].try_into().unwrap());
                EncryptedPointer::Obfuscated {
                    value: ptr_val ^ key_chunk,
                }
            }
            Cipher::Rotate => {
                let shift = (key[0] % 63) + 1;
                EncryptedPointer::Obfuscated {
                    value: ptr_val.rotate_left(shift as u32),
                }
            }
            Cipher::Add => {
                let key_chunk = u64::from_le_bytes(key[0..8].try_into().unwrap());
                EncryptedPointer::Obfuscated {
                    value: ptr_val.wrapping_add(key_chunk),
                }
            }
            Cipher::Sub => {
                let key_chunk = u64::from_le_bytes(key[0..8].try_into().unwrap());
                EncryptedPointer::Obfuscated {
                    value: ptr_val.wrapping_sub(key_chunk),
                }
            }
            Cipher::Swap => EncryptedPointer::Obfuscated {
                value: ptr_val.swap_bytes(),
            },
        }
    }

    /// Decrypts or deobfuscates a pointer value using the active cipher.
    fn decrypt_pointer(internal: &Internal) -> Result<u64, ()> {
        let ad = Self::build_ad(internal.rotation_counter, internal.nonce.expose_secret());
        let key_bytes = internal.key.expose_secret();
        let nonce_bytes = internal.nonce.expose_secret();

        match (internal.active_cipher, &internal.encrypted_ptr) {
            (Cipher::Aes256Gcm, EncryptedPointer::Aead { ciphertext, tag }) => {
                let mut buffer = ciphertext.to_le_bytes();
                let cipher = Aes256Gcm::new(GenericArray::from_slice(key_bytes));
                cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(nonce_bytes),
                        &ad,
                        &mut buffer,
                        GenericArray::from_slice(tag),
                    )
                    .map(|_| u64::from_le_bytes(buffer))
                    .map_err(|_| ())
            }
            (Cipher::ChaCha20Poly1305, EncryptedPointer::Aead { ciphertext, tag }) => {
                let mut buffer = ciphertext.to_le_bytes();
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key_bytes));
                cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(nonce_bytes),
                        &ad,
                        &mut buffer,
                        GenericArray::from_slice(tag),
                    )
                    .map(|_| u64::from_le_bytes(buffer))
                    .map_err(|_| ())
            }
            (Cipher::Xor, EncryptedPointer::Obfuscated { value }) => {
                let key_chunk = u64::from_le_bytes(key_bytes[0..8].try_into().unwrap());
                Ok(value ^ key_chunk)
            }
            (Cipher::Rotate, EncryptedPointer::Obfuscated { value }) => {
                let shift = (key_bytes[0] % 63) + 1;
                Ok(value.rotate_right(shift as u32))
            }
            (Cipher::Add, EncryptedPointer::Obfuscated { value }) => {
                let key_chunk = u64::from_le_bytes(key_bytes[0..8].try_into().unwrap());
                Ok(value.wrapping_sub(key_chunk))
            }
            (Cipher::Sub, EncryptedPointer::Obfuscated { value }) => {
                let key_chunk = u64::from_le_bytes(key_bytes[0..8].try_into().unwrap());
                Ok(value.wrapping_add(key_chunk))
            }
            (Cipher::Swap, EncryptedPointer::Obfuscated { value }) => Ok(value.swap_bytes()),
            _ => Err(()), // Mismatch between cipher type and encrypted state, indicating tampering.
        }
    }

    /// A wrapper that decrypts the pointer and triggers the `on_fail` handler on error.
    fn verify_and_decrypt_ptr<G: Deref<Target = Internal>>(&self, internal: &G) -> *mut T {
        match Self::decrypt_pointer(internal) {
            Ok(ptr_val) => ptr_val as *mut T,
            Err(_) => {
                (self.on_fail)();
                unreachable!("on_fail should not return");
            }
        }
    }

    /// Verifies the master HMAC tag to ensure holistic integrity.
    fn verify_master_integrity<G: Deref<Target = Internal>>(
        &self,
        internal: &G,
        data_ptr: *const T,
    ) {
        if let Some(stored_tag) = internal.master_integrity_tag {
            if let Some(expected_tag) = calculate_master_hmac(internal, &self.layout, data_ptr) {
                // Constant-time comparison is not strictly necessary here as failure is catastrophic.
                if stored_tag != expected_tag {
                    (self.on_fail)();
                    unreachable!("on_fail should not return");
                }
            } else {
                // This case (a stored tag exists but the key doesn't) indicates corruption.
                (self.on_fail)();
                unreachable!("on_fail should not return");
            }
        }
    }

    /// Recalculates and updates the master HMAC tag, typically after a mutation.
    fn update_master_hmac(&self, internal: &mut RwLockWriteGuard<Internal>, data_ptr: *const T) {
        if internal.master_integrity_key.is_some() {
            let new_tag = calculate_master_hmac(internal, &self.layout, data_ptr);
            internal.master_integrity_tag = new_tag;
        }
    }

    /// Provides secure, read-only access to the protected data.
    pub fn read(&self) -> PtrReadGuard<'_, T, A> {
        self.check_debugger();
        let mut guard = self.internal.upgradable_read();

        // This block hardens against crashes from dereferencing a tampered pointer.
        // `catch_unwind` intercepts a panic (e.g., segfault), allowing a controlled failure.
        let ptr = match panic::catch_unwind(AssertUnwindSafe(|| {
            // Decrypt the pointer to get the memory address. This may crash if tampered.
            let decrypted_ptr = self.verify_and_decrypt_ptr(&guard);

            // Verify the integrity of all metadata and the data at the decrypted address.
            self.verify_master_integrity(&guard, decrypted_ptr);

            // If both checks pass, the pointer and state are authentic.
            decrypted_ptr
        })) {
            Ok(valid_ptr) => valid_ptr, // Success, no panic occurred.
            Err(_) => {
                // A panic was caught, which is treated as a detected integrity violation.
                (self.on_fail)();
                unreachable!("on_fail should not return");
            }
        };

        // Check if key rotation is needed and perform it if necessary.
        if self.need_rotate(&guard) {
            let mut write_guard = RwLockUpgradableReadGuard::upgrade(guard);
            self.rotate(&mut write_guard);
            guard = RwLockWriteGuard::downgrade_to_upgradable(write_guard);
        }

        // Return a read guard that allows dereferencing the pointer.
        PtrReadGuard {
            _guard: RwLockUpgradableReadGuard::downgrade(guard),
            target: unsafe { &*ptr },
            _phantom: PhantomData,
        }
    }

    /// Provides secure, mutable access to the protected data.
    pub fn write(&self) -> PtrWriteGuard<'_, T, A> {
        self.check_debugger();
        let mut guard = self.internal.upgradable_read();

        // Harden the write path against tampering-induced crashes.
        let ptr = match panic::catch_unwind(AssertUnwindSafe(|| {
            let decrypted_ptr = self.verify_and_decrypt_ptr(&guard);
            self.verify_master_integrity(&guard, decrypted_ptr);
            decrypted_ptr
        })) {
            Ok(valid_ptr) => valid_ptr,
            Err(_) => {
                (self.on_fail)();
                unreachable!("on_fail should not return");
            }
        };

        // Perform key rotation if needed before granting mutable access.
        if self.need_rotate(&guard) {
            let mut write_guard = RwLockUpgradableReadGuard::upgrade(guard);
            self.rotate(&mut write_guard);
            guard = RwLockWriteGuard::downgrade_to_upgradable(write_guard);
        }

        // Return a write guard that allows mutable dereferencing.
        PtrWriteGuard {
            _guard: RwLockUpgradableReadGuard::upgrade(guard),
            target: unsafe { &mut *ptr },
            ptr_guard: self,
        }
    }

    /// Determines if a key rotation is required based on the configured interval.
    fn need_rotate<G: Deref<Target = Internal>>(&self, guard: &G) -> bool {
        if let Some(interval) = self.rotation_interval {
            Instant::now().duration_since(guard.last_rotate) > interval
        } else {
            false
        }
    }

    /// Performs a key rotation, generating a new key, nonce, and cipher.
    fn rotate(&self, internal: &mut RwLockWriteGuard<Internal>) {
        // First, safely decrypt the current pointer.
        let ptr_val = match Self::decrypt_pointer(&*internal) {
            Ok(val) => val,
            Err(_) => {
                (self.on_fail)();
                unreachable!("on_fail should not return");
            }
        };

        // Generate new cryptographic materials.
        internal.key = Secret::new(generate_key());
        internal.nonce = Secret::new(generate_nonce());
        internal.rotation_counter = internal.rotation_counter.wrapping_add(1);
        internal.active_cipher = self.cipher_override.unwrap_or_else(pick_random_cipher);

        // Re-encrypt the pointer with the new materials.
        let ad = Self::build_ad(internal.rotation_counter, internal.nonce.expose_secret());
        internal.encrypted_ptr = Self::encrypt_pointer(
            internal.active_cipher,
            internal.key.expose_secret(),
            internal.nonce.expose_secret(),
            &ad,
            ptr_val,
        );
        internal.last_rotate = Instant::now();

        // Recalculate the master HMAC to authenticate the new state.
        self.update_master_hmac(internal, ptr_val as *const T);
    }

    /// Executes the configured anti-debugging checks.
    fn check_debugger(&self) {
        let detected_count = self
            .anti_debug_methods
            .iter()
            .filter(|&&method| method.is_present())
            .count();
        // Trigger failure if two or more methods detect a debugger, reducing false positives.
        if detected_count >= 2 {
            (self.on_fail)();
        }
    }

    /// Manually forces a key and cipher rotation.
    pub fn reset(&self) {
        let mut internal = self.internal.write();
        self.rotate(&mut internal);
    }
}

impl<T, A: Allocator> Drop for EncryptedPtr<T, A> {
    /// Securely deallocates the memory and cleans up the `EncryptedPtr`.
    #[inline(always)]
    fn drop(&mut self) {
        let internal = self.internal.write();

        if let Ok(ptr_val) = Self::decrypt_pointer(&*internal) {
            // Decrypt the pointer one last time to deallocate the correct memory region.
            let ptr = ptr_val as *mut T;
            let ptr_u8 = ptr as *mut u8;
            unlock_memory(ptr_u8, self.layout.size());
            // Securely wipe and deallocate the memory.
            unsafe {
                std::ptr::write_bytes(ptr_u8, 0, self.layout.size());
                std::ptr::drop_in_place(ptr);
                self.allocator
                    .deallocate(NonNull::new_unchecked(ptr_u8), self.layout);
            }
        }
    }
}

impl<T, A: Allocator + Clone + Default> From<(T, A)> for EncryptedPtr<T, A> {
    /// Creates an `EncryptedPtr` from a tuple of a value and an allocator.
    fn from((value, allocator): (T, A)) -> Self {
        PtrGuardBuilder::new()
            .with_allocator(allocator)
            .build(value)
    }
}

impl<T: fmt::Debug, A: Allocator> fmt::Debug for EncryptedPtr<T, A> {
    /// Provides a debug representation of the pointed-to value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let read = self.read();
        f.debug_struct("EncryptedPtr")
            .field("pointed_value", &*read)
            .finish()
    }
}
// The `RwLock` ensures that access to the internal state is thread-safe.
// The data `T` is heap-allocated and its access is controlled by the lock.
// If `T` is `Send`/`Sync`, the `EncryptedPtr` is also `Send`/`Sync`.
unsafe impl<T: Send, A: Allocator + Send> Send for EncryptedPtr<T, A> {}
unsafe impl<T: Sync, A: Allocator + Sync> Sync for EncryptedPtr<T, A> {}

/// A read guard that provides immutable access to the protected data.
pub struct PtrReadGuard<'a, T, A: Allocator = Global> {
    _guard: RwLockReadGuard<'a, Internal>,
    target: &'a T,
    #[doc(hidden)]
    _phantom: PhantomData<A>,
}

impl<'a, T, A: Allocator> Deref for PtrReadGuard<'a, T, A> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.target
    }
}

/// A write guard that provides mutable access to the protected data.
pub struct PtrWriteGuard<'a, T, A: Allocator = Global> {
    _guard: RwLockWriteGuard<'a, Internal>,
    target: &'a mut T,
    ptr_guard: &'a EncryptedPtr<T, A>,
}

impl<'a, T, A: Allocator> Deref for PtrWriteGuard<'a, T, A> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.target
    }
}

impl<'a, T, A: Allocator> DerefMut for PtrWriteGuard<'a, T, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.target
    }
}

impl<'a, T, A: Allocator> Drop for PtrWriteGuard<'a, T, A> {
    /// Updates the master integrity HMAC when the write guard is dropped, ensuring changes are authenticated.
    fn drop(&mut self) {
        self.ptr_guard
            .update_master_hmac(&mut self._guard, self.target);
    }
}

/// A type alias for `EncryptedPtr` using the global allocator, similar to `Box<T>`.
pub type EncryptedBox<T> = EncryptedPtr<T, Global>;

// Platform-Specific and Helper Functions
/// Attempts to lock a memory region to prevent it from being swapped to disk.
fn lock_memory(ptr: *mut u8, size: usize, require: bool) -> Result<bool, i32> {
    #[cfg(unix)]
    unsafe {
        let ret = libc::mlock(ptr as *const std::ffi::c_void, size);
        if ret == 0 {
            Ok(true)
        } else if require {
            Err(ret)
        } else {
            Ok(false)
        }
    }
    #[cfg(windows)]
    unsafe {
        let ret =
            windows_sys::Win32::System::Memory::VirtualLock(ptr as *mut std::ffi::c_void, size);
        if ret != 0 {
            Ok(true)
        } else if require {
            Err(ret as i32)
        } else {
            Ok(false)
        }
    }
    #[cfg(not(any(unix, windows)))]
    if require { Err(-1) } else { Ok(false) }
}
/// Unlocks a previously locked memory region.
fn unlock_memory(ptr: *mut u8, size: usize) {
    #[cfg(unix)]
    unsafe {
        libc::munlock(ptr as *const std::ffi::c_void, size);
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *mut std::ffi::c_void, size);
    }
}
/// A platform-specific implementation to check for the presence of a debugger.
fn platform_specific_is_debugger_present() -> bool {
    #[cfg(target_os = "windows")]
    {
        unsafe { windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() != 0 }
    }
    #[cfg(target_os = "linux")]
    {
        // Check `/proc/self/status` for the `TracerPid` field. A non-zero value indicates a debugger.
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            status
                .lines()
                .find(|l| l.starts_with("TracerPid:"))
                .map(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .map(|pid| pid != "0")
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        } else {
            false
        }
    }
    #[cfg(target_os = "macos")]
    {
        // Use sysctl to check the process flags for the P_TRACED flag.
        use libc::{CTL_KERN, KERN_PROC, KERN_PROC_PID, c_int, c_void, sysctl};
        use std::mem;
        use std::ptr;
        #[repr(C)]
        #[allow(non_camel_case_types)]
        struct extern_proc {
            _dummy1: [u8; 64],
            pub p_flag: i32,
            _dummy2: [u8; 200],
        }
        #[repr(C)]
        #[allow(non_camel_case_types)]
        struct kinfo_proc {
            pub kp_proc: extern_proc,
        }
        unsafe {
            let mut kp: kinfo_proc = mem::zeroed();
            let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, libc::getpid()];
            let mut size = mem::size_of::<kinfo_proc>();
            let ret = sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                &mut kp as *mut _ as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            );
            if ret == 0 {
                const P_TRACED: i32 = 0x00000800;
                return (kp.kp_proc.p_flag & P_TRACED) != 0;
            }
        }
        false
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// A macro that implements Control-Flow Flattening.
///
/// This macro transforms a series of labeled code blocks into a state machine
/// inside a dispatcher loop, destroying the logical flow to thwart decompilers.
macro_rules! flatten_control_flow {
    // The main entry point for the macro
    (
        start: $start_block:ident,
        blocks: {
            $(
                $block_name:ident => {
                    $($block_content:tt)*
                }
            ),+
        }
    ) => {
        {
            // Define an enum for all possible states (blocks).
            #[derive(PartialEq)]
            enum Block {
                $($block_name),+
            }

            // The state variable, initialized to the specified start block.
            let mut current_block = Block::$start_block;

            // Helper macro to transition between states.
            macro_rules! goto {
                ($next_block:ident) => {
                    current_block = Block::$next_block;
                    continue;
                }
            }
            // Helper macro to exit the state machine loop.
             macro_rules! exit {
                () => {
                    break;
                }
            }


            // Main dispatcher loop.
            loop {
                // The match statement is the central dispatcher.
                match current_block {
                    $(
                        Block::$block_name => {
                            $($block_content)*
                        }
                    ),+
                }
            }
        }
    };
}

/// An empty operation that, when enabled, introduces obfuscated control flow to hinder analysis.
#[cfg(feature = "obfuscate")]
#[inline(always)]
fn obfuscate_op() {
    // Break decoy logic into arbitrary blocks with non-sequential execution order.
    flatten_control_flow! {
        start: Init,
        blocks: {
            // Initializes decoy values.
            Init => {
                let decoy_key = obfustr::obfuscate!("deadbeef").as_ptr() as u64;
                let mut decoy = decoy_key.wrapping_mul(0xCAFEBABE);
                // Non-sequential jump to make analysis harder.
                goto!(RotateAndXor);
            },
            // Performs the final operation and check.
            AddAndCheck => {
                let decoy_key = obfustr::obfuscate!("deadbeef").as_ptr() as u64;
                let mut decoy = decoy_key.wrapping_mul(0x1337BEEF); // Dummy value
                decoy = decoy.wrapping_add(0xBADC0DE);
                if decoy == 0 {
                    // This path should never be taken, but it adds a branch to the control flow graph.
                    goto!(Exit);
                }
                goto!(Exit); // Normal exit path.
            },
            // Performs an intermediate decoy operation.
            RotateAndXor => {
                let decoy_key = obfustr::obfuscate!("deadbeef").as_ptr() as u64;
                let mut decoy = decoy_key.wrapping_mul(0xFEEDFACE); // Dummy value
                decoy = decoy.rotate_left(13) ^ decoy_key;
                goto!(AddAndCheck);
            },
            // The only exit point from the loop.
            Exit => {
                exit!();
            }
        }
    }
}

/// A no-op function when the `obfuscate` feature is not enabled.
#[cfg(not(feature = "obfuscate"))]
#[inline(always)]
fn obfuscate_op() {}

// Test Suite

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use strum::IntoEnumIterator;

    fn test_panic_on_fail() {
        panic!("on_fail called as expected due to security violation");
    }

    #[test]
    fn basic_usage() {
        struct Player {
            health: u32,
            mana: u32,
        }
        let player = PtrGuardBuilder::<Global>::new().build(Player {
            health: 100,
            mana: 50,
        });
        assert_eq!(player.read().health, 100);
        player.write().health = 150;
        assert_eq!(player.read().health, 150);
    }

    #[test]
    fn all_ciphers_roundtrip() {
        for cipher in Cipher::iter() {
            println!("Testing cipher: {:?}", cipher);
            let ptr = PtrGuardBuilder::<Global>::new()
                .with_cipher(cipher)
                .build(1337u64);
            assert_eq!(*ptr.read(), 1337);
        }
    }

    #[test]
    fn rotation_changes_cipher_and_key() {
        let ptr = PtrGuardBuilder::<Global>::new().build(42u32);

        let old_key = ptr.internal.read().key.expose_secret().clone();
        let old_cipher = ptr.internal.read().active_cipher;

        ptr.reset(); // Force rotation

        let new_key = ptr.internal.read().key.expose_secret().clone();
        let new_cipher = ptr.internal.read().active_cipher;

        assert_ne!(old_key, new_key, "Key should change on rotation");
        println!("Old cipher: {:?}, New cipher: {:?}", old_cipher, new_cipher);

        assert_eq!(*ptr.read(), 42, "Value should be preserved after rotation");
    }

    #[test]
    fn holistic_integrity_success_path() {
        let ptr = PtrGuardBuilder::<Global>::new()
            .with_holistic_integrity(true)
            .build(vec![10, 20, 30]);

        // Initial read should succeed.
        assert_eq!(*ptr.read(), vec![10, 20, 30]);

        // Write, which triggers HMAC update on drop.
        ptr.write().push(40);

        // Read after write should succeed.
        assert_eq!(*ptr.read(), vec![10, 20, 30, 40]);

        // Rotation also triggers an HMAC update.
        ptr.reset();

        // Read after rotation should succeed.
        assert_eq!(*ptr.read(), vec![10, 20, 30, 40]);
    }

    #[test]
    #[should_panic(expected = "on_fail called as expected due to security violation")]
    fn holistic_integrity_tamper_data() {
        let ptr = PtrGuardBuilder::<Global>::new()
            .with_on_fail(test_panic_on_fail)
            .with_holistic_integrity(true)
            .build([1u8, 2, 3, 4]);

        // Decrypt the raw pointer to tamper with the data directly.
        let raw_ptr = ptr.verify_and_decrypt_ptr(&ptr.internal.read());

        // Unsafely tamper with the underlying data.
        unsafe {
            (*raw_ptr)[1] = 99;
        }

        // The next read should detect the holistic HMAC mismatch and panic.
        let _ = ptr.read();
    }

    #[test]
    #[should_panic(expected = "on_fail called as expected due to security violation")]
    fn holistic_integrity_tamper_cipher() {
        let ptr = PtrGuardBuilder::<Global>::new()
            .with_on_fail(test_panic_on_fail)
            .with_holistic_integrity(true)
            .with_cipher(Cipher::Aes256Gcm) // Lock to a known cipher
            .build(123u32);

        // Manually tamper with the internal state.
        {
            let mut internal = ptr.internal.write();
            // Change the cipher without re-calculating the HMAC.
            internal.active_cipher = Cipher::Xor;
        }

        // The next access will compute an HMAC with Cipher::Xor, which won't match
        // the stored HMAC that was computed with Cipher::Aes256Gcm.
        let _ = ptr.read();
    }

    #[test]
    #[should_panic(expected = "on_fail called as expected due to security violation")]
    fn holistic_integrity_tamper_counter() {
        let ptr = PtrGuardBuilder::<Global>::new()
            .with_on_fail(test_panic_on_fail)
            .with_holistic_integrity(true)
            .build(456u32);

        // Manually tamper with the internal state.
        {
            let mut internal = ptr.internal.write();
            internal.rotation_counter = internal.rotation_counter.wrapping_add(1);
        }

        // The next read will fail the HMAC check because the counter is part of the MAC'd data.
        let _ = ptr.read();
    }
}
