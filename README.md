# ptrguard

A pointer encryption library intended for Red Team implant design in Rust. It provides a heap-allocated smart pointer that features encryption of the pointer value, runtime integrity verification, and configurable anti-analysis routines.

## Prerequisites

The compilation of this crate requires the **nightly** Rust toolchain. This is necessary due to the use of the unstable Allocator API (`#![feature(allocator_api)]`), which permits the use of custom memory allocators.

## Functional Overview

The `ptrguard` crate provides `EncryptedPtr<T, A>`, a smart pointer that manages a heap-allocated object of type `T`. The memory address of this object is stored within the `EncryptedPtr` struct in an encrypted format. The data that `T` represents is not encrypted by this mechanism.

Upon instantiation, a cryptographic cipher is selected to encrypt the pointer. The available ciphers are `Aes256Gcm`, `ChaCha20Poly1305`, `Xor`, `Rotate`, `Add`, `Sub`, and `Swap`. Access to the underlying data is mediated through RAII guards returned by the `read()` and `write()` methods. Before access is granted, these methods decrypt the pointer and perform a series of security checks.

An optional HMAC-SHA256 integrity layer can be enabled. This computes a tag over the pointer's internal state (including the encrypted address, cipher choice, and nonce) and the raw bytes of the object on the heap. This tag is verified on every access attempt to detect tampering of either the pointer or the data it points to.

The library also contains facilities for periodic key rotation and runtime debugger presence detection. A custom failure handler can be specified to define the program's behavior when a security check fails.

## Compilation Features

The library's behavior can be modified at compile time through the following Cargo features.

-   **`obfuscate`**: Applies control-flow flattening to certain internal security routines.
-   **`fail_panic`**: On a security violation, the program will panic. This overrides custom handlers.
-   **`fail_exit`**: On a security violation, the process will exit with code 0. This overrides custom handlers.

If no failure feature is specified, the default behavior for a security violation is to enter an infinite loop.

## Build Procedure

After cloning the source repository, the library can be compiled with the following Cargo command:

```bash
cargo build --release
```

## Usage

To include the library, add the following entry to `Cargo.toml`:

```toml
[dependencies]
ptrguard = "0.1.0"
```

## Configuration and Instantiation 

Instances of EncryptedPtr are created and configured using the PtrGuardBuilder.

The default builder creates a pointer with a random cipher and default security settings.

```rust
use ptrguard::EncryptedBox;
use ptrguard::PtrGuardBuilder;

struct SystemData {
    id: u32,
    buffer: Vec<u8>,
}

let data = SystemData { id: 101, buffer: vec![0, 1, 2] };

// An EncryptedBox<T> is created via the PtrGuardBuilder.
let guarded_data: EncryptedBox<_> = PtrGuardBuilder::new().build(data);

// Data is accessed immutably through a read guard.
let id = guarded_data.read().id;
assert_eq!(id, 101);

// Data is accessed mutably through a write guard.
guarded_data.write().buffer.push(3);
assert_eq!(guarded_data.read().buffer, vec![0, 1, 2, 3]);
```

The builder exposes methods to set the security parameters for the pointer prior to its construction.

```rust
use ptrguard::{PtrGuardBuilder, AntiDebugMethod, Cipher};
use std::time::Duration;

struct Config {
    key: [u8; 16],
}

let ptr = PtrGuardBuilder::new()
    // Enables the HMAC-SHA256 integrity check over the pointer and its data.
    .with_holistic_integrity(true)
    
    // Sets the encryption key and cipher to rotate at a specified interval.
    .with_key_rotation(Duration::from_secs(300))
    
    // Adds debugger detection methods to be checked on access.
    .add_anti_debug_method(AntiDebugMethod::PlatformSpecific)
    .add_anti_debug_method(AntiDebugMethod::Timing)
    
    // Overrides random cipher selection to use a specific algorithm.
    .with_cipher(Cipher::Aes256Gcm)
    
    // Specifies a function to call if a security check fails.
    .with_on_fail(|| std::process::exit(1))
    
    // Constructs the pointer with the specified configuration.
    .build(Config { key: [0; 16] });
```

## Reference
The concept for this library was inspired by the original pointerguard project, available at:
- https://github.com/teabound/pointerguard/
