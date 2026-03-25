# Ignitum

Ignitum is a `no_std`, zero-dependency WebAssembly JIT compiler and runtime designed specifically for Windows x86_64. It provides low-latency execution by leveraging OS-level virtual memory management and hardware-assisted exception handling.

## Architecture

The runtime is modularized into strictly isolated components focused on zero-cost abstractions and direct hardware interaction:

### 1. Execution Engine
* **Single-Pass x86_64 JIT:** Directly translates WebAssembly stack-machine bytecode into native register operations in a single pass, bypassing heavy intermediate representations.


* **Host-to-Wasm Interop:** Implements standard Windows x64 ABI calling conventions (RCX, RDX, R8, R9, and shadow space) for seamless integration between safe Rust and generated machine code.

### 2. Memory Subsystem & Sandboxing
* **Hardware-Assisted Sandboxing:** Eliminates software-level array bounds checking. It reserves an 8GB virtual address space per instance using `VirtualAlloc`. Out-of-bounds access falls into uncommitted guard pages, triggering hardware page faults.


* **Trap Handling (VEH):** Hardware faults (e.g., `EXCEPTION_ACCESS_VIOLATION`, `EXCEPTION_INT_DIVIDE_BY_ZERO`) are intercepted via Windows Vectored Exception Handling (`AddVectoredExceptionHandler`) and safely unwound into standard Rust `Result::Err` values.

### 3. Resource Management & Security
* **Instance Pooling:** Achieves sub-millisecond cold starts. Lock-free pools reuse pre-allocated linear memory and JIT buffers, eliminating continuous OS-level allocation overhead.


* **W^X Security Enforcement:** Strictly separates write and execute permissions. JIT-compiled pages transition directly from `PAGE_READWRITE` to `PAGE_EXECUTE_READ`.


* **Zero-Copy Parser:** Reads and validates the `.wasm` binary format (magic bytes, sections, LEB128 encoding) using contiguous `&[u8]` slices without heap allocations.

## Getting Started

### Prerequisites
* Rust toolchain (stable)


* Rust nightly (strictly for Miri UB verification)


* Windows x86_64 target

## Installation

Add the core components to your project's `Cargo.toml`:

```toml
[dependencies]
ignitum-runtime = { git = "https://github.com/Rozolini/Ignitum.git" }
ignitum-compiler = { git = "https://github.com/Rozolini/Ignitum.git" }
```

## Verification

Due to the extensive use of direct memory manipulation and FFI, the project relies on strict automated verification.

### 1. Undefined Behavior Detection (Miri)

Validates strict provenance, memory leaks, and unsafe block contracts. Hardware-specific traps and executable memory allocations are bypassed via #[cfg(miri)] directives during interpretation.

```PowerShell
cargo +nightly miri test --workspace
```
### 2. Concurrency Testing (Loom)

Exhaustively simulates thread interleavings for the lock-free data structures and instance pools to guarantee the absence of data races.

```PowerShell
$env:RUSTFLAGS="--cfg loom"; cargo test --release
```

## End-to-End Testing

To verify the entire JIT pipeline, memory sandboxing, and hardware trap handling, run the comprehensive integration example:

```bash
cargo run -p ignitum-runtime --example run_wasm
```
**What it tests:**
1. **Standard JIT Compilation:** Verifies Wasm IR parsing, single-pass x86_64 machine code generation, and ABI-compliant execution.


2. **Hardware Sandboxing:** Confirms that out-of-bounds memory accesses (Access Violation) are caught by Guard Pages and intercepted by the Vectored Exception Handler (VEH) without crashing the host process.


3. **Hardware Exceptions:** Ensures that CPU-level faults (e.g., Divide By Zero via `idiv`) are safely intercepted and translated into Rust `Result::Err`.
## Design Considerations

* **Zero-Cost Abstractions:** Post-initialization, memory bounds checking and execution flow incur zero runtime overhead.


* **Unsafe Code Isolation:** `unsafe` blocks are strictly confined to OS-level FFI (`windows-sys`), raw pointer dereferencing for JIT buffers, and Vectored Exception Handling contexts.


* **Minimal Footprint:** The entire pipeline operates entirely within `#![no_std]`, utilizing the `alloc` crate solely for dynamic JIT buffer assembly and linear memory pooling.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
