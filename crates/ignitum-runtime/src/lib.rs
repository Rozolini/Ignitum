#![allow(clippy::result_unit_err)]
#![no_std]

extern crate alloc;

/// Manages the lifecycle of WebAssembly state (Memory, Globals, Tables).
/// Acts as the primary ownership layer for runtime resources.
pub mod store;

/// Handles the execution of a single WebAssembly module instance.
/// Responsible for sandboxed invocation and trap management.
pub mod instance;
