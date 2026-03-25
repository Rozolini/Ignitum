#![allow(clippy::result_unit_err)]
#![no_std]

use ignitum_jit::compiler::{Compiler, WasmOp};
use ignitum_jit::ExecutableBuffer;

/// Orchestrates the single-pass translation of WebAssembly operations
/// into native x86_64 machine code.
///
/// Returns an `ExecutableBuffer` containing the executable memory region.
pub fn compile(code: &[WasmOp]) -> Result<ExecutableBuffer, ()> {
    let compiler = Compiler::new();
    compiler.compile(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ignitum_jit::compiler::WasmOp;
    use ignitum_runtime::instance::Instance;
    use ignitum_runtime::store::Store;

    #[test]
    #[cfg_attr(miri, ignore)] // Bypass execution under Miri as it cannot evaluate x86_64 machine code
    fn test_full_pipeline() {
        // Phase 1: Emulate parser output (Wasm IR).
        let code = [
            WasmOp::I64Const(100),
            WasmOp::I64Const(500),
            WasmOp::I64Add,
            WasmOp::Return,
        ];

        // Phase 2: Single-pass JIT Compilation (Wasm IR -> x86_64).
        let exec_buffer = compile(&code).unwrap();

        // Phase 3: Runtime Initialization.
        // Allocates hardware-sandboxed linear memory from the instance pool.
        let mut store = Store::new();
        let _mem_id = store.alloc_memory(1).unwrap();

        // Phase 4: Sandboxed Execution.
        // Reinterprets the buffer as a callable function and executes it under VEH protection.
        let func: extern "win64" fn() -> u64 = unsafe { exec_buffer.as_fn() };
        let instance = Instance::new(func);

        let result = instance.run().unwrap();
        assert_eq!(result, 600);
    }
}
