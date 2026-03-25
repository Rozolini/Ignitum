use ignitum_jit::trap::{execute_safe, TrapCode};

/// An operational WebAssembly module instance ready for execution.
/// Encapsulates the entry point to the generated x86_64 machine code.
pub struct Instance {
    /// Pointer to the ABI-compliant JIT-compiled main function.
    main_func: extern "win64" fn() -> u64,
}

impl Instance {
    /// Wraps a compiled function into an executable instance.
    pub fn new(main_func: extern "win64" fn() -> u64) -> Self {
        Self { main_func }
    }

    /// Triggers the execution of the instance within the runtime sandbox.
    ///
    /// Hardware-level exceptions (e.g., memory corruption or math errors)
    /// are caught by the Vectored Exception Handler (VEH) and
    /// translated into a `TrapCode` rather than crashing the host process.
    pub fn run(&self) -> Result<u64, TrapCode> {
        unsafe { execute_safe(self.main_func) }
    }
}
