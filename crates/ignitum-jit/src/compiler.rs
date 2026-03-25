use crate::{Assembler, ExecutableBuffer, Reg};
use alloc::vec::Vec;

/// Intermediate Representation (IR) for a subset of WebAssembly instructions.
/// Used as the input format for the baseline JIT compiler.
#[derive(Debug, Clone, Copy)]
pub enum WasmOp {
    I64Const(u64),
    I64Add,
    I64DivS,
    Return,
}

/// A single-pass, non-optimizing baseline JIT compiler.
/// Translates WebAssembly stack-machine semantics directly into x86_64 register operations.
pub struct Compiler {
    asm: Assembler,
    /// Virtual stack tracking the allocation of physical hardware registers
    /// during the compilation pass.
    stack: Vec<Reg>,
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            asm: Assembler::new(),
            stack: Vec::new(),
        }
    }

    /// Volatile (caller-saved) General Purpose Registers allocated for expression evaluation.
    /// Adheres to the Windows x64 ABI volatile register set.
    const GPR_POOL: [Reg; 4] = [Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::R8];

    /// Executes the single-pass translation pipeline.
    ///
    /// Consumes the Wasm IR and yields an OS-allocated, executable memory buffer
    /// containing the generated x86_64 machine code.
    pub fn compile(mut self, code: &[WasmOp]) -> Result<ExecutableBuffer, ()> {
        // Establish an ABI-compliant stack frame.
        self.asm.prologue();

        for op in code {
            match op {
                WasmOp::I64Const(val) => {
                    let reg = Self::GPR_POOL[self.stack.len() % Self::GPR_POOL.len()];
                    self.asm.mov_imm64(reg, *val);
                    self.stack.push(reg);
                }
                WasmOp::I64Add => {
                    let rhs = self.stack.pop().unwrap();
                    let lhs = self.stack.pop().unwrap();
                    self.asm.add_reg64(lhs, rhs);
                    self.stack.push(lhs);
                }
                WasmOp::I64DivS => {
                    let rhs = self.stack.pop().unwrap(); // Divisor
                    let lhs = self.stack.pop().unwrap(); // Dividend

                    // x86_64 idiv constraint: dividend must be in RDX:RAX.
                    if lhs != Reg::Rax {
                        self.asm.mov_reg64(Reg::Rax, lhs);
                    }

                    // Move divisor to RCX to avoid conflicts with RDX (which gets clobbered).
                    if rhs != Reg::Rcx {
                        self.asm.mov_reg64(Reg::Rcx, rhs);
                    }

                    // Sign-extend RAX into RDX (cqo).
                    self.asm.cqo();

                    // Signed division: RDX:RAX / RCX. Quotient goes to RAX.
                    self.asm.idiv_reg64(Reg::Rcx);

                    // Push the result (RAX) back to the virtual stack.
                    self.stack.push(Reg::Rax);
                }
                WasmOp::Return => {
                    // Windows x64 ABI constraint: Integer return values must reside in RAX.
                    if let Some(ret_reg) = self.stack.last() {
                        if *ret_reg != Reg::Rax {
                            self.asm.mov_reg64(Reg::Rax, *ret_reg);
                        }
                    }
                    break;
                }
            }
        }

        // Tear down the stack frame and return to the host.
        self.asm.epilogue();
        self.asm.ret();

        let machine_code = self.asm.finalize();
        ExecutableBuffer::new(&machine_code)
    }
}
