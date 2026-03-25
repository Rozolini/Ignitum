#![allow(clippy::result_unit_err)]
#![no_std]

pub mod compiler;
pub mod memory;
pub mod trap;

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;

#[cfg(not(miri))]
use core::ptr;

#[cfg(not(miri))]
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
};

/// Represents x86_64 General Purpose Registers (GPR).
/// Mapped directly to hardware register encoding values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

/// A zero-dependency, linear x86_64 machine code emitter.
/// Bypasses heavy IR frameworks to minimize cold-start latencies.
pub struct Assembler {
    buffer: Vec<u8>,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Freezes the emission pipeline and yields the raw machine code payload.
    pub fn finalize(self) -> Vec<u8> {
        self.buffer
    }

    #[inline]
    fn emit8(&mut self, byte: u8) {
        self.buffer.push(byte);
    }

    #[inline]
    fn emit32(&mut self, word: u32) {
        self.buffer.extend_from_slice(&word.to_le_bytes());
    }

    #[inline]
    fn emit64(&mut self, qword: u64) {
        self.buffer.extend_from_slice(&qword.to_le_bytes());
    }

    /// Emits `xor dst, src` (64-bit). Often used for register zeroing.
    pub fn xor_reg64(&mut self, dst: Reg, src: Reg) {
        let d = dst as u8;
        let s = src as u8;
        self.emit_rex(true, s, 0, d);
        self.emit8(0x31);
        self.emit_modrm(0b11, s, d);
    }

    /// Emits `div src`. Unsigned division of RDX:RAX by `src`.
    pub fn div_reg64(&mut self, src: Reg) {
        let s = src as u8;
        self.emit_rex(true, 0, 0, s);
        self.emit8(0xF7);
        self.emit_modrm(0b11, 6, s);
    }

    /// Emits `add reg, imm8` (sign-extended to 64-bit).
    pub fn add_imm8(&mut self, reg: Reg, imm: i8) {
        let r = reg as u8;
        self.emit_rex(true, 0, 0, r);
        self.emit8(0x83);
        self.emit_modrm(0b11, 0, r);
        self.emit8(imm as u8);
    }

    /// Emits `sub reg, imm8` (sign-extended to 64-bit).
    pub fn sub_imm8(&mut self, reg: Reg, imm: i8) {
        let r = reg as u8;
        self.emit_rex(true, 0, 0, r);
        self.emit8(0x83);
        self.emit_modrm(0b11, 5, r);
        self.emit8(imm as u8);
    }

    /// Emits an indirect call via register (`call reg`).
    pub fn call_reg(&mut self, reg: Reg) {
        let r = reg as u8;
        if r >= 8 {
            self.emit_rex(false, 0, 0, r);
        }
        self.emit8(0xFF);
        self.emit_modrm(0b11, 2, r);
    }

    /// Reserves 32 bytes on the stack.
    /// Required to comply with the Microsoft x64 calling convention (Shadow Space).
    pub fn allocate_shadow_space(&mut self) {
        self.sub_imm8(Reg::Rsp, 32);
    }

    /// Releases the 32-byte Shadow Space constraint.
    pub fn deallocate_shadow_space(&mut self) {
        self.add_imm8(Reg::Rsp, 32);
    }

    /// Emits `push reg` (64-bit).
    pub fn push_reg64(&mut self, reg: Reg) {
        let r = reg as u8;
        if r >= 8 {
            self.emit_rex(false, 0, 0, r);
        }
        self.emit8(0x50 + (r & 7));
    }

    /// Emits `pop reg` (64-bit).
    pub fn pop_reg64(&mut self, reg: Reg) {
        let r = reg as u8;
        if r >= 8 {
            self.emit_rex(false, 0, 0, r);
        }
        self.emit8(0x58 + (r & 7));
    }

    /// Standard x64 function prologue: stores the previous frame pointer
    /// and establishes a new frame.
    pub fn prologue(&mut self) {
        self.push_reg64(Reg::Rbp);
        self.mov_reg64(Reg::Rbp, Reg::Rsp);
    }

    /// Standard x64 function epilogue: restores the stack and frame pointers.
    pub fn epilogue(&mut self) {
        self.mov_reg64(Reg::Rsp, Reg::Rbp);
        self.pop_reg64(Reg::Rbp);
    }

    /// Emits `mov dst, src` (64-bit).
    pub fn mov_reg64(&mut self, dst: Reg, src: Reg) {
        let d = dst as u8;
        let s = src as u8;
        self.emit_rex(true, s, 0, d);
        self.emit8(0x89);
        self.emit_modrm(0b11, s, d);
    }

    /// Sign-extends RAX into RDX:RAX (required before 64-bit idiv).
    pub fn cqo(&mut self) {
        self.buffer.extend_from_slice(&[0x48, 0x99]);
    }

    /// Performs signed division of RDX:RAX by the specified register.
    pub fn idiv_reg64(&mut self, reg: Reg) {
        let reg_code = reg as u8;

        // REX.W prefix. Use 0x49 if using extended registers (R8-R15).
        let rex_w = if reg_code >= 8 { 0x49 } else { 0x48 };

        // ModR/M byte: Mod=11 (register), Reg=111 (idiv), R/M=reg_code.
        let modrm = 0b11_111_000 | (reg_code & 7);

        self.buffer.extend_from_slice(&[rex_w, 0xF7, modrm]);
    }

    /// Emits `cmp dst, src` (64-bit).
    pub fn cmp_reg64(&mut self, dst: Reg, src: Reg) {
        let d = dst as u8;
        let s = src as u8;
        self.emit_rex(true, s, 0, d);
        self.emit8(0x39);
        self.emit_modrm(0b11, s, d);
    }

    /// Emits `jmp rel32` (unconditional relative jump).
    pub fn jmp_rel32(&mut self, offset: i32) {
        self.emit8(0xE9);
        self.emit32(offset as u32);
    }

    /// Emits `je rel32` (jump if equal / ZF=1).
    pub fn je_rel32(&mut self, offset: i32) {
        self.emit8(0x0F);
        self.emit8(0x84);
        self.emit32(offset as u32);
    }

    /// Emits `jne rel32` (jump if not equal / ZF=0).
    pub fn jne_rel32(&mut self, offset: i32) {
        self.emit8(0x0F);
        self.emit8(0x85);
        self.emit32(offset as u32);
    }

    /// Computes and emits the REX prefix byte.
    /// Dictates 64-bit operand sizes and access to extended registers (R8-R15).
    fn emit_rex(&mut self, w: bool, r: u8, x: u8, b: u8) {
        let mut rex = 0x40;
        if w {
            rex |= 0x08;
        }
        if (r & 0x08) != 0 {
            rex |= 0x04;
        }
        if (x & 0x08) != 0 {
            rex |= 0x02;
        }
        if (b & 0x08) != 0 {
            rex |= 0x01;
        }
        if rex != 0x40 {
            self.emit8(rex);
        }
    }

    /// Computes and emits the ModR/M byte for operand addressing.
    fn emit_modrm(&mut self, mod_: u8, reg: u8, rm: u8) {
        self.emit8((mod_ << 6) | ((reg & 7) << 3) | (rm & 7));
    }

    /// Emits `mov reg, imm64` (loads a 64-bit immediate).
    pub fn mov_imm64(&mut self, reg: Reg, imm: u64) {
        let r = reg as u8;
        self.emit_rex(true, 0, 0, r);
        self.emit8(0xB8 | (r & 7));
        self.emit64(imm);
    }

    /// Emits `mov reg, imm32` (loads a 32-bit immediate, sign-extended to 64-bit).
    pub fn mov_imm32(&mut self, reg: Reg, imm: i32) {
        let r = reg as u8;
        self.emit_rex(true, 0, 0, r);
        self.emit8(0xC7);
        self.emit_modrm(0b11, 0, r);
        self.emit32(imm as u32);
    }

    /// Emits `add dst, src` (64-bit register addition).
    pub fn add_reg64(&mut self, dst: Reg, src: Reg) {
        let d = dst as u8;
        let s = src as u8;
        self.emit_rex(true, s, 0, d);
        self.emit8(0x01);
        self.emit_modrm(0b11, s, d);
    }

    /// Emits `sub dst, src` (64-bit register subtraction).
    pub fn sub_reg64(&mut self, dst: Reg, src: Reg) {
        let d = dst as u8;
        let s = src as u8;
        self.emit_rex(true, s, 0, d);
        self.emit8(0x29);
        self.emit_modrm(0b11, s, d);
    }

    /// Emits `ret` (returns from the current procedure).
    pub fn ret(&mut self) {
        self.emit8(0xC3);
    }
}

/// Encapsulates a JIT-compiled machine code payload within an OS-allocated memory region.
/// Enforces W^X (Write XOR Execute) memory protection.
pub struct ExecutableBuffer {
    ptr: *mut c_void,
    size: usize,
}

// Safety: The buffer maintains exclusive ownership of the underlying memory region.
// It is safe to transfer across thread boundaries.
unsafe impl Send for ExecutableBuffer {}
unsafe impl Sync for ExecutableBuffer {}

impl ExecutableBuffer {
    /// Allocates memory, copies the emitted machine code, and transitions the region to executable.
    /// Fails if the allocation or protection transition is denied by the OS.
    pub fn new(machine_code: &[u8]) -> Result<Self, ()> {
        let size = machine_code.len();
        if size == 0 {
            return Err(());
        }

        // Miri environment: Bypasses OS APIs and uses the standard allocator for UB analysis.
        #[cfg(miri)]
        {
            use alloc::alloc::{alloc, Layout};
            let layout = Layout::from_size_align(size, 4096).map_err(|_| ())?;
            let ptr = unsafe { alloc(layout) };

            if ptr.is_null() {
                return Err(());
            }

            unsafe {
                core::ptr::copy_nonoverlapping(machine_code.as_ptr(), ptr, size);
            }

            Ok(Self {
                ptr: ptr as *mut core::ffi::c_void,
                size,
            })
        }

        // Hardware environment: Uses Windows VirtualAlloc to enforce page-level protections.
        #[cfg(not(miri))]
        unsafe {
            // Allocate as Read/Write initially.
            let ptr = VirtualAlloc(
                ptr::null_mut(),
                size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            );

            if ptr.is_null() {
                return Err(());
            }

            ptr::copy_nonoverlapping(machine_code.as_ptr(), ptr as *mut u8, size);

            let mut old_protect = 0;
            // W^X enforcement: Transition from RW to RX. Memory is never writable and executable simultaneously.
            let res = VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &mut old_protect);

            if res == 0 {
                VirtualFree(ptr, 0, MEM_RELEASE);
                return Err(());
            }

            Ok(Self { ptr, size })
        }
    }

    /// Casts the internal memory pointer to a callable function pointer.
    ///
    /// # Safety
    /// The caller must guarantee that the buffer contains valid, ABI-compliant
    /// x86_64 machine code that exactly matches the signature of `T`.
    pub unsafe fn as_fn<T>(&self) -> T {
        // Under Miri, this pointer is never called, but the transmute is semantically valid.
        core::mem::transmute_copy(&self.ptr)
    }

    /// Returns the size of the allocated executable memory region in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns true if the executable buffer contains no bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Drop for ExecutableBuffer {
    /// Frees the underlying memory region, preventing leaks.
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.size > 0 {
            #[cfg(miri)]
            {
                let layout = core::alloc::Layout::from_size_align(self.size, 4096).unwrap();
                unsafe { alloc::alloc::dealloc(self.ptr as *mut u8, layout) };
            }

            #[cfg(not(miri))]
            unsafe {
                VirtualFree(self.ptr as _, 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_mov_imm64() {
        let mut asm = Assembler::new();
        asm.mov_imm64(Reg::Rax, 0x1122334455667788);
        assert_eq!(
            asm.finalize(),
            vec![0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
    }

    #[test]
    fn test_add_reg64() {
        let mut asm = Assembler::new();
        asm.add_reg64(Reg::Rax, Reg::Rcx);
        assert_eq!(asm.finalize(), vec![0x48, 0x01, 0xC8]);
    }

    #[test]
    fn test_ret() {
        let mut asm = Assembler::new();
        asm.ret();
        assert_eq!(asm.finalize(), vec![0xC3]);
    }

    #[test]
    fn test_host_to_wasm_interop_4_args() {
        // Miri bypass: Cannot execute heap-allocated machine code.
        if cfg!(miri) {
            return;
        }
        let mut asm = Assembler::new();

        // Establish stack frame
        asm.prologue();

        // Windows x64 ABI calling convention: arg1=RCX, arg2=RDX, arg3=R8, arg4=R9.
        // Accumulate arguments into RAX.
        asm.mov_reg64(Reg::Rax, Reg::Rcx);
        asm.add_reg64(Reg::Rax, Reg::Rdx);
        asm.add_reg64(Reg::Rax, Reg::R8);
        asm.add_reg64(Reg::Rax, Reg::R9);

        // Tear down frame and return
        asm.epilogue();
        asm.ret();

        let code = asm.finalize();
        let exec = ExecutableBuffer::new(&code).unwrap();

        // Reinterpret the memory region as an ABI-compliant function pointer.
        let add4_func: extern "win64" fn(u64, u64, u64, u64) -> u64 = unsafe { exec.as_fn() };

        let result = add4_func(10, 20, 30, 40);
        assert_eq!(result, 100);
    }

    #[test]
    fn test_push_pop() {
        let mut asm = Assembler::new();
        asm.push_reg64(Reg::Rbp);
        asm.pop_reg64(Reg::R15);
        assert_eq!(asm.finalize(), vec![0x55, 0x41, 0x5F]);
    }

    #[test]
    fn test_execute_jit_code() {
        // Miri bypass
        if cfg!(miri) {
            return;
        }
        let mut asm = Assembler::new();
        asm.mov_imm64(Reg::Rax, 42);
        asm.ret();

        let code = asm.finalize();
        let exec = ExecutableBuffer::new(&code).unwrap();

        let func: extern "C" fn() -> u64 = unsafe { exec.as_fn() };

        let result = func();
        assert_eq!(result, 42);
    }

    use super::compiler::{Compiler, WasmOp};

    #[test]
    fn test_single_pass_compiler() {
        // Miri bypass
        if cfg!(miri) {
            return;
        }

        let wasm_code = [
            WasmOp::I64Const(10),
            WasmOp::I64Const(32),
            WasmOp::I64Add,
            WasmOp::Return,
        ];

        let compiler = Compiler::new();
        let exec = compiler.compile(&wasm_code).unwrap();

        let func: extern "win64" fn() -> u64 = unsafe { exec.as_fn() };
        let result = func();

        assert_eq!(result, 42);
    }

    #[test]
    fn test_cmp_reg64() {
        let mut asm = Assembler::new();
        asm.cmp_reg64(Reg::Rax, Reg::Rcx);
        assert_eq!(asm.finalize(), vec![0x48, 0x39, 0xC8]);
    }

    #[test]
    fn test_jmp_rel32() {
        let mut asm = Assembler::new();
        asm.jmp_rel32(0x10);
        assert_eq!(asm.finalize(), vec![0xE9, 0x10, 0x00, 0x00, 0x00]);
    }

    /// External host callback used for interop verification.
    extern "win64" fn host_callback(val: u64) -> u64 {
        val * 2
    }

    #[test]
    fn test_wasm_to_host_interop_with_shadow_space() {
        // Miri bypass
        if cfg!(miri) {
            return;
        }
        let mut asm = Assembler::new();

        asm.prologue();

        // Input: RCX holds 'val', RDX holds 'host_callback' pointer.
        // We prepare to invoke RDX with RCX as its first argument.
        // No move needed, RCX is already set correctly per ABI.

        // Enforce Windows x64 ABI Shadow Space allocation before CALL.
        asm.allocate_shadow_space();
        asm.call_reg(Reg::Rdx);
        asm.deallocate_shadow_space();

        asm.epilogue();
        asm.ret();

        let code = asm.finalize();
        let exec = ExecutableBuffer::new(&code).unwrap();

        let jit_func: extern "win64" fn(u64, extern "win64" fn(u64) -> u64) -> u64 =
            unsafe { exec.as_fn() };
        let result = jit_func(21, host_callback);

        assert_eq!(result, 42);
    }

    #[test]
    fn test_trap_divide_by_zero() {
        // Miri bypass: Miri does not simulate hardware CPU exceptions (VEH).
        if cfg!(miri) {
            return;
        }

        // Ensure the Vectored Exception Handler is active for the current thread.
        unsafe { trap::init_veh() };

        let mut asm = Assembler::new();
        asm.prologue();

        // Deliberately trigger EXCEPTION_INT_DIVIDE_BY_ZERO.
        asm.xor_reg64(Reg::Rdx, Reg::Rdx);
        asm.mov_imm64(Reg::Rax, 42);
        asm.xor_reg64(Reg::Rcx, Reg::Rcx);
        asm.div_reg64(Reg::Rcx);

        asm.epilogue();
        asm.ret();

        let code = asm.finalize();
        let exec = ExecutableBuffer::new(&code).unwrap();
        let func: extern "win64" fn() -> u64 = unsafe { exec.as_fn() };

        // Execute under the protection of the VEH sandbox.
        let result = unsafe { trap::execute_safe(func) };

        assert_eq!(result, Err(trap::TrapCode::DivideByZero));
    }

    #[test]
    fn test_safe_execution_success() {
        // Miri bypass
        if cfg!(miri) {
            return;
        }
        unsafe { trap::init_veh() };

        let mut asm = Assembler::new();
        asm.prologue();
        asm.mov_imm64(Reg::Rax, 99);
        asm.epilogue();
        asm.ret();

        let code = asm.finalize();
        let exec = ExecutableBuffer::new(&code).unwrap();

        let func: extern "win64" fn() -> u64 = unsafe { exec.as_fn() };
        let result = unsafe { trap::execute_safe(func) };

        assert_eq!(result, Ok(99));
    }
}
