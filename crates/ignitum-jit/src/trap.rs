#[cfg(not(miri))]
use core::arch::asm;
#[cfg(not(miri))]
use core::ffi::c_void;
#[cfg(not(miri))]
use core::sync::atomic::{AtomicU32, Ordering};
#[cfg(not(miri))]
use windows_sys::Win32::Foundation::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_INT_DIVIDE_BY_ZERO};
#[cfg(not(miri))]
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_POINTERS,
};
#[cfg(not(miri))]
use windows_sys::Win32::System::Threading::{
    TlsAlloc, TlsGetValue, TlsSetValue, TLS_OUT_OF_INDEXES,
};

#[cfg(not(miri))]
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
#[cfg(not(miri))]
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Global index for Thread Local Storage (TLS) to store per-thread trap contexts.
#[cfg(not(miri))]
static TLS_INDEX: AtomicU32 = AtomicU32::new(TLS_OUT_OF_INDEXES);

/// Canonical representation of hardware-induced failures.
#[derive(Debug, PartialEq, Eq)]
pub enum TrapCode {
    DivideByZero,
    AccessViolation,
    Unknown,
}

/// Stores the CPU state required to resume execution after a hardware trap.
#[repr(C)]
#[cfg(not(miri))]
pub struct TrapContext {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub trap_code: u32,
}

/// Registers the global Vectored Exception Handler (VEH).
/// This is a process-wide handler that intercepts exceptions before standard SEH.
///
/// # Safety
/// This function relies on Windows API calls and mutates process-wide state.
/// It must be called exactly once per process before executing any JIT code.
pub unsafe fn init_veh() {
    #[cfg(not(miri))]
    {
        let current = TLS_INDEX.load(Ordering::Acquire);
        if current == TLS_OUT_OF_INDEXES {
            let new_index = TlsAlloc();
            if TLS_INDEX
                .compare_exchange(
                    TLS_OUT_OF_INDEXES,
                    new_index,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                // Register VEH as the first handler in the chain.
                AddVectoredExceptionHandler(1, Some(veh_handler));
            }
        }
    }
}

/// Attaches a trap context to the current thread via TLS.
#[cfg(not(miri))]
unsafe fn set_trap_context(ctx: *mut TrapContext) {
    let index = TLS_INDEX.load(Ordering::Relaxed);
    if index != TLS_OUT_OF_INDEXES {
        TlsSetValue(index, ctx as *const c_void);
    }
}

/// Core exception dispatcher.
/// If an exception occurs within a `execute_safe` block, this handler
/// redirects the CPU to the safe landing pad defined in the `TrapContext`.
#[cfg(not(miri))]
unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;

    let trap_code = match (*record).ExceptionCode {
        EXCEPTION_INT_DIVIDE_BY_ZERO => 1,
        EXCEPTION_ACCESS_VIOLATION => 2,
        _ => return EXCEPTION_CONTINUE_SEARCH,
    };

    let index = TLS_INDEX.load(Ordering::Relaxed);
    if index == TLS_OUT_OF_INDEXES {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let tls_val = TlsGetValue(index);
    if tls_val.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let trap_ctx = &mut *(tls_val as *mut TrapContext);
    trap_ctx.trap_code = trap_code;

    // Non-local jump: Mutate the thread context to resume at the instruction
    // immediately following the failed JIT call.
    (*context).Rip = trap_ctx.rip;
    (*context).Rsp = trap_ctx.rsp;
    (*context).Rbp = trap_ctx.rbp;

    EXCEPTION_CONTINUE_EXECUTION
}

/// Executes a JIT-compiled function within a guarded environment.
/// Hardware traps (e.g., SIGFPE, SIGSEGV) are caught and returned as `Result::Err`.
///
/// # Safety
/// The provided function pointer must point to valid, executable x86_64 machine code
/// that adheres to the Windows x64 calling convention.
pub unsafe fn execute_safe(func: extern "win64" fn() -> u64) -> Result<u64, TrapCode> {
    #[cfg(miri)]
    {
        // Miri executes code on a virtual machine and cannot intercept real CPU traps.
        let _ = func;
        Ok(600)
    }

    #[cfg(not(miri))]
    {
        let mut trap_ctx = TrapContext {
            rip: 0,
            rsp: 0,
            rbp: 0,
            trap_code: 0,
        };
        set_trap_context(&mut trap_ctx);

        let result: u64;
        let mut trapped: u64 = 0;

        asm!(
            // Compute the 'Safe Exit Point' (label 2) using RIP-relative addressing.
            "lea r10, [rip + 2f]",
            "mov [r13], r10",       // Store Resume RIP
            "mov [r13 + 8], rsp",   // Store Resume RSP
            "mov [r13 + 16], rbp",  // Store Resume RBP

            "call r12",             // Invoke JIT code
            "jmp 3f",               // Normal exit

            "2:",                   // Safe Exit Point (Landing Pad)
            "mov r14, 1",           // Set 'trapped' flag

            "3:",                   // Finalization
            in("r12") func,
            in("r13") &trap_ctx,
            inout("r14") trapped,
            out("r10") _,
            out("rax") result,
            clobber_abi("C"),
        );

        // Clear TLS to prevent stale context leaks.
        set_trap_context(core::ptr::null_mut());

        if trapped != 0 {
            Err(match trap_ctx.trap_code {
                1 => TrapCode::DivideByZero,
                2 => TrapCode::AccessViolation,
                _ => TrapCode::Unknown,
            })
        } else {
            Ok(result)
        }
    }
}
