//! Comprehensive End-to-End showcase of the Ignitum JIT runtime.
//! Validates JIT compilation, memory sandboxing, and hardware trap handling (VEH).

use ignitum_jit::compiler::{Compiler, WasmOp};
use ignitum_jit::trap::init_veh;
use ignitum_runtime::instance::Instance;
use ignitum_runtime::store::Store;

/// Simulates a JIT-compiled Wasm function reading out of bounds (hitting a guard page).
extern "win64" fn trigger_access_violation() -> u64 {
    unsafe { core::ptr::read_volatile(0x0 as *const u64) }
}

fn main() {
    println!("[INIT] Initializing Vectored Exception Handler (VEH)...");
    unsafe { init_veh() };

    let mut store = Store::new();
    let _mem_id = store
        .alloc_memory(1)
        .expect("Failed to allocate sandboxed memory");

    println!("\n--- Test 1: Standard JIT Compilation & Execution ---");
    let code = [
        WasmOp::I64Const(100),
        WasmOp::I64Const(500),
        WasmOp::I64Add,
        WasmOp::Return,
    ];

    let compiler = Compiler::new();
    let exec_buffer = compiler.compile(&code).expect("JIT compilation failed");
    let func: extern "win64" fn() -> u64 = unsafe { exec_buffer.as_fn() };
    let instance = Instance::new(func);

    match instance.run() {
        Ok(res) => println!("[PASS] Execution successful. Result: {}", res),
        Err(e) => println!("[FAIL] Unexpected trap: {:?}", e),
    }

    println!("\n--- Test 2: Hardware Sandboxing (Access Violation) ---");
    let instance_oob = Instance::new(trigger_access_violation);
    match instance_oob.run() {
        Ok(_) => println!("[FAIL] Execution should have trapped!"),
        Err(trap) => println!("[PASS] Hardware exception safely caught: {:?}", trap),
    }

    println!("\n--- Test 3: Math Exception (Divide By Zero) ---");
    // Generate Wasm IR that explicitly divides by zero using JIT to bypass Rust's panic handler.
    let div_code = [
        WasmOp::I64Const(100),
        WasmOp::I64Const(0),
        WasmOp::I64DivS,
        WasmOp::Return,
    ];

    let compiler = Compiler::new();
    let div_buffer = compiler.compile(&div_code).expect("JIT compilation failed");
    let div_func: extern "win64" fn() -> u64 = unsafe { div_buffer.as_fn() };
    let instance_div = Instance::new(div_func);

    match instance_div.run() {
        Ok(_) => println!("[FAIL] Execution should have trapped!"),
        Err(trap) => println!("[PASS] Hardware exception safely caught: {:?}", trap),
    }

    println!("\n[DONE] All End-to-End tests completed.");
}
