#![no_std]

use core::ffi::c_void;
use core::ptr;
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};

/// WebAssembly page size is strictly 64KB.
pub const WASM_PAGE_SIZE: usize = 64 * 1024;

/// 8GB reservation for zero-cost bounds checking.
/// Covers 4GB max Wasm32 memory + 4GB guard region.
pub const WASM_MEMORY_LIMIT: usize = 8 * 1024 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub enum MemoryError {
    ReservationFailed,
    CommitFailed,
    VirtualProtectFailed,
    OutOfBounds,
}

/// Abstract representation of Wasm linear memory utilizing Windows virtual memory subsystem.
pub struct WasmMemory {
    base_ptr: *mut c_void,
    committed_bytes: usize,
}

// Safety: WasmMemory exclusively owns its virtual memory region.
unsafe impl Send for WasmMemory {}
unsafe impl Sync for WasmMemory {}

impl WasmMemory {
    /// Reserves 8GB of virtual address space without allocating physical memory.
    pub fn new() -> Result<Self, MemoryError> {
        let base_ptr = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                WASM_MEMORY_LIMIT,
                MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if base_ptr.is_null() {
            return Err(MemoryError::ReservationFailed);
        }

        Ok(Self {
            base_ptr,
            committed_bytes: 0,
        })
    }

    /// Commits physical memory for the specified number of Wasm pages.
    pub fn grow(&mut self, pages: usize) -> Result<(), MemoryError> {
        let bytes_to_commit = pages
            .checked_mul(WASM_PAGE_SIZE)
            .ok_or(MemoryError::OutOfBounds)?;
        let new_committed = self
            .committed_bytes
            .checked_add(bytes_to_commit)
            .ok_or(MemoryError::OutOfBounds)?;

        if new_committed > WASM_MEMORY_LIMIT {
            return Err(MemoryError::OutOfBounds);
        }

        // Pointer arithmetic to find the start of the uncommitted region.
        let commit_ptr =
            unsafe { (self.base_ptr as *mut u8).add(self.committed_bytes) as *mut c_void };

        let result =
            unsafe { VirtualAlloc(commit_ptr, bytes_to_commit, MEM_COMMIT, PAGE_READWRITE) };

        if result.is_null() {
            return Err(MemoryError::CommitFailed);
        }

        self.committed_bytes = new_committed;
        Ok(())
    }

    /// Changes the access protection of a committed memory region.
    /// Returns the previous protection flags on success.
    pub fn protect(
        &mut self,
        offset: usize,
        size: usize,
        new_protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS, MemoryError> {
        let end_offset = offset.checked_add(size).ok_or(MemoryError::OutOfBounds)?;
        if end_offset > self.committed_bytes {
            return Err(MemoryError::OutOfBounds);
        }

        let mut old_protect = 0;
        let target_ptr = unsafe { (self.base_ptr as *mut u8).add(offset) as *mut c_void };

        let result = unsafe { VirtualProtect(target_ptr, size, new_protect, &mut old_protect) };

        if result == 0 {
            return Err(MemoryError::VirtualProtectFailed);
        }

        Ok(old_protect)
    }

    /// Returns a mutable slice to the successfully committed memory region.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        if self.committed_bytes == 0 || self.base_ptr.is_null() {
            return &mut [];
        }
        unsafe { core::slice::from_raw_parts_mut(self.base_ptr as *mut u8, self.committed_bytes) }
    }

    /// Returns the raw base pointer of the memory region.
    pub fn as_ptr(&self) -> *mut c_void {
        self.base_ptr
    }
}

impl Drop for WasmMemory {
    fn drop(&mut self) {
        if !self.base_ptr.is_null() {
            unsafe {
                // MEM_RELEASE requires the size parameter to be strictly 0.
                VirtualFree(self.base_ptr, 0, MEM_RELEASE);
            }
        }
    }
}

/// Signature for the hardware exception callback.
pub type ExceptionCallback = unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32;

/// RAII guard for the Vectored Exception Handler.
pub struct VehHandle(*mut c_void);

// Safety: Handle is safe to send/share as it represents a global OS registration.
unsafe impl Send for VehHandle {}
unsafe impl Sync for VehHandle {}

/// Represents system-level errors during execution.
#[derive(Debug, PartialEq, Eq)]
pub enum SysError {
    VehInstallFailed,
}

impl VehHandle {
    /// Registers a global exception handler.
    /// `first` determines if this handler is called before others.
    pub fn install(handler: ExceptionCallback, first: bool) -> Result<Self, SysError> {
        let first_param = if first { 1 } else { 0 };
        let handle = unsafe { AddVectoredExceptionHandler(first_param, Some(handler)) };

        if handle.is_null() {
            Err(SysError::VehInstallFailed)
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for VehHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                RemoveVectoredExceptionHandler(self.0 as *const c_void);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::{PAGE_READONLY, PAGE_READWRITE};

    #[test]
    fn test_memory_reserve_and_commit() {
        if cfg!(miri) {
            return;
        }
        let mut mem = WasmMemory::new().unwrap();
        assert_eq!(mem.committed_bytes, 0);

        // Grow by 2 pages (128KB)
        mem.grow(2).unwrap();
        assert_eq!(mem.committed_bytes, WASM_PAGE_SIZE * 2);

        let slice = mem.as_slice_mut();
        slice[0] = 42;
        slice[WASM_PAGE_SIZE * 2 - 1] = 84;

        assert_eq!(slice[0], 42);
        assert_eq!(slice[WASM_PAGE_SIZE * 2 - 1], 84);
    }

    #[test]
    fn test_memory_out_of_bounds_grow() {
        if cfg!(miri) {
            return;
        }
        let mut mem = WasmMemory::new().unwrap();
        let max_pages = WASM_MEMORY_LIMIT / WASM_PAGE_SIZE;

        let result = mem.grow(max_pages + 1);
        assert_eq!(result, Err(MemoryError::OutOfBounds));
    }

    #[test]
    fn test_memory_protect() {
        if cfg!(miri) {
            return;
        }
        let mut mem = WasmMemory::new().unwrap();
        mem.grow(1).unwrap();

        // Change protection to READONLY
        let old_protect = mem.protect(0, WASM_PAGE_SIZE, PAGE_READONLY).unwrap();
        assert_eq!(old_protect, PAGE_READWRITE);

        // Revert back to READWRITE
        let old_protect = mem.protect(0, WASM_PAGE_SIZE, PAGE_READWRITE).unwrap();
        assert_eq!(old_protect, PAGE_READONLY);
    }
}
