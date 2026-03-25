use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};

#[cfg(not(miri))]
use core::ptr;

use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(miri))]
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE,
};

/// Standard WebAssembly page size (64KB).
pub const WASM_PAGE_SIZE: usize = 64 * 1024;

/// 8GB virtual memory reservation layout:
/// - 0..4GB: Addressable WebAssembly linear memory.
/// - 4GB..8GB: Unmapped guard region.
///
/// Architectural intent: Eliminates the need for explicit bounds checking instructions
/// in the JIT compiler. Any out-of-bounds access maps to the guard region,
/// triggering a hardware page fault (EXCEPTION_ACCESS_VIOLATION) caught by VEH.
#[cfg(not(miri))]
const GUARD_REGION_SIZE: usize = 8 * 1024 * 1024 * 1024;

/// A lightweight, `no_std` compatible Test-and-Set (TAS) spinlock.
/// Optimized for extremely short critical sections where OS thread suspension
/// (e.g., via futex) would introduce unacceptable latency.
pub struct SpinMutex<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinMutex<T> {}
unsafe impl<T: Send> Sync for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    /// Acquires the lock, spinning until the atomic state transitions to false.
    /// Utilizes `spin_loop` hint to reduce CPU power consumption and pipeline flushes.
    pub fn lock(&self) -> SpinMutexGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        SpinMutexGuard { mutex: self }
    }
}

/// RAII guard for deterministic lock release.
pub struct SpinMutexGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> Deref for SpinMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for SpinMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for SpinMutexGuard<'_, T> {
    fn drop(&mut self) {
        // Synchronizes with Acquire in lock() to ensure memory visibility.
        self.mutex.locked.store(false, Ordering::Release);
    }
}

/// Hardware-sandboxed linear memory allocation for a WebAssembly instance.
/// Manages the OS-level Virtual Memory lifecycle (Reserve -> Commit -> Decommit/Release).
pub struct LinearMemory {
    base_ptr: *mut u8,
    committed_size: usize,
}

unsafe impl Send for LinearMemory {}
unsafe impl Sync for LinearMemory {}

impl LinearMemory {
    /// Reserves the 8GB virtual address space and commits the initial required pages.
    pub fn new(initial_pages: usize) -> Result<Self, ()> {
        #[cfg(miri)]
        {
            let committed_size = initial_pages * WASM_PAGE_SIZE;
            let base_ptr = if committed_size > 0 {
                let layout =
                    core::alloc::Layout::from_size_align(committed_size, 4096).map_err(|_| ())?;
                unsafe { alloc::alloc::alloc_zeroed(layout) }
            } else {
                core::ptr::NonNull::dangling().as_ptr()
            };
            Ok(Self {
                base_ptr,
                committed_size,
            })
        }

        #[cfg(not(miri))]
        unsafe {
            // Reserve the contiguous 8GB block without allocating physical RAM.
            let base_ptr = VirtualAlloc(
                ptr::null_mut(),
                GUARD_REGION_SIZE,
                MEM_RESERVE,
                PAGE_NOACCESS,
            ) as *mut u8;

            if base_ptr.is_null() {
                return Err(());
            }

            let mut mem = Self {
                base_ptr,
                committed_size: 0,
            };
            if initial_pages > 0 {
                mem.grow(initial_pages)?;
            }
            Ok(mem)
        }
    }

    /// Commits additional physical memory pages incrementally.
    /// Bypasses bounds checks entirely, relying on the pre-reserved 8GB VMA.
    pub fn grow(&mut self, pages: usize) -> Result<(), ()> {
        let size = pages * WASM_PAGE_SIZE;

        #[cfg(miri)]
        {
            let new_size = self.committed_size + size;
            let old_layout = core::alloc::Layout::from_size_align(self.committed_size.max(1), 4096)
                .map_err(|_| ())?;
            let new_ptr = unsafe { alloc::alloc::realloc(self.base_ptr, old_layout, new_size) };
            if new_ptr.is_null() {
                return Err(());
            }
            self.base_ptr = new_ptr;
            self.committed_size = new_size;
            Ok(())
        }

        #[cfg(not(miri))]
        unsafe {
            // Commit physical RAM for the requested block size adjacent to existing memory.
            let ptr = VirtualAlloc(
                self.base_ptr.add(self.committed_size) as _,
                size,
                MEM_COMMIT,
                PAGE_READWRITE,
            );
            if ptr.is_null() {
                return Err(());
            }
            self.committed_size += size;
            Ok(())
        }
    }

    /// Zero-fills the committed memory region for secure instance reuse.
    pub fn clear(&mut self) {
        if self.committed_size > 0 {
            #[cfg(miri)]
            unsafe {
                core::ptr::write_bytes(self.base_ptr, 0, self.committed_size);
            }
            #[cfg(not(miri))]
            unsafe {
                ptr::write_bytes(self.base_ptr, 0, self.committed_size);
            }
        }
    }

    #[inline]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.base_ptr
    }
}

impl Drop for LinearMemory {
    /// Releases the entire 8GB VMA back to the OS.
    fn drop(&mut self) {
        #[cfg(miri)]
        {
            if self.committed_size > 0 {
                let layout =
                    core::alloc::Layout::from_size_align(self.committed_size, 4096).unwrap();
                unsafe {
                    alloc::alloc::dealloc(self.base_ptr, layout);
                }
            }
        }

        #[cfg(not(miri))]
        {
            if !self.base_ptr.is_null() {
                // MEM_RELEASE requires the size parameter to be 0.
                unsafe {
                    VirtualFree(self.base_ptr as _, 0, MEM_RELEASE);
                }
            }
        }
    }
}

/// Global object pool for `LinearMemory` allocations.
/// Amortizes the high latency of `VirtualAlloc` syscalls to enable
/// sub-millisecond instance cold starts.
pub struct InstancePool {
    pool: SpinMutex<Vec<LinearMemory>>,
}

impl Default for InstancePool {
    fn default() -> Self {
        Self::new()
    }
}

impl InstancePool {
    pub const fn new() -> Self {
        Self {
            pool: SpinMutex::new(Vec::new()),
        }
    }

    /// Acquires an initialized memory region from the pool.
    /// Grows or allocates a new region if the pool is exhausted or capacity is insufficient.
    pub fn acquire(&self, initial_pages: usize) -> Result<LinearMemory, ()> {
        let mut pool = self.pool.lock();
        if let Some(mut mem) = pool.pop() {
            // Ensure security and determinism by zeroing out previous state.
            mem.clear();
            let required_size = initial_pages * WASM_PAGE_SIZE;
            if mem.committed_size < required_size {
                let diff_pages = (required_size - mem.committed_size) / WASM_PAGE_SIZE;
                mem.grow(diff_pages)?;
            }
            Ok(mem)
        } else {
            LinearMemory::new(initial_pages)
        }
    }

    /// Returns a memory region to the LIFO pool for subsequent reuse.
    pub fn release(&self, mem: LinearMemory) {
        let mut pool = self.pool.lock();
        pool.push(mem);
    }
}

/// Singleton instance pool shared across the runtime.
pub static MEMORY_POOL: InstancePool = InstancePool::new();

// Compile only for tests, when loom is enabled, and strictly exclude Miri.
#[cfg(all(test, loom, not(miri)))]
mod loom_tests {
    use super::*;
    use loom::sync::Arc;
    use loom::thread;

    #[test]
    fn test_spin_mutex_concurrency() {
        loom::model(|| {
            let mutex = Arc::new(SpinMutex::new(0));
            let mutex_clone = mutex.clone();

            let t = thread::spawn(move || {
                let mut data = mutex_clone.lock();
                *data += 1;
            });

            let mut data = mutex.lock();
            *data += 1;
            drop(data);

            t.join().unwrap();
            assert_eq!(*mutex.lock(), 2);
        });
    }
}
