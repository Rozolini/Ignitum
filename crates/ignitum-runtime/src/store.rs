use alloc::vec::Vec;
use ignitum_jit::memory::{LinearMemory, MEMORY_POOL};

/// Root ownership layer for WebAssembly state (Memory, Tables, Globals).
/// Maintains a collection of resources required for module execution.
pub struct Store {
    /// Actively allocated linear memory regions for this store.
    memories: Vec<LinearMemory>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// Initializes an empty store.
    pub fn new() -> Self {
        Self {
            memories: Vec::new(),
        }
    }

    /// Requests a new hardware-sandboxed memory region from the global `InstancePool`.
    ///
    /// Returns the internal memory index (ID) upon successful allocation.
    /// syscalls are amortized by reusing regions from the global pool.
    pub fn alloc_memory(&mut self, initial_pages: usize) -> Result<usize, ()> {
        let mem = MEMORY_POOL.acquire(initial_pages)?;
        let id = self.memories.len();
        self.memories.push(mem);
        Ok(id)
    }

    /// Provides mutable access to a specific memory instance by its ID.
    pub fn memory_mut(&mut self, id: usize) -> Option<&mut LinearMemory> {
        self.memories.get_mut(id)
    }
}

impl Drop for Store {
    /// Recycles all owned memory regions back to the global `MEMORY_POOL`.
    ///
    /// This zero-cost deallocation ensures that subsequent instances can achieve
    /// sub-millisecond cold starts by skipping `VirtualAlloc` calls.
    fn drop(&mut self) {
        while let Some(mem) = self.memories.pop() {
            MEMORY_POOL.release(mem);
        }
    }
}
