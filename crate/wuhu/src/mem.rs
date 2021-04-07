use crate::prelude::*;

pub fn alloc(size: usize) -> LPVOID {
    _alloc(NULL, size)
}

pub fn alloc_with_addr(addr: LPVOID, size: usize) -> LPVOID {
    _alloc(addr, size)
}

pub fn alloc_process(process: HANDLE, size: usize) -> LPVOID {
    _alloc_process(process, NULL, size)
}

pub fn alloc_process_with_addr(process: HANDLE, addr: LPVOID, size: usize) -> LPVOID {
    _alloc_process(process, addr, size)
}

/*********************
 * Fallback functions *
 *********************/
fn _alloc(addr: LPVOID, size: usize) -> LPVOID {
    unsafe { VirtualAlloc(addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) }
}

fn _alloc_process(process: HANDLE, addr: LPVOID, size: usize) -> LPVOID {
    unsafe {
        VirtualAllocEx(
            process,
            addr,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    }
}
