pub(crate) use winapi::{
    ctypes::c_char,
    shared::{
        minwindef::{DWORD, FALSE, LPVOID},
        ntdef::NULL,
    },
    um::{
        errhandlingapi::GetLastError,
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{
            ReadProcessMemory, VirtualAlloc, VirtualAllocEx, VirtualFreeEx, WriteProcessMemory,
        },
        processthreadsapi::{CreateRemoteThread, GetExitCodeThread, OpenProcess},
        winbase::{INFINITE, WAIT_FAILED},
        winnt::{
            HANDLE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};
