use std::{ffi::CString, intrinsics::{transmute}, mem::zeroed, ptr::null_mut};

use anyhow::*;
use pe_tools::x64;
use winapi::{shared::ntdef::HANDLE, um::{errhandlingapi::{GetLastError, SetLastError}, memoryapi::{VirtualAllocEx, WriteProcessMemory}, processthreadsapi::{GetThreadContext, ResumeThread, SetThreadContext, SuspendThread}, winnt::{CONTEXT, CONTEXT_ALL, CONTEXT_CONTROL, CONTEXT_FULL, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}}};

/*
 *    code =
 *    push dword 0x17171717 ; ret (high)
 *    push dword 0x17171717 ; ret (low)
 *    pushfq
 *    push rax
 *    push rbx
 *    push rcx
 *    push rdx
 *    push rsi
 *    push rdi
 *    push rbp
 *    push r8
 *    push r9
 *    push r10
 *    push r11
 *    push r12
 *    push r13
 *    push r14
 *    push r15
 *    push dword 0x23232323 ; align stack
 *    mov rcx, 0x1818181818181818 ; dll path, using fastcall
 *    mov rax, 0x1919191919191919 ; LoadLibrary
 *    call rax
 *    pop rax ; pop dummy stack alignment value
 *    pop r15
 *    pop r14
 *    pop r13
 *    pop r12
 *    pop r11
 *    pop r10
 *    pop r9
 *    pop r8
 *    pop rbp
 *    pop rdi
 *    pop rsi
 *    pop rdx
 *    pop rcx
 *    pop rbx
 *    pop rax
 *    popfq
 *    ret
 */

pub fn inject(hp: HANDLE, ht: HANDLE, lib: impl Into<String>) -> Result<()>{
    unsafe {
        let mut code: [u8; 87] = [
            0x68, 0x17, 0x17, 0x17, 0x17,
            0x68, 0x17, 0x17, 0x17, 0x17,
            0x9c,
            0x50,
            0x53,
            0x51,
            0x52,
            0x56,
            0x57,
            0x55,
            0x41, 0x50,
            0x41, 0x51,
            0x41, 0x52,
            0x41, 0x53,
            0x41, 0x54,
            0x41, 0x55,
            0x41, 0x56,
            0x41, 0x57,
            0x68, 0x23, 0x23, 0x23, 0x23,
            0x48, 0xb9, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
            0x48, 0xb8, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19,
            0xff, 0xd0, 0x58,
            0x41, 0x5f,
            0x41, 0x5e,
            0x41, 0x5d,
            0x41, 0x5c,
            0x41, 0x5b,
            0x41, 0x5a,
            0x41, 0x59,
            0x41, 0x58,
            0x5d,
            0x5f,
            0x5e,
            0x5a,
            0x59,
            0x5b,
            0x58,
            0x9d,
            0xc3,
        ];

        let lib = lib.into();
        let lib_len = lib.len();

        let clib_name = CString::new::<String>(lib).expect("CString::new failed");

        let load_library = x64::search_proc_address_from_loaded_module("LoadLibraryA")?;

        let lib_name_addr = VirtualAllocEx(hp, null_mut(), (lib_len + 1) as _, MEM_COMMIT, PAGE_READWRITE);

        let stub_addr = VirtualAllocEx(hp, null_mut(), code.len() as _, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if load_library.is_null() || lib_name_addr.is_null() || stub_addr.is_null() {
            bail!("something happened");
        }

        let res_lib_name = WriteProcessMemory(hp, lib_name_addr, clib_name.as_ptr() as _, lib_len, null_mut());

        if res_lib_name == 0 {
            bail!("could not write to prcoess memory");
        }

        SuspendThread(ht);

        let mut ctx = zeroed::<CONTEXT>();
        ctx.ContextFlags = CONTEXT_CONTROL;

        GetThreadContext(ht, &mut ctx as *mut _);

        let old_rip = transmute::<u64, [u8; 8]>(ctx.Rip.to_le());

        ctx.Rip = stub_addr as _;

        ctx.ContextFlags = CONTEXT_CONTROL;

        // write rip's high bit
        for i in 1..5 {
            code[i] = old_rip[i - 1];
        }

        // write rip's low bit
        for i in 6..10 {
            code[i] = old_rip[i - 2];
        }

        let lib_name_addr = transmute::<u64, [u8; 8]>((lib_name_addr as u64).to_le());

        // write lib name address
        for i in 41..49 {
            code[i] = lib_name_addr[i - 41];
        }

        let load_library = transmute::<u64, [u8; 8]>((load_library as u64).to_le());

        // write load library function address
        for i in 51..59 {
            code[i] = load_library[i - 51];
        }

        WriteProcessMemory(hp, stub_addr, &mut code[0] as *const _ as *mut _, code.len(), null_mut());

        SetThreadContext(ht, &mut ctx as *mut _);

        ResumeThread(ht);

        Ok(())
    }
}
