#![allow(dead_code)]

/***********
 * BINDING *
 ***********/
pub enum c_void {}
pub type c_char = i8;
pub type c_schar = i8;
pub type c_uchar = u8;
pub type c_short = i16;
pub type c_ushort = u16;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_long = i32;
pub type c_ulong = u32;
pub type c_longlong = i64;
pub type c_ulonglong = u64;
pub type c_float = f32;
pub type c_double = f64;
pub type __int8 = i8;
pub type __uint8 = u8;
pub type __int16 = i16;
pub type __uint16 = u16;
pub type __int32 = i32;
pub type __uint32 = u32;
pub type __int64 = i64;
pub type __uint64 = u64;
pub type wchar_t = u16;

pub type BOOLEAN = UCHAR;
pub type POINTER_64_INT = usize;
pub type INT8 = c_schar;
pub type PINT8 = *mut c_schar;
pub type INT16 = c_short;
pub type PINT16 = *mut c_short;
pub type INT32 = c_int;
pub type PINT32 = *mut c_int;
pub type INT64 = __int64;
pub type PINT64 = *mut __int64;
pub type UINT8 = c_uchar;
pub type PUINT8 = *mut c_uchar;
pub type UINT16 = c_ushort;
pub type PUINT16 = *mut c_ushort;
pub type UINT32 = c_uint;
pub type PUINT32 = *mut c_uint;
pub type UINT64 = __uint64;
pub type PUINT64 = *mut __uint64;
pub type LONG32 = c_int;
pub type PLONG32 = *mut c_int;
pub type ULONG32 = c_uint;
pub type PULONG32 = *mut c_uint;
pub type DWORD32 = c_uint;
pub type PDWORD32 = *mut c_uint;
pub type INT_PTR = isize;
pub type PINT_PTR = *mut isize;
pub type UINT_PTR = usize;
pub type PUINT_PTR = *mut usize;
pub type LONG_PTR = isize;
pub type PLONG_PTR = *mut isize;
pub type ULONG_PTR = usize;
pub type PULONG_PTR = *mut usize;
pub type SHANDLE_PTR = isize;
pub type HANDLE_PTR = usize;
#[cfg(target_pointer_width = "32")]
pub type UHALF_PTR = c_ushort;
#[cfg(target_pointer_width = "64")]
pub type UHALF_PTR = c_uint;
#[cfg(target_pointer_width = "32")]
pub type PUHALF_PTR = *mut c_ushort;
#[cfg(target_pointer_width = "64")]
pub type PUHALF_PTR = *mut c_uint;
#[cfg(target_pointer_width = "32")]
pub type HALF_PTR = c_short;
#[cfg(target_pointer_width = "64")]
pub type HALF_PTR = c_int;
#[cfg(target_pointer_width = "32")]
pub type PHALF_PTR = *mut c_short;
#[cfg(target_pointer_width = "64")]
pub type PHALF_PTR = *mut c_int;
pub type SIZE_T = ULONG_PTR;
pub type PSIZE_T = *mut ULONG_PTR;
pub type SSIZE_T = LONG_PTR;
pub type PSSIZE_T = *mut LONG_PTR;
pub type DWORD_PTR = ULONG_PTR;
pub type PDWORD_PTR = *mut ULONG_PTR;
pub type LONG64 = __int64;
pub type PLONG64 = *mut __int64;
pub type ULONG64 = __uint64;
pub type PULONG64 = *mut __uint64;
pub type DWORD64 = __uint64;
pub type PDWORD64 = *mut __uint64;
pub type KAFFINITY = ULONG_PTR;
pub type PKAFFINITY = *mut KAFFINITY;

pub type ULONG = c_ulong;
pub type PULONG = *mut ULONG;
pub type USHORT = c_ushort;
pub type PUSHORT = *mut USHORT;
pub type UCHAR = c_uchar;
pub type PUCHAR = *mut UCHAR;
pub type PSZ = *mut c_char;
pub const MAX_PATH: usize = 260;
pub const FALSE: BOOL = 0;
pub const TRUE: BOOL = 1;
pub type DWORD = c_ulong;
pub type BOOL = c_int;
pub type BYTE = c_uchar;
pub type WORD = c_ushort;
pub type FLOAT = c_float;
pub type PFLOAT = *mut FLOAT;
pub type PBOOL = *mut BOOL;
pub type LPBOOL = *mut BOOL;
pub type PBYTE = *mut BYTE;
pub type LPBYTE = *mut BYTE;
pub type PINT = *mut c_int;
pub type LPINT = *mut c_int;
pub type PWORD = *mut WORD;
pub type LPWORD = *mut WORD;
pub type LPLONG = *mut c_long;
pub type PDWORD = *mut DWORD;
pub type LPDWORD = *mut DWORD;
pub type LPVOID = *mut c_void;
pub type LPCVOID = *const c_void;
pub type INT = c_int;
pub type UINT = c_uint;
pub type PUINT = *mut c_uint;
pub type WPARAM = UINT_PTR;
pub type LPARAM = LONG_PTR;
pub type LRESULT = LONG_PTR;

pub type PVOID = *mut c_void;
pub type PVOID64 = u64; // This is a 64-bit pointer, even when in 32-bit
pub type VOID = c_void;
pub type CHAR = c_char;
pub type SHORT = c_short;
pub type LONG = c_long;
pub type WCHAR = wchar_t;
pub type PWCHAR = *mut WCHAR;
pub type LPWCH = *mut WCHAR;
pub type PWCH = *mut WCHAR;
pub type LPCWCH = *const WCHAR;
pub type PCWCH = *const WCHAR;
pub type NWPSTR = *mut WCHAR;
pub type LPWSTR = *mut WCHAR;
pub type LPTSTR = LPSTR;
pub type PWSTR = *mut WCHAR;
pub type PZPWSTR = *mut PWSTR;
pub type PCZPWSTR = *const PWSTR;
pub type LPUWSTR = *mut WCHAR; // Unaligned pointer
pub type PUWSTR = *mut WCHAR; // Unaligned pointer
pub type LPCWSTR = *const WCHAR;
pub type PCWSTR = *const WCHAR;
pub type PZPCWSTR = *mut PCWSTR;
pub type PCZPCWSTR = *const PCWSTR;
pub type LPCUWSTR = *const WCHAR; // Unaligned pointer
pub type PCUWSTR = *const WCHAR; // Unaligned pointer
pub type PZZWSTR = *mut WCHAR;
pub type PCZZWSTR = *const WCHAR;
pub type PUZZWSTR = *mut WCHAR; // Unaligned pointer
pub type PCUZZWSTR = *const WCHAR; // Unaligned pointer
pub type PNZWCH = *mut WCHAR;
pub type PCNZWCH = *const WCHAR;
pub type PUNZWCH = *mut WCHAR; // Unaligned pointer
pub type PCUNZWCH = *const WCHAR; // Unaligned pointer
pub type LPCWCHAR = *const WCHAR;
pub type PCWCHAR = *const WCHAR;
pub type LPCUWCHAR = *const WCHAR; // Unaligned pointer
pub type PCUWCHAR = *const WCHAR; // Unaligned pointer
pub type UCSCHAR = c_ulong;
pub const UCSCHAR_INVALID_CHARACTER: UCSCHAR = 0xffffffff;
pub const MIN_UCSCHAR: UCSCHAR = 0;
pub const MAX_UCSCHAR: UCSCHAR = 0x0010FFFF;
pub type PUCSCHAR = *mut UCSCHAR;
pub type PCUCSCHAR = *const UCSCHAR;
pub type PUCSSTR = *mut UCSCHAR;
pub type PUUCSSTR = *mut UCSCHAR; // Unaligned pointer
pub type PCUCSSTR = *const UCSCHAR;
pub type PCUUCSSTR = *const UCSCHAR; // Unaligned pointer
pub type PUUCSCHAR = *mut UCSCHAR; // Unaligned pointer
pub type PCUUCSCHAR = *const UCSCHAR; // Unaligned pointer
pub type PCHAR = *mut CHAR;
pub type LPCH = *mut CHAR;
pub type PCH = *mut CHAR;
pub type LPCCH = *const CHAR;
pub type PCCH = *const CHAR;
pub type NPSTR = *mut CHAR;
pub type LPSTR = *mut CHAR;
pub type PSTR = *mut CHAR;
pub type PZPSTR = *mut PSTR;
pub type PCZPSTR = *const PSTR;
pub type LPCSTR = *const CHAR;
pub type PCSTR = *const CHAR;
pub type PZPCSTR = *mut PCSTR;
pub type PCZPCSTR = *const PCSTR;
pub type PZZSTR = *mut CHAR;
pub type PCZZSTR = *const CHAR;
pub type PNZCH = *mut CHAR;
pub type PCNZCH = *const CHAR;

pub type SPHANDLE = *mut HANDLE;
pub type LPHANDLE = *mut HANDLE;
pub type HGLOBAL = HANDLE;
pub type HLOCAL = HANDLE;
pub type GLOBALHANDLE = HANDLE;
pub type LOCALHANDLE = HANDLE;
pub enum __some_function {}
/// Pointer to a function with unknown type signature.
pub type FARPROC = *mut __some_function;
/// Pointer to a function with unknown type signature.
pub type NEARPROC = *mut __some_function;
/// Pointer to a function with unknown type signature.
pub type PROC = *mut __some_function;
pub type ATOM = WORD;

pub enum HINSTANCE__ {}
pub type HINSTANCE = *mut HINSTANCE__;
pub type HMODULE = HINSTANCE;

pub type HANDLE = *mut c_void;
pub type PHANDLE = *mut HANDLE;
pub type FCHAR = UCHAR;
pub type FSHORT = USHORT;
pub type FLONG = ULONG;
pub type HRESULT = c_long;
pub const OBJ_HANDLE_TAGBITS: usize = 0x00000003;
pub type CCHAR = c_char;
pub type CSHORT = c_short;
pub type CLONG = ULONG;
pub type PCCHAR = *mut CCHAR;
pub type PCSHORT = *mut CSHORT;
pub type PCLONG = *mut CLONG;
pub type LCID = ULONG;
pub type PLCID = PULONG;
pub type LANGID = USHORT;
pub type LOGICAL = ULONG;
pub type PLOGICAL = *mut ULONG;
pub type NTSTATUS = LONG;
pub type PNTSTATUS = *mut NTSTATUS;
pub type PCNTSTATUS = *const NTSTATUS;

pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_WRITECOPY: DWORD = 0x08;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;
pub const PAGE_GUARD: DWORD = 0x100;
pub const PAGE_NOCACHE: DWORD = 0x200;
pub const PAGE_WRITECOMBINE: DWORD = 0x400;
pub const PAGE_ENCLAVE_THREAD_CONTROL: DWORD = 0x80000000;
pub const PAGE_REVERT_TO_FILE_MAP: DWORD = 0x80000000;
pub const PAGE_TARGETS_NO_UPDATE: DWORD = 0x40000000;
pub const PAGE_TARGETS_INVALID: DWORD = 0x40000000;
pub const PAGE_ENCLAVE_UNVALIDATED: DWORD = 0x20000000;
pub const PAGE_ENCLAVE_DECOMMIT: DWORD = 0x10000000;
pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_RESERVE: DWORD = 0x2000;
pub const MEM_DECOMMIT: DWORD = 0x4000;
pub const MEM_RELEASE: DWORD = 0x8000;
pub const MEM_FREE: DWORD = 0x10000;
pub const MEM_PRIVATE: DWORD = 0x20000;
pub const MEM_MAPPED: DWORD = 0x40000;
pub const MEM_RESET: DWORD = 0x80000;
pub const MEM_TOP_DOWN: DWORD = 0x100000;
pub const MEM_WRITE_WATCH: DWORD = 0x200000;
pub const MEM_PHYSICAL: DWORD = 0x400000;
pub const MEM_ROTATE: DWORD = 0x800000;
pub const MEM_DIFFERENT_IMAGE_BASE_OK: DWORD = 0x800000;
pub const MEM_RESET_UNDO: DWORD = 0x1000000;
pub const MEM_LARGE_PAGES: DWORD = 0x20000000;
pub const MEM_4MB_PAGES: DWORD = 0x80000000;
pub const MEM_64K_PAGES: DWORD = MEM_LARGE_PAGES | MEM_PHYSICAL;
pub const SEC_64K_PAGES: DWORD = 0x00080000;
pub const SEC_FILE: DWORD = 0x800000;
pub const SEC_IMAGE: DWORD = 0x1000000;
pub const SEC_PROTECTED_IMAGE: DWORD = 0x2000000;
pub const SEC_RESERVE: DWORD = 0x4000000;
pub const SEC_COMMIT: DWORD = 0x8000000;
pub const SEC_NOCACHE: DWORD = 0x10000000;
pub const SEC_WRITECOMBINE: DWORD = 0x40000000;
pub const SEC_LARGE_PAGES: DWORD = 0x80000000;
pub const SEC_IMAGE_NO_EXECUTE: DWORD = SEC_IMAGE | SEC_NOCACHE;
pub const MEM_IMAGE: DWORD = SEC_IMAGE;
pub const WRITE_WATCH_FLAG_RESET: DWORD = 0x01;
pub const MEM_UNMAP_WITH_TRANSIENT_BOOST: DWORD = 0x01;
pub const ENCLAVE_TYPE_SGX: DWORD = 0x00000001;
pub const ENCLAVE_TYPE_SGX2: DWORD = 0x00000002;

pub type PFLOAT128 = *mut FLOAT128;
pub type LONGLONG = __int64;
pub type ULONGLONG = __uint64;
pub const MAXLONGLONG: LONGLONG = 0x7fffffffffffffff;
pub type PLONGLONG = *mut LONGLONG;
pub type PULONGLONG = *mut ULONGLONG;
pub type USN = LONGLONG;

pub struct FLOAT128 {
    pub LowPart: __int64,
    pub HighPart: __int64,
}

pub const NULL: PVOID = 0 as PVOID;
pub const NULL64: PVOID64 = 0;
//pub const MINCHAR: CHAR = 0x80;
pub const MAXCHAR: CHAR = 0x7f;
//pub const MINSHORT: SHORT = 0x8000;
pub const MAXSHORT: SHORT = 0x7fff;
//pub const MINLONG: LONG = 0x80000000;
pub const MAXLONG: LONG = 0x7fffffff;
pub const MAXUCHAR: UCHAR = 0xff;
pub const MAXUSHORT: USHORT = 0xffff;
pub const MAXULONG: ULONG = 0xffffffff;

pub const IMAGE_DOS_SIGNATURE: WORD = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: DWORD = 0x00004550;

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWCH,
}

#[repr(C)]
pub struct ANSI_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PCHAR,
}

pub const IMAGE_SUBSYSTEM_UNKNOWN: WORD = 0;
pub const IMAGE_SUBSYSTEM_NATIVE: WORD = 1;
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: WORD = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: WORD = 3;
pub const IMAGE_SUBSYSTEM_OS2_CUI: WORD = 5;
pub const IMAGE_SUBSYSTEM_POSIX_CUI: WORD = 7;
pub const IMAGE_SUBSYSTEM_NATIVE_WINDOWS: WORD = 8;
pub const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: WORD = 9;
pub const IMAGE_SUBSYSTEM_EFI_APPLICATION: WORD = 10;
pub const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: WORD = 11;
pub const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: WORD = 12;
pub const IMAGE_SUBSYSTEM_EFI_ROM: WORD = 13;
pub const IMAGE_SUBSYSTEM_XBOX: WORD = 14;
pub const IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: WORD = 16;
pub const IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG: WORD = 17;
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: WORD = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: WORD = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: WORD = 0x0080;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: WORD = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: WORD = 0x0200;
pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: WORD = 0x0400;
pub const IMAGE_DLLCHARACTERISTICS_NO_BIND: WORD = 0x0800;
pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: WORD = 0x1000;
pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: WORD = 0x2000;
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: WORD = 0x4000;
pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: WORD = 0x8000;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: WORD = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: WORD = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: WORD = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: WORD = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: WORD = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: WORD = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: WORD = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: WORD = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: WORD = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: WORD = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: WORD = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: WORD = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: WORD = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: WORD = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: WORD = 14;

pub const IMAGE_ORDINAL_FLAG64: ULONGLONG = 0x8000000000000000;
pub const IMAGE_ORDINAL_FLAG32: DWORD = 0x80000000;

#[inline]
pub fn NT_SUCCESS(Status: NTSTATUS) -> bool {
    Status >= 0
}
#[inline]
pub fn NT_INFORMATION(Status: NTSTATUS) -> bool {
    ((Status as ULONG) >> 30) == 1
}
#[inline]
pub fn NT_WARNING(Status: NTSTATUS) -> bool {
    ((Status as ULONG) >> 30) == 2
}
#[inline]
pub fn NT_ERROR(Status: NTSTATUS) -> bool {
    ((Status as ULONG) >> 30) == 3
}
#[inline]
pub fn IMAGE_ORDINAL64(Ordinal: ULONGLONG) -> ULONGLONG {
    Ordinal & 0xffff
}
#[inline]
pub fn IMAGE_ORDINAL32(Ordinal: DWORD) -> DWORD {
    Ordinal & 0xffff
}
#[inline]
pub fn IMAGE_SNAP_BY_ORDINAL64(Ordinal: ULONGLONG) -> bool {
    (Ordinal & IMAGE_ORDINAL_FLAG64) != 0
}
#[inline]
pub fn IMAGE_SNAP_BY_ORDINAL32(Ordinal: DWORD) -> bool {
    (Ordinal & IMAGE_ORDINAL_FLAG32) != 0
}

//    (pub ){0,1}([a-z A-Z 0-9 _]*):
//    pub $2:

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}

#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: BOOLEAN,
    pub ReadImageFileExecOptions: BOOLEAN,
    pub BeingDebugged: BOOLEAN,
    pub BitField: BOOLEAN,
    pub Mutant: HANDLE,
    pub ImageBaseAddress: PVOID,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: ULONG,
    pub Initialized: BOOLEAN,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    // ...
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: ULONG,
    pub Length: ULONG,
    pub Flags: ULONG,
    pub DebugFlags: ULONG,
    pub ConsoleHandle: HANDLE,
    pub ConsoleFlags: ULONG,
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LIST_ENTRY,
    pub DllBase: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    // ...
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub ImageBase: ULONGLONG,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: ULONGLONG,
    pub SizeOfStackCommit: ULONGLONG,
    pub SizeOfHeapReserve: ULONGLONG,
    pub SizeOfHeapCommit: ULONGLONG,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

#[repr(C)]
pub struct IMAGE_SECTION_HEADER_Misc ([u32; 1]);
impl Copy for IMAGE_SECTION_HEADER_Misc {}
impl Clone for IMAGE_SECTION_HEADER_Misc {
    #[inline]
    fn clone(&self) -> IMAGE_SECTION_HEADER_Misc { *self }
}
impl IMAGE_SECTION_HEADER_Misc {
    pub unsafe fn PhysicalAddress(&self) -> &DWORD {
        &*(self as *const _ as *const DWORD)
    }

    pub unsafe fn PhysicalAddress_mut(&mut self) -> &mut DWORD {
        &mut *(self as *mut _ as *mut DWORD)
    }

    pub unsafe fn VirtualSize(&self) -> &DWORD {
        &*(self as *const _ as *const DWORD)
    }

    pub unsafe fn VirtualSize_mut(&mut self) -> &mut DWORD {
        &mut *(self as *mut _ as *mut DWORD)
    }
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [BYTE; IMAGE_SIZEOF_SHORT_NAME],
    pub Misc: IMAGE_SECTION_HEADER_Misc,
    pub VirtualAddress: DWORD,
    pub SizeOfRawData: DWORD,
    pub PointerToRawData: DWORD,
    pub PointerToRelocations: DWORD,
    pub PointerToLinenumbers: DWORD,
    pub NumberOfRelocations: WORD,
    pub NumberOfLinenumbers: WORD,
    pub Characteristics: DWORD,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: WORD,
    pub Name: [CHAR; 1],
}

#[repr(C)]
pub struct IMAGE_THUNK_DATA64_u1([u64; 1]);
impl Copy for IMAGE_THUNK_DATA64_u1 {}
impl Clone for IMAGE_THUNK_DATA64_u1 {
    #[inline]
    fn clone(&self) -> IMAGE_THUNK_DATA64_u1 { *self }
}
impl IMAGE_THUNK_DATA64_u1 {
    pub unsafe fn ForwarderString(&self) -> &ULONGLONG {
        &*(self as *const _ as *const ULONGLONG)
    }

    pub unsafe fn ForwarderString_mut(&mut self) -> &mut ULONGLONG {
        &mut *(self as *mut _ as *mut ULONGLONG)
    }

    pub unsafe fn Function(&self) -> &ULONGLONG {
        &*(self as *const _ as *const ULONGLONG)
    }

    pub unsafe fn Function_mut(&mut self) -> &mut ULONGLONG {
        &mut *(self as *mut _ as *mut ULONGLONG)
    }

    pub unsafe fn Ordinal(&self) -> &ULONGLONG {
        &*(self as *const _ as *const ULONGLONG)
    }

    pub unsafe fn Ordinal_mut(&mut self) -> &mut ULONGLONG {
        &mut *(self as *mut _ as *mut ULONGLONG)
    }

    pub unsafe fn AddressOfData(&self) -> &ULONGLONG {
        &*(self as *const _ as *const ULONGLONG)
    }

    pub unsafe fn AddressOfData_mut(&mut self) -> &mut ULONGLONG {
        &mut *(self as *mut _ as *mut ULONGLONG)
    }
}

#[repr(C)]
pub struct IMAGE_THUNK_DATA64 {
    pub u1: IMAGE_THUNK_DATA64_u1,
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR_u([u32; 1]);
impl Copy for IMAGE_IMPORT_DESCRIPTOR_u {}
impl Clone for IMAGE_IMPORT_DESCRIPTOR_u {
    #[inline]
    fn clone(&self) -> IMAGE_IMPORT_DESCRIPTOR_u { *self }
}
impl IMAGE_IMPORT_DESCRIPTOR_u {
    pub unsafe fn Characteristics(&self) -> &DWORD {
        &*(self as *const _ as *const DWORD)
    }

    pub unsafe fn Characteristics_mut(&mut self) -> &mut DWORD {
        &mut *(self as *mut _ as *mut DWORD)
    }

    pub unsafe fn OriginalFirstThunk(&self) -> &DWORD {
        &*(self as *const _ as *const DWORD)
    }

    pub unsafe fn OriginalFirstThunk_mut(&mut self) -> &mut DWORD {
        &mut *(self as *mut _ as *mut DWORD)
    }
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub u: IMAGE_IMPORT_DESCRIPTOR_u,
    pub TimeDateStamp: DWORD,
    pub ForwarderChain: DWORD,
    pub Name: DWORD,
    pub FirstThunk: DWORD,
}

#[repr(C)]
pub struct IMAGE_DELAYLOAD_DESCRIPTOR_Attributes {
    pub AllAttributes: DWORD,
}

#[repr(C)]
pub struct IMAGE_DELAYLOAD_DESCRIPTOR {
    pub Attributes: IMAGE_DELAYLOAD_DESCRIPTOR_Attributes,
    pub DllNameRVA: DWORD,
    pub ModuleHandleRVA: DWORD,
    pub ImportAddressTableRVA: DWORD,
    pub ImportNameTableRVA: DWORD,
    pub BoundImportAddressTableRVA: DWORD,
    pub UnloadInformationTableRVA: DWORD,
    pub TimeDateStamp: DWORD,
}

#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: DWORD,
    pub SizeOfBlock: DWORD,
}

#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY64 {
    pub StartAddressOfRawData: ULONGLONG,
    pub EndAddressOfRawData: ULONGLONG,
    pub AddressOfIndex: ULONGLONG,
    pub AddressOfCallBacks: ULONGLONG,
    pub SizeOfZeroFill: DWORD,
    pub Characteristics: DWORD,
}

#[repr(C)]
pub struct IMAGE_RUNTIME_FUNCTION_ENTRY_u([u32; 1]);
impl Copy for IMAGE_RUNTIME_FUNCTION_ENTRY_u {}
impl Clone for IMAGE_RUNTIME_FUNCTION_ENTRY_u {
    #[inline]
    fn clone(&self) -> IMAGE_RUNTIME_FUNCTION_ENTRY_u { *self }
}
impl IMAGE_RUNTIME_FUNCTION_ENTRY_u {
    pub unsafe fn UnwindInfoAddress(&self) -> &DWORD {
        &*(self as *const _ as *const DWORD)
    }

    pub unsafe fn UnwindInfoAddress_mut(&mut self) -> &mut DWORD {
        &mut *(self as *mut _ as *mut DWORD)
    }

    pub unsafe fn UnwindData(&self) -> &DWORD {
        &*(self as *const _ as *const DWORD)
    }

    pub unsafe fn UnwindData_mut(&mut self) -> &mut DWORD {
        &mut *(self as *mut _ as *mut DWORD)
    }
}

#[repr(C)]
pub struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub BeginAddress: DWORD,
    pub EndAddress: DWORD,
    pub u: IMAGE_RUNTIME_FUNCTION_ENTRY_u,
}

pub type IMAGE_RUNTIME_FUNCTION_ENTRY = _IMAGE_RUNTIME_FUNCTION_ENTRY;
pub type PRUNTIME_FUNCTION = *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
