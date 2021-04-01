use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
};

use ntapi::ntrtl::RtlGetVersion;
use winapi::{shared::ntdef::HRESULT, um::winnt::RTL_OSVERSIONINFOW};

pub fn check(result: HRESULT) {
    if result < 0 {
        println!("{:?}", result);
        panic!("Bad HRESULT!")
    }
}

pub fn file_operation_flags() -> u32 {
    use crate::global::*;
    use winapi::um::shellapi::{FOF_NOCONFIRMATION, FOF_SILENT};

    unsafe {
        if IFileOperationFlags == 0x0 {
            IFileOperationFlags = if get_build_number() > 14997 {
                FOF_NOCONFIRMATION as u32 | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION
            } else {
                FOF_NOCONFIRMATION as u32
                    | FOF_SILENT as u32
                    | FOFX_SHOWELEVATIONPROMPT
                    | FOFX_NOCOPYHOOKS
                    | FOFX_REQUIREELEVATION
            };
        };

        IFileOperationFlags
    }
}

pub fn get_build_number() -> u32 {
    unsafe {
        let mut os = zeroed::<RTL_OSVERSIONINFOW>();

        os.dwOSVersionInfoSize = size_of::<RTL_OSVERSIONINFOW>() as _;

        RtlGetVersion(&mut os);

        os.dwBuildNumber
    }
}

pub fn e(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(Some(0)).collect()
}

pub fn from_wide_ptr(ptr: *const u16) -> String {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    unsafe {
        assert!(!ptr.is_null());
        let len = (0..std::isize::MAX)
            .position(|i| *ptr.offset(i) == 0)
            .unwrap();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

pub fn wstr_cat(dest: *mut c_void, src: &[u16]) {
    unsafe {
        let buffer = std::slice::from_raw_parts_mut::<u16>(dest as _, src.len());

        for (i, ch) in src.iter().enumerate() {
            buffer[i] = *ch;
        }
    }
}
