use crate::dll::loader64;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _module: HINSTANCE,
    call_reason: DWORD,
    _reserved: LPVOID,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            msg("hello", "test");
        }
        _ => {}
    };

    true as _
}

use std::ptr;
use winapi::um::winuser::{MessageBoxW, MB_OK};

fn e(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(Some(0)).collect()
}

fn msg(t: impl Into<String>, c: impl Into<String>) {
    let t = t.into();
    let c = c.into();
    unsafe {
        MessageBoxW(ptr::null_mut(), e(&c).as_ptr(), e(&t).as_ptr(), MB_OK);
    }
}
