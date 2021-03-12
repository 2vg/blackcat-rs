#![windows_subsystem = "windows"]

use winapi::um::winuser::{MessageBoxW, MB_OK};
use std::ptr;

fn main() {
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            e("Hello ♡").as_ptr(),
            e("ur machine hacked ฅ( ̳• ε • ̳").as_ptr(),
            MB_OK
        );
    }
}

fn e(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(Some(0)).collect()
}
