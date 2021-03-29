use std::ptr::null_mut;

use anyhow::*;
use pe_tools::{shared, x64};
use pelite::pe64::exports::GetProcAddress;
use winapi::ctypes::c_void;

pub fn get_loader_offset(dll_base_address: *mut c_void) -> Result<*mut c_void> {
    let dll_container = x64::PEContainer::new(dll_base_address, true)?;
    let loader = dll_container.search_expoted_func("reflective_load");

    if loader.is_ok() {
        Ok(loader.unwrap() as _)
    } else {
        bail!("could not find reflective_load function")
    }
}
