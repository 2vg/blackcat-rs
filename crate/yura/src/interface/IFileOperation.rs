use winapi::shared::{minwindef::DWORD, ntdef::LPCWSTR};
use winapi::{
    ctypes::c_void,
    shared::{guiddef::REFIID, minwindef::ULONG, ntdef::HRESULT},
    um::{shobjidl::IFileOperationProgressSink, shobjidl_core::IShellItem},
};

#[allow(non_snake_case)]
#[repr(C)]
pub struct IFileOperation {
    lpVtbl: *const IFileOperationVtble,
}

#[allow(non_snake_case)]
pub struct IFileOperationVtble {
    QueryInterface:
        unsafe fn(this: *mut IFileOperation, riid: REFIID, ppv: *mut *mut c_void) -> HRESULT,
    Addref: unsafe fn(this: *mut IFileOperation) -> ULONG,
    Release: unsafe fn(this: *mut IFileOperation) -> ULONG,
    Advise: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    Unadvise: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    SetOperationFlags: unsafe fn(this: *mut IFileOperation, dwOperationFlags: DWORD) -> HRESULT,
    SetProgressMessage: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    SetProgressDialog: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    SetProperties: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    SetOwnerWindow: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    ApplyPropertiesToItem: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    ApplyPropertiesToItems: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    RenameItem: unsafe fn(
        this: *mut IFileOperation,
        psiItem: *mut IShellItem,
        pszNewName: LPCWSTR,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT,
    RenameItems: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    MoveItem: unsafe fn(
        this: *mut IFileOperation,
        psiItem: *mut IShellItem,
        psiDestinationFolder: *mut IShellItem,
        pszCopyName: LPCWSTR,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT,
    MoveItems: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    CopyItem: unsafe fn(
        this: *mut IFileOperation,
        psiItem: *mut IShellItem,
        psiDestinationFolder: *mut IShellItem,
        pszCopyName: LPCWSTR,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT,
    CopyItems: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    DeleteItem: unsafe fn(
        this: *mut IFileOperation,
        psiItem: *mut IShellItem,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT,
    DeleteItems: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    NewItem: unsafe fn(
        this: *mut IFileOperation,
        psiDestinationFolder: *mut IShellItem,
        dwFileAttributes: DWORD,
        pszName: LPCWSTR,
        pszTemplateName: LPCWSTR,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT,
    PerformOperations: unsafe fn(this: *mut IFileOperation) -> HRESULT,
    GetAnyOperationsAborted: unsafe fn(this: *mut IFileOperation) -> HRESULT,
}

#[allow(non_snake_case)]
impl IFileOperation {
    pub unsafe fn QueryInterface(&self, riid: REFIID, ppv: *mut *mut c_void) -> HRESULT {
        ((*self.lpVtbl).QueryInterface)(self as *const _ as *mut _, riid, ppv)
    }

    pub unsafe fn Addref(&self) -> ULONG {
        ((*self.lpVtbl).Addref)(self as *const _ as *mut _)
    }

    pub unsafe fn Release(&self) -> ULONG {
        ((*self.lpVtbl).Release)(self as *const _ as *mut _)
    }

    pub unsafe fn Advise(&self) -> HRESULT {
        ((*self.lpVtbl).Advise)(self as *const _ as *mut _)
    }

    pub unsafe fn ApplyPropertiesToItem(&self) -> HRESULT {
        ((*self.lpVtbl).ApplyPropertiesToItem)(self as *const _ as *mut _)
    }

    pub unsafe fn ApplyPropertiesToItems(&self) -> HRESULT {
        ((*self.lpVtbl).ApplyPropertiesToItems)(self as *const _ as *mut _)
    }

    pub unsafe fn CopyItem(
        &self,
        psiItem: *mut IShellItem,
        psiDestinationFolder: *mut IShellItem,
        pszCopyName: LPCWSTR,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT {
        ((*self.lpVtbl).CopyItem)(
            self as *const _ as *mut _,
            psiItem,
            psiDestinationFolder,
            pszCopyName,
            pfopsItem,
        )
    }

    pub unsafe fn CopyItems(&self) -> HRESULT {
        ((*self.lpVtbl).CopyItems)(self as *const _ as *mut _)
    }

    pub unsafe fn DeleteItem(
        &self,
        psiItem: *mut IShellItem,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT {
        ((*self.lpVtbl).DeleteItem)(self as *const _ as *mut _, psiItem, pfopsItem)
    }

    pub unsafe fn DeleteItems(&self) -> HRESULT {
        ((*self.lpVtbl).DeleteItems)(self as *const _ as *mut _)
    }

    pub unsafe fn GetAnyOperationsAborted(&self) -> HRESULT {
        ((*self.lpVtbl).GetAnyOperationsAborted)(self as *const _ as *mut _)
    }

    pub unsafe fn MoveItem(
        &self,
        psiItem: *mut IShellItem,
        psiDestinationFolder: *mut IShellItem,
        pszCopyName: LPCWSTR,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT {
        ((*self.lpVtbl).MoveItem)(
            self as *const _ as *mut _,
            psiItem,
            psiDestinationFolder,
            pszCopyName,
            pfopsItem,
        )
    }

    pub unsafe fn MoveItems(&self) -> HRESULT {
        ((*self.lpVtbl).MoveItems)(self as *const _ as *mut _)
    }

    pub unsafe fn NewItem(
        &self,
        psiDestinationFolder: *mut IShellItem,
        dwFileAttributes: DWORD,
        pszName: LPCWSTR,
        pszTemplateName: LPCWSTR,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT {
        ((*self.lpVtbl).NewItem)(
            self as *const _ as *mut _,
            psiDestinationFolder,
            dwFileAttributes,
            pszName,
            pszTemplateName,
            pfopsItem,
        )
    }

    pub unsafe fn PerformOperations(&self) -> HRESULT {
        ((*self.lpVtbl).PerformOperations)(self as *const _ as *mut _)
    }

    pub unsafe fn RenameItem(
        &self,
        psiItem: *mut IShellItem,
        pszNewName: LPCWSTR,
        pfopsItem: *mut IFileOperationProgressSink,
    ) -> HRESULT {
        ((*self.lpVtbl).RenameItem)(self as *const _ as *mut _, psiItem, pszNewName, pfopsItem)
    }

    pub unsafe fn RenameItems(&self) -> HRESULT {
        ((*self.lpVtbl).RenameItems)(self as *const _ as *mut _)
    }

    pub unsafe fn SetOperationFlags(&self, dwOperationFlags: DWORD) -> HRESULT {
        ((*self.lpVtbl).SetOperationFlags)(self as *const _ as *mut _, dwOperationFlags)
    }

    pub unsafe fn SetOwnerWindow(&self) -> HRESULT {
        ((*self.lpVtbl).SetOwnerWindow)(self as *const _ as *mut _)
    }

    pub unsafe fn SetProgressDialog(&self) -> HRESULT {
        ((*self.lpVtbl).SetProgressDialog)(self as *const _ as *mut _)
    }

    pub unsafe fn SetProgressMessage(&self) -> HRESULT {
        ((*self.lpVtbl).SetProgressMessage)(self as *const _ as *mut _)
    }

    pub unsafe fn SetProperties(&self) -> HRESULT {
        ((*self.lpVtbl).SetProperties)(self as *const _ as *mut _)
    }

    pub unsafe fn Unadvise(&self) -> HRESULT {
        ((*self.lpVtbl).Unadvise)(self as *const _ as *mut _)
    }
}
