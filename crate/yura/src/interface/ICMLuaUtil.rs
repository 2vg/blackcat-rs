#[allow(non_snake_case)]
use winapi::{
    ctypes::c_void,
    shared::{
        guiddef::REFIID,
        minwindef::ULONG,
        ntdef::{HRESULT, LPCWSTR},
    },
};
use winreg::HKEY;

#[allow(non_snake_case)]
#[repr(C)]
pub struct ICMLuaUtil {
    lpVtbl: *const ICMLuaUtilVtbl,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct ICMLuaUtilVtbl {
    // parent: IUnknownVtbl,
    QueryInterface:
        unsafe fn(this: *mut ICMLuaUtil, riid: REFIID, ppv: *mut *mut c_void) -> HRESULT,
    Addref: unsafe fn(this: *mut ICMLuaUtil) -> ULONG,
    Release: unsafe fn(this: *mut ICMLuaUtil) -> ULONG,
    SetRasCredentials: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    SetRasEntryProperties: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    DeleteRasEntry: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    LaunchInfSection: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    LaunchInfSectionEx: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    CreateLayerDirectory: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    ShellExec: unsafe fn(
        this: *mut ICMLuaUtil,
        lpFile: LPCWSTR,
        lpParameters: LPCWSTR,
        lpDirectory: LPCWSTR,
        fmask: ULONG,
        nShow: ULONG,
    ) -> HRESULT,
    SetRegistryStringValue: unsafe fn(
        this: *mut ICMLuaUtil,
        hKey: HKEY,
        lpSubKey: LPCWSTR,
        lpValueName: LPCWSTR,
        lpValueString: LPCWSTR,
    ) -> HRESULT,
    DeleteRegistryStringValue: unsafe fn(
        this: *mut ICMLuaUtil,
        hKey: HKEY,
        lpSubKey: LPCWSTR,
        lpValueName: LPCWSTR,
    ) -> HRESULT,
    method3: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method4: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method5: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method6: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method7: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method8: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method9: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method10: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method11: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method12: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
    method13: unsafe fn(this: *mut ICMLuaUtil) -> HRESULT,
}

#[allow(non_snake_case)]
impl ICMLuaUtil {
    pub unsafe fn QueryInterface(&self, riid: REFIID, ppv: *mut *mut c_void) -> HRESULT {
        ((*self.lpVtbl).QueryInterface)(self as *const _ as *mut _, riid, ppv)
    }

    pub unsafe fn Addref(&self) -> ULONG {
        ((*self.lpVtbl).Addref)(self as *const _ as *mut _)
    }

    pub unsafe fn Release(&self) -> ULONG {
        ((*self.lpVtbl).Release)(self as *const _ as *mut _)
    }

    pub unsafe fn SetRasCredentials(&self) -> HRESULT {
        ((*self.lpVtbl).SetRasCredentials)(self as *const _ as *mut _)
    }

    pub unsafe fn SetRasEntryProperties(&self) -> HRESULT {
        ((*self.lpVtbl).SetRasEntryProperties)(self as *const _ as *mut _)
    }

    pub unsafe fn DeleteRasEntry(&self) -> HRESULT {
        ((*self.lpVtbl).DeleteRasEntry)(self as *const _ as *mut _)
    }

    pub unsafe fn LaunchInfSection(&self) -> HRESULT {
        ((*self.lpVtbl).LaunchInfSection)(self as *const _ as *mut _)
    }

    pub unsafe fn LaunchInfSectionEx(&self) -> HRESULT {
        ((*self.lpVtbl).LaunchInfSectionEx)(self as *const _ as *mut _)
    }

    pub unsafe fn CreateLayerDirectory(&self) -> HRESULT {
        ((*self.lpVtbl).CreateLayerDirectory)(self as *const _ as *mut _)
    }

    pub unsafe fn ShellExec(
        &self,
        lpFile: LPCWSTR,
        lpParameters: LPCWSTR,
        lpDirectory: LPCWSTR,
        fmask: ULONG,
        nShow: ULONG,
    ) -> HRESULT {
        ((*self.lpVtbl).ShellExec)(
            self as *const _ as *mut _,
            lpFile,
            lpParameters,
            lpDirectory,
            fmask,
            nShow,
        )
    }

    pub unsafe fn SetRegistryStringValue(
        &self,
        hKey: HKEY,
        lpSubKey: LPCWSTR,
        lpValueName: LPCWSTR,
        lpValueString: LPCWSTR,
    ) -> HRESULT {
        ((*self.lpVtbl).SetRegistryStringValue)(
            self as *const _ as *mut _,
            hKey,
            lpSubKey,
            lpValueName,
            lpValueString,
        )
    }

    pub unsafe fn DeleteRegistryStringValue(
        &self,
        hKey: HKEY,
        lpSubKey: LPCWSTR,
        lpValueName: LPCWSTR,
    ) -> HRESULT {
        ((*self.lpVtbl).DeleteRegistryStringValue)(
            self as *const _ as *mut _,
            hKey,
            lpSubKey,
            lpValueName,
        )
    }

    pub unsafe fn method3(&self) -> HRESULT {
        ((*self.lpVtbl).method3)(self as *const _ as *mut _)
    }

    pub unsafe fn method4(&self) -> HRESULT {
        ((*self.lpVtbl).method4)(self as *const _ as *mut _)
    }

    pub unsafe fn method5(&self) -> HRESULT {
        ((*self.lpVtbl).method5)(self as *const _ as *mut _)
    }

    pub unsafe fn method6(&self) -> HRESULT {
        ((*self.lpVtbl).method6)(self as *const _ as *mut _)
    }

    pub unsafe fn method7(&self) -> HRESULT {
        ((*self.lpVtbl).method7)(self as *const _ as *mut _)
    }

    pub unsafe fn method8(&self) -> HRESULT {
        ((*self.lpVtbl).method8)(self as *const _ as *mut _)
    }

    pub unsafe fn method9(&self) -> HRESULT {
        ((*self.lpVtbl).method9)(self as *const _ as *mut _)
    }

    pub unsafe fn method10(&self) -> HRESULT {
        ((*self.lpVtbl).method10)(self as *const _ as *mut _)
    }

    pub unsafe fn method11(&self) -> HRESULT {
        ((*self.lpVtbl).method11)(self as *const _ as *mut _)
    }

    pub unsafe fn method12(&self) -> HRESULT {
        ((*self.lpVtbl).method12)(self as *const _ as *mut _)
    }

    pub unsafe fn method13(&self) -> HRESULT {
        ((*self.lpVtbl).method13)(self as *const _ as *mut _)
    }
}
