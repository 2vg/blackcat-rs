use winapi::shared::windef::HWND;
use winapi::{
    ctypes::c_void,
    shared::{guiddef::REFIID, minwindef::ULONG, ntdef::HRESULT},
};

#[allow(non_snake_case)]
#[repr(C)]
pub struct IColorDataProxy {
    lpVtbl: *const IColorDataProxyVtble,
}

#[allow(non_snake_case)]
pub struct IColorDataProxyVtble {
    QueryInterface:
        unsafe fn(this: *mut IColorDataProxy, riid: REFIID, ppv: *mut *mut c_void) -> HRESULT,
    Addref: unsafe fn(this: *mut IColorDataProxy) -> ULONG,
    Release: unsafe fn(this: *mut IColorDataProxy) -> ULONG,
    method1: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method2: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method3: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method4: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method5: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method6: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method7: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method8: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method9: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method10: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    method11: unsafe fn(this: *mut IColorDataProxy) -> HRESULT,
    LaunchDccw: unsafe fn(this: *mut IColorDataProxy, hwnd: HWND) -> HRESULT,
}

#[allow(non_snake_case)]
impl IColorDataProxy {
    pub unsafe fn QueryInterface(&self, riid: REFIID, ppv: *mut *mut c_void) -> HRESULT {
        ((*self.lpVtbl).QueryInterface)(self as *const _ as *mut _, riid, ppv)
    }

    pub unsafe fn Addref(&self) -> ULONG {
        ((*self.lpVtbl).Addref)(self as *const _ as *mut _)
    }

    pub unsafe fn Release(&self) -> ULONG {
        ((*self.lpVtbl).Release)(self as *const _ as *mut _)
    }

    pub unsafe fn method1(&self) -> HRESULT {
        ((*self.lpVtbl).method1)(self as *const _ as *mut _)
    }

    pub unsafe fn method2(&self) -> HRESULT {
        ((*self.lpVtbl).method2)(self as *const _ as *mut _)
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

    pub unsafe fn LaunchDccw(&self, hwnd: HWND) -> HRESULT {
        ((*self.lpVtbl).LaunchDccw)(self as *const _ as *mut _, hwnd)
    }
}
