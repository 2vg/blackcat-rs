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
            let _ = DLL_PROCESS_ATTACH;
            true as _
        },
        _ => { true as _ }
    }
}
