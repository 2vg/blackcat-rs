use winapi::shared::guiddef::GUID;

pub const T_DISPLAY_CALIBRATION: &'static str =
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration";

pub const T_ELEVATION_MONIKER_ADMIN: &'static str = "Elevation:Administrator!new:";
pub const T_CALIBRATOR_VALUE: &'static str = "DisplayCalibrator";

pub const T_CLSID_CMSTPLUA: &'static str = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";
#[allow(non_upper_case_globals)]
pub const T_CLSID_ColorDataProxy: &'static str = "{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}";
#[allow(non_upper_case_globals)]
pub const T_CLSID_FileOperation: &'static str = "{3AD05575-8857-4850-9277-11B85BDB8E09}";

#[allow(non_upper_case_globals)]
pub const IID_ICMLuaUtil: &'static GUID = &GUID {
    Data1: 0x6EDD6D74,
    Data2: 0xC007,
    Data3: 0x4E75,
    Data4: [0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C],
};
#[allow(non_upper_case_globals)]
pub const IID_IColorDataProxy: &'static GUID = &GUID {
    Data1: 0x0A16D195,
    Data2: 0x6F47,
    Data3: 0x4964,
    Data4: [0x92, 0x87, 0x9F, 0x4B, 0xAB, 0x6D, 0x98, 0x27],
};
#[allow(non_upper_case_globals)]
pub const IID_IFileOperation: &'static GUID = &GUID {
    Data1: 0x947AAB5F,
    Data2: 0x0A5C,
    Data3: 0x4C13,
    Data4: [0xB4, 0xD6, 0x4B, 0xF7, 0x83, 0x6F, 0xC9, 0xF8],
};
#[allow(non_upper_case_globals)]
pub const IID_IShellItem: &'static GUID = &GUID {
    Data1: 0x43826D1E,
    Data2: 0xE718,
    Data3: 0x42EE,
    Data4: [0xBC, 0x55, 0xA1, 0xE2, 0x61, 0xC3, 0x7B, 0xFE],
};

pub const FOFX_SHOWELEVATIONPROMPT: u32 = 0x00040000;
pub const FOFX_NOCOPYHOOKS: u32 = 0x00800000;
pub const FOFX_REQUIREELEVATION: u32 = 0x10000000;

#[allow(non_upper_case_globals)]
pub static mut IFileOperationFlags: u32 = 0x0;
