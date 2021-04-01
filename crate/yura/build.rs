fn main() {
    windows::build!(
        Windows::Win32::SystemServices::PWSTR,
        Windows::Win32::WindowsAndMessaging::HWND,
        Windows::Win32::Com::BIND_OPTS3,
        Windows::Win32::Com::CoGetObject
    );
}
