//! Explicit recovery on the same loaded-image configuration path.
use alloc::format;
use uefi::proto::console::text::{Key, ScanCode};
use uefi::{boot, char16, cstr16, system, CStr16, CString16, Status};

pub const CONFIG_PATH: &CStr16 = cstr16!("\\EFI\\OC\\config.plist");
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Retry,
    Exit,
}

/// No filesystem, image-loading or runtime-service operations occur here.
/// Required display and input errors retain their actual firmware status.
pub fn choose(reason: &str, report: fn(&str)) -> Result<Action, Status> {
    report(&format!(
        "NEXTCORE: CONFIG_RECOVERY_BEGIN path={} reason={reason}",
        CONFIG_PATH
    ));
    let message = CString16::try_from(format!(
        "\r\nNextCore configuration recovery\r\n\r\nPath: {}\r\nReason: {reason}\r\n\r\nEnter: retry this configuration\r\nEsc: return to firmware\r\n",
        CONFIG_PATH).as_str()).map_err(|_| Status::INVALID_PARAMETER)?;
    // Clear stale firmware graphics when possible; readable text is still
    // useful when this cosmetic operation is unsupported.
    if let Err(error) = system::with_stdout(|out| out.clear()) {
        report(&format!(
            "NEXTCORE: CONFIG_RECOVERY_DISPLAY_WARNING operation=clear status={:?}",
            error.status()
        ));
    }
    system::with_stdout(|out| out.output_string(&message)).map_err(|e| e.status())?;
    report("NEXTCORE: CONFIG_RECOVERY_READY");
    loop {
        let mut events =
            [system::with_stdin(|input| input.wait_for_key_event()).map_err(|e| e.status())?];
        boot::wait_for_event(&mut events).map_err(|e| e.status())?;
        let Some(key) = system::with_stdin(|input| input.read_key()).map_err(|e| e.status())?
        else {
            continue;
        };
        match key {
            Key::Printable(ch) if ch == char16!('\r') => {
                report("NEXTCORE: CONFIG_RECOVERY_ACTION retry");
                return Ok(Action::Retry);
            }
            Key::Special(ScanCode::ESCAPE) => {
                report("NEXTCORE: CONFIG_RECOVERY_ACTION exit");
                return Ok(Action::Exit);
            }
            _ => {}
        }
    }
}
