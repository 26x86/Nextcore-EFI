//! The loaded EFI application owns its wait/runtime watchdog policy.
use uefi::{boot, Status};

/// Disable the firmware timer while boot services are active. No retries or
/// alternate firmware calls: unsupported firmware returns its exact status.
pub fn disable() -> Result<(), Status> {
    disable_with(|seconds, code| {
        boot::set_watchdog_timer(seconds, code, None).map_err(|e| e.status())
    })
}

/// Shared production call boundary, also exercised by the authored EFI probe.
pub(crate) fn disable_with(
    mut set_timer: impl FnMut(usize, u64) -> Result<(), Status>,
) -> Result<(), Status> {
    set_timer(0, 0x10000)
}
