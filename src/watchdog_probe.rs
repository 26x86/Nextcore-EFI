//! Authored watchdog ownership proof, excluded from default firmware builds.
#![no_std]
#![no_main]
extern crate alloc;
mod watchdog;
use core::time::Duration;
use uefi::{boot, entry, proto::console::serial::Serial, Status};
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;
fn report(message: &str) {
    if let Ok(handle) = boot::get_handle_for_protocol::<Serial>() {
        if let Ok(mut serial) = boot::open_protocol_exclusive::<Serial>(handle) {
            let _ = serial.write_exact(message.as_bytes());
            let _ = serial.write_exact(b"\r\n");
        }
    }
}
#[entry]
fn efi_main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::NOT_READY;
    }
    let mut calls = 0;
    let injected = watchdog::disable_with(|seconds, code| {
        calls += 1;
        if seconds != 0 || code != 0x10000 {
            return Err(Status::INVALID_PARAMETER);
        }
        Err(Status::DEVICE_ERROR)
    });
    if injected != Err(Status::DEVICE_ERROR) || calls != 1 {
        return Status::ABORTED;
    }
    report("NXWATCHDOG: FAILURE_PRESERVED status=DEVICE_ERROR");
    if let Err(error) = boot::set_watchdog_timer(2, 0x10000, None) {
        return error.status();
    }
    report("NXWATCHDOG: ARMED seconds=2");
    if cfg!(feature = "watchdog-probe-armed") {
        report("NXWATCHDOG: CONTROL_ARMED");
    } else {
        if let Err(status) = watchdog::disable() {
            return status;
        }
        report("NXWATCHDOG: DISABLED");
    }
    report("NXWATCHDOG: STALL seconds=3");
    boot::stall(Duration::from_secs(3));
    report("NXWATCHDOG: SURVIVED");
    Status::SUCCESS
}
