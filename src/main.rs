#![no_std]
#![no_main]

extern crate alloc;
mod configuration_recovery;
mod watchdog;

mod exit_data;
mod linux_handoff;
mod picker;
// Shared adapters also expose diagnostic NXAPFS entry points unused by BOOTX64.
#[cfg(feature = "apfs-jumpstart")]
#[allow(dead_code)]
mod apfs_driver;
#[cfg(feature = "apfs-jumpstart")]
#[allow(dead_code)]
mod apfs_filesystems;
#[cfg(feature = "apfs-jumpstart")]
#[allow(dead_code)]
mod apfs_observation;
#[cfg(feature = "apfs-jumpstart")]
mod apfs_target;
#[cfg(feature = "console-control")]
mod console_control;

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt::Write;
use nextcore_core::boot_config::{parse_boot_menu, BootTarget};
use uefi::boot::LoadImageSource;
use uefi::mem::memory_map::MemoryType;
use uefi::prelude::*;
use uefi::proto::console::serial::Serial;
use uefi::proto::device_path::{
    build::{media::FilePath, DevicePathBuilder},
    media, DevicePath,
};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::BootPolicy;
use uefi::{boot, CString16};

// A corrupt size field must not consume the firmware's available memory.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

#[entry]
fn efi_main() -> Status {
    uefi::helpers::init().expect("failed to initialize UEFI services");

    match watchdog::disable() {
        Ok(()) => report("NEXTCORE: WATCHDOG_DISABLED"),
        Err(status) => report(&format!(
            "NEXTCORE: WATCHDOG_DISABLE_FAILED status={status:?}"
        )),
    }
    report("NextCore");
    report("NEXTCORE: EFI_ENTRY");
    loop {
        let (status, reason) = match read_config() {
            Ok(bytes) => {
                report(&format!("NEXTCORE: CONFIG_READ bytes={}", bytes.len()));
                match parse_boot_menu(&bytes) {
                    Ok(menu) if !menu.entries.is_empty() => {
                        report("NEXTCORE: CONFIG_PARSED");
                        if !menu.show_picker {
                            return chainload(menu.entries[0].target.clone());
                        }
                        loop {
                            let index = match picker::choose(&menu.entries, report) {
                                Ok(Some(index)) => index,
                                Ok(None) => return Status::ABORTED,
                                Err(status) => {
                                    report(&format!("NEXTCORE: PICKER_ERROR status={status:?}"));
                                    return status;
                                }
                            };
                            let status = chainload(menu.entries[index].target.clone());
                            if !status.is_error() {
                                return status;
                            }
                            report(&format!(
                                "NEXTCORE: BOOT_FAILED index={index} status={status:?}"
                            ));
                            report("Boot failed. Press any key to return to the boot menu.");
                            if let Err(error) = acknowledge_failure() {
                                report(&format!("NEXTCORE: RECOVERY_INPUT_ERROR status={error:?}"));
                                return error;
                            }
                            report("NEXTCORE: PICKER_RETRY");
                        }
                    }
                    Ok(_) => {
                        report("No enabled boot entries");
                        report("NEXTCORE: NO_BOOT_TARGET");
                        (Status::NOT_FOUND, String::from("No enabled boot entries"))
                    }
                    Err(error) => {
                        report(&format!("NEXTCORE: CONFIG_INVALID reason={error}"));
                        (
                            Status::INVALID_PARAMETER,
                            format!("Invalid configuration: {error}"),
                        )
                    }
                }
            }
            Err((status, reason)) => {
                report(&format!("NEXTCORE: CONFIG_ERROR status={status:?}"));
                (status, format!("{reason}: {status:?}"))
            }
        };
        match configuration_recovery::choose(&reason, report) {
            Ok(configuration_recovery::Action::Retry) => continue,
            Ok(configuration_recovery::Action::Exit) => return status,
            Err(error) => {
                report(&format!("NEXTCORE: CONFIG_RECOVERY_ERROR status={error:?}"));
                return error;
            }
        }
    }
}

fn chainload(target: BootTarget) -> Status {
    let status = match load_target(&target) {
        Ok(child) => {
            // The UTF-16 buffer remains owned by the parent until StartImage
            // returns. Drop all protocol guards before transferring control.
            let mut options: Vec<u16> = target.arguments.encode_utf16().collect();
            if !options.is_empty() {
                options.push(0);
            }
            let configured = (|| {
                let mut image =
                    boot::open_protocol_exclusive::<LoadedImage>(child).map_err(|e| e.status())?;
                // UEFI SCT Loaded Image 5.3.1.1.7 defines application types.
                // Resident EFI drivers have different lifetime semantics.
                if image.code_type() != MemoryType::LOADER_CODE
                    || image.data_type() != MemoryType::LOADER_DATA
                {
                    report("NEXTCORE: TARGET_REJECTED reason=NOT_APPLICATION");
                    return Err(Status::UNSUPPORTED);
                }
                let pointer = if options.is_empty() {
                    core::ptr::null()
                } else {
                    options.as_ptr().cast()
                };
                // SAFETY: size is bytes; parser bounds it to at most 8194.
                // The allocation is not modified or freed while child runs.
                unsafe {
                    image.set_load_options(pointer, (options.len() * 2) as u32);
                }
                Ok::<(), Status>(())
            })();
            if let Err(status) = configured {
                let _ = boot::unload_image(child);
                report(&format!("NEXTCORE: IMAGE_OPTIONS_ERROR status={status:?}"));
                return status;
            }
            #[cfg(feature = "console-control")]
            let console = match console_control::Lease::acquire(report) {
                Ok(lease) => lease,
                Err(status) => {
                    let _ = boot::unload_image(child);
                    report(&format!("NEXTCORE: CONSOLE_ERROR status={status:?}"));
                    return status;
                }
            };
            report("NEXTCORE: IMAGE_START");
            let status = exit_data::start_image(child, report);
            #[cfg(feature = "console-control")]
            console.release();
            // Application return/Exit unloads it. StartImage can also fail
            // before entry, leaving a loaded image that needs cleanup.
            match boot::open_protocol_exclusive::<LoadedImage>(child) {
                Ok(mut image) => {
                    // SAFETY: the image is no longer executing; drop guard
                    // before unload, and remove its borrowed pointer first.
                    unsafe {
                        image.set_load_options(core::ptr::null(), 0);
                    }
                    drop(image);
                    if let Err(error) = boot::unload_image(child) {
                        report(&format!(
                            "NEXTCORE: IMAGE_CLEANUP_ERROR status={:?}",
                            error.status()
                        ));
                    }
                }
                Err(error)
                    if matches!(
                        error.status(),
                        Status::UNSUPPORTED | Status::INVALID_PARAMETER
                    ) => {}
                Err(_) => {
                    if boot::unload_image(child).is_err() {
                        // Do not free memory that a surviving protocol may
                        // reference. At most 8194 bytes retained until reboot.
                        core::mem::forget(options);
                        report("NEXTCORE: IMAGE_CLEANUP_ERROR options=RETAINED");
                    }
                }
            }
            report(&format!("NEXTCORE: IMAGE_RETURN status={status:?}"));
            status
        }
        Err(status) => {
            report(&format!("NEXTCORE: IMAGE_LOAD_ERROR status={status:?}"));
            status
        }
    };
    status
}

fn load_target(target: &BootTarget) -> core::result::Result<Handle, Status> {
    if target.apfs_volume.is_some() {
        #[cfg(feature = "apfs-jumpstart")]
        { return apfs_target::load(target, report); }
        #[cfg(not(feature = "apfs-jumpstart"))]
        {
            report("NEXTCORE: APFS_TARGET_UNSUPPORTED feature=disabled");
            return Err(Status::UNSUPPORTED);
        }
    }
    let current = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|e| e.status())?;
    let device = current.device().ok_or(Status::NOT_FOUND)?;
    // File paths can be split across multiple MEDIA_FILEPATH nodes.
    let mut own_path = String::new();
    for node in current.file_path().ok_or(Status::UNSUPPORTED)?.node_iter() {
        if let Ok(path) = <&media::FilePath>::try_from(node) {
            own_path.push_str(
                &path
                    .path_name()
                    .to_cstring16()
                    .map_err(|_| Status::INVALID_PARAMETER)?
                    .to_string(),
            );
        }
    }
    if own_path.is_empty() {
        return Err(Status::UNSUPPORTED);
    }
    if own_path
        .replace('/', "\\")
        .eq_ignore_ascii_case(&target.path)
    {
        report("NEXTCORE: TARGET_REJECTED reason=SELF_REFERENCE");
        return Err(Status::INVALID_PARAMETER);
    }
    drop(current);
    let path = CString16::try_from(target.path.as_str()).map_err(|_| Status::INVALID_PARAMETER)?;
    let mut storage = Vec::new();
    let source = boot::open_protocol_exclusive::<DevicePath>(device).map_err(|e| e.status())?;
    let mut builder = DevicePathBuilder::with_vec(&mut storage);
    for node in source.node_iter() {
        builder = builder.push(&node).map_err(|_| Status::OUT_OF_RESOURCES)?;
    }
    let full_path = builder
        .push(&FilePath { path_name: &path })
        .map_err(|_| Status::OUT_OF_RESOURCES)?
        .finalize()
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    drop(source);
    report("NEXTCORE: IMAGE_LOAD_BEGIN");
    boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: full_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )
    .map_err(|e| e.status())
}

fn report(message: &str) {
    // Diagnostic output must not turn an optional console failure into panic.
    uefi::system::with_stdout(|out| {
        let _ = writeln!(out, "{message}");
    });
    // Use the public Serial I/O protocol, without assuming a UART I/O address.
    if let Ok(handle) = boot::get_handle_for_protocol::<Serial>() {
        if let Ok(mut serial) = boot::open_protocol_exclusive::<Serial>(handle) {
            let _ = serial.write_exact(message.as_bytes());
            let _ = serial.write_exact(b"\r\n");
        }
    }
}

fn acknowledge_failure() -> core::result::Result<(), Status> {
    loop {
        let mut events = [uefi::system::with_stdin(|input| input.wait_for_key_event())
            .map_err(|error| error.status())?];
        boot::wait_for_event(&mut events).map_err(|error| error.status())?;
        if uefi::system::with_stdin(|input| input.read_key())
            .map_err(|error| error.status())?
            .is_some()
        {
            return Ok(());
        }
    }
}

fn read_config() -> core::result::Result<Vec<u8>, (Status, &'static str)> {
    let mut fs = boot::get_image_file_system(boot::image_handle())
        .map_err(|e| (e.status(), "Loaded image file system unavailable"))?;
    let mut root = fs
        .open_volume()
        .map_err(|e| (e.status(), "Cannot open loaded image volume"))?;
    let handle = root
        .open(
            configuration_recovery::CONFIG_PATH,
            FileMode::Read,
            FileAttribute::empty(),
        )
        .map_err(|e| (e.status(), "Cannot open configuration file"))?;
    let mut file = handle.into_regular_file().ok_or((
        Status::INVALID_PARAMETER,
        "Configuration path is not a regular file",
    ))?;
    let size = file
        .get_boxed_info::<FileInfo>()
        .map_err(|e| (e.status(), "Cannot read configuration file information"))?
        .file_size();
    if size == 0 {
        return Err((Status::BAD_BUFFER_SIZE, "Configuration file is empty"));
    }
    if size > MAX_CONFIG_BYTES {
        return Err((
            Status::BAD_BUFFER_SIZE,
            "Configuration exceeds the 1 MiB limit",
        ));
    }
    let mut bytes = vec![0; size as usize];
    let mut position = 0;
    while position < bytes.len() {
        let count = file
            .read(&mut bytes[position..])
            .map_err(|e| (e.status(), "Cannot read configuration contents"))?;
        if count == 0 {
            return Err((
                Status::END_OF_FILE,
                "Configuration ended before its reported size",
            ));
        }
        position += count;
    }
    Ok(bytes)
}
