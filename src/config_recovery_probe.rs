//! Authored protocol fault wrapper around the actual production BOOTX64 image.
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;
use alloc::{format, vec::Vec};
use core::{
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};
use uefi::proto::{
    console::serial::Serial,
    device_path::{
        build::{media::FilePath, DevicePathBuilder},
        DevicePath,
    },
    loaded_image::LoadedImage,
    media::fs::SimpleFileSystem,
    BootPolicy,
};
use uefi::{boot, cstr16, entry, table, Status};
use uefi_raw::protocol::{
    console::{InputKey, SimpleTextInputProtocol, SimpleTextOutputProtocol},
    file_system::{FileAttribute, FileMode, FileProtocolV1, SimpleFileSystemProtocol},
};
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;
#[used]
static mut CASE_MARKER: [u8; 17] = *b"NXCONFIG_CASE=00!";
static CASE: AtomicUsize = AtomicUsize::new(0);
static OPENS: AtomicUsize = AtomicUsize::new(0);
static FAILS: AtomicUsize = AtomicUsize::new(0);
type Volume =
    unsafe extern "efiapi" fn(*mut SimpleFileSystemProtocol, *mut *mut FileProtocolV1) -> Status;
type Open = unsafe extern "efiapi" fn(
    *mut FileProtocolV1,
    *mut *mut FileProtocolV1,
    *const u16,
    FileMode,
    FileAttribute,
) -> Status;
type Output = unsafe extern "efiapi" fn(*mut SimpleTextOutputProtocol, *const u16) -> Status;
static mut VOLUME: Option<Volume> = None;
static mut OPEN: Option<Open> = None;
static mut OUTPUT: Option<Output> = None;
fn report(s: &str) {
    if let Ok(h) = boot::get_handle_for_protocol::<Serial>() {
        if let Ok(mut serial) = boot::open_protocol_exclusive::<Serial>(h) {
            let _ = serial.write_exact(s.as_bytes());
            let _ = serial.write_exact(b"\r\n");
        }
    }
}
unsafe extern "efiapi" fn open(
    this: *mut FileProtocolV1,
    result: *mut *mut FileProtocolV1,
    name: *const u16,
    mode: FileMode,
    attr: FileAttribute,
) -> Status {
    // SAFETY: Synchronous firmware File.Open arguments remain live. Compare only
    // the bounded constant path, and forward every other access unmodified.
    let config = unsafe {
        !name.is_null()
            && cstr16!("\\EFI\\OC\\config.plist")
                .to_u16_slice_with_nul()
                .iter()
                .enumerate()
                .all(|(i, v)| name.add(i).read() == *v)
    };
    if config {
        let attempt = OPENS.fetch_add(1, Ordering::SeqCst) + 1;
        report(&format!(
            "NXCONFIG: CONFIG_OPEN attempt={attempt} mode={mode:?} attr={attr:?}"
        ));
        if matches!(CASE.load(Ordering::SeqCst), 1 | 9) && attempt == 1 {
            FAILS.fetch_add(1, Ordering::SeqCst);
            if !result.is_null() {
                unsafe {
                    result.write(ptr::null_mut());
                }
            }
            return Status::NOT_FOUND;
        }
    }
    unsafe { OPEN.unwrap()(this, result, name, mode, attr) }
}
unsafe extern "efiapi" fn volume(
    this: *mut SimpleFileSystemProtocol,
    result: *mut *mut FileProtocolV1,
) -> Status {
    // SAFETY: Delegate real volume creation. Only the fresh root's Open callback
    // changes; its firmware Close owns destruction. No root pointer is retained.
    let status = unsafe { VOLUME.unwrap()(this, result) };
    if status == Status::SUCCESS && !result.is_null() && unsafe { !(*result).is_null() } {
        unsafe {
            OPEN = Some((**result).open);
            (**result).open = open;
        }
    }
    status
}
unsafe extern "efiapi" fn output(_: *mut SimpleTextOutputProtocol, _: *const u16) -> Status {
    FAILS.fetch_add(1, Ordering::SeqCst);
    Status::DEVICE_ERROR
}
unsafe extern "efiapi" fn clear(_: *mut SimpleTextOutputProtocol) -> Status {
    FAILS.fetch_add(1, Ordering::SeqCst);
    Status::DEVICE_ERROR
}
unsafe extern "efiapi" fn key(_: *mut SimpleTextInputProtocol, _: *mut InputKey) -> Status {
    FAILS.fetch_add(1, Ordering::SeqCst);
    Status::DEVICE_ERROR
}
fn run() -> Result<Status, Status> {
    let case = unsafe {
        let p = ptr::addr_of!(CASE_MARKER).cast::<u8>();
        usize::from(p.add(14).read() - b'0') * 10 + usize::from(p.add(15).read() - b'0')
    };
    CASE.store(case, Ordering::SeqCst);
    let loaded = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|e| e.status())?;
    let device = loaded.device().ok_or(Status::NOT_FOUND)?;
    drop(loaded);
    let source = boot::open_protocol_exclusive::<DevicePath>(device).map_err(|e| e.status())?;
    let mut storage = Vec::new();
    let mut builder = DevicePathBuilder::with_vec(&mut storage);
    for node in source.node_iter() {
        builder = builder.push(&node).map_err(|_| Status::OUT_OF_RESOURCES)?;
    }
    let path = builder
        .push(&FilePath {
            path_name: cstr16!("\\EFI\\NEXTCORE\\BASELINE.EFI"),
        })
        .map_err(|_| Status::OUT_OF_RESOURCES)?
        .finalize()
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    drop(source);
    let child = boot::load_image(
        boot::image_handle(),
        boot::LoadImageSource::FromDevicePath {
            device_path: path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )
    .map_err(|e| e.status())?;
    let mut fs =
        boot::open_protocol_exclusive::<SimpleFileSystem>(device).map_err(|e| e.status())?;
    let fs_ptr = (&mut *fs as *mut SimpleFileSystem).cast::<SimpleFileSystemProtocol>();
    drop(fs);
    report(&format!("NXCONFIG: BEGIN case={case}"));
    // SAFETY: Authored single application, no concurrent firmware callbacks or
    // retained protocol references. Hooks exist only across synchronous StartImage.
    // All protocol fields are restored before returning, including error results.
    let status = unsafe {
        let st = table::system_table_raw().ok_or(Status::NOT_READY)?.as_ptr();
        let out = (*st).stdout;
        let input = (*st).stdin;
        let old_volume = (*fs_ptr).open_volume;
        let old_output = (*out).output_string;
        let old_clear = (*out).clear_screen;
        let old_key = (*input).read_key_stroke;
        let old_event = (*input).wait_for_key;
        VOLUME = Some(old_volume);
        OUTPUT = Some(old_output);
        (*fs_ptr).open_volume = volume;
        if case == 6 {
            (*out).output_string = output;
        }
        if case == 9 {
            (*out).clear_screen = clear;
        }
        if case == 7 {
            (*input).read_key_stroke = key;
        }
        if case == 8 {
            (*input).wait_for_key = ptr::null_mut();
        }
        let status = boot::start_image(child).map_or_else(|e| e.status(), |_| Status::SUCCESS);
        (*fs_ptr).open_volume = old_volume;
        (*out).output_string = old_output;
        (*out).clear_screen = old_clear;
        (*input).read_key_stroke = old_key;
        (*input).wait_for_key = old_event;
        VOLUME = None;
        OPEN = None;
        OUTPUT = None;
        status
    };
    report(&format!(
        "NXCONFIG: RETURN case={case} status={status:?} opens={} injected={}",
        OPENS.load(Ordering::SeqCst),
        FAILS.load(Ordering::SeqCst)
    ));
    Ok(status)
}
#[entry]
fn efi_main() -> Status {
    if let Err(e) = uefi::helpers::init() {
        return e.status();
    }
    match run() {
        Ok(s) => s,
        Err(s) => {
            report(&format!("NXCONFIG: SETUP_ERROR status={s:?}"));
            s
        }
    }
}
