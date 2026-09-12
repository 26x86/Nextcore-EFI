//! Authored OVMF fault injection; never part of BOOTX64 or a normal bundle.
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;
mod picker;
use alloc::{format, string::String};
use core::sync::atomic::{AtomicUsize, Ordering};
use nextcore_core::boot_config::{BootMenuEntry, BootTarget};
use uefi::proto::console::{gop::GraphicsOutput, serial::Serial};
use uefi::{boot, entry, table, Status};
use uefi_raw::protocol::console::{
    GraphicsOutputBltOperation, GraphicsOutputBltPixel, GraphicsOutputProtocol, InputKey,
    SimpleTextInputProtocol, SimpleTextOutputProtocol,
};

#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;
static CASE: AtomicUsize = AtomicUsize::new(0);
static KEYS: AtomicUsize = AtomicUsize::new(0);
static INJECTED: AtomicUsize = AtomicUsize::new(0);
static GOP_FAILURES: AtomicUsize = AtomicUsize::new(0);
static GOP_DRAWS: AtomicUsize = AtomicUsize::new(0);
static WIDTH: AtomicUsize = AtomicUsize::new(0);
static HEIGHT: AtomicUsize = AtomicUsize::new(0);
static WRITES: AtomicUsize = AtomicUsize::new(0);
type OutputFn = unsafe extern "efiapi" fn(*mut SimpleTextOutputProtocol, *const u16) -> Status;
type BltFn = unsafe extern "efiapi" fn(
    *mut GraphicsOutputProtocol,
    *mut GraphicsOutputBltPixel,
    GraphicsOutputBltOperation,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> Status;
static mut OUTPUT: Option<OutputFn> = None;
static mut BLT: Option<BltFn> = None;

fn report(text: &str) {
    if let Ok(handle) = boot::get_handle_for_protocol::<Serial>() {
        if let Ok(mut serial) = boot::open_protocol_exclusive::<Serial>(handle) {
            let _ = serial.write_exact(text.as_bytes());
            let _ = serial.write_exact(b"\r\n");
        }
    }
}

unsafe extern "efiapi" fn color(_: *mut SimpleTextOutputProtocol, _: usize) -> Status {
    INJECTED.fetch_add(1, Ordering::SeqCst);
    Status::UNSUPPORTED
}
unsafe extern "efiapi" fn clear(_: *mut SimpleTextOutputProtocol) -> Status {
    INJECTED.fetch_add(1, Ordering::SeqCst);
    Status::DEVICE_ERROR
}
unsafe extern "efiapi" fn output(this: *mut SimpleTextOutputProtocol, text: *const u16) -> Status {
    WRITES.fetch_add(1, Ordering::SeqCst);
    if CASE.load(Ordering::SeqCst) == 4 || KEYS.load(Ordering::SeqCst) != 0 {
        INJECTED.fetch_add(1, Ordering::SeqCst);
        return Status::DEVICE_ERROR;
    }
    // SAFETY: Installed only during synchronous picker execution. The original
    // firmware callback and the caller's UTF-16 input remain live and unchanged.
    unsafe { OUTPUT.unwrap()(this, text) }
}
unsafe extern "efiapi" fn key(_: *mut SimpleTextInputProtocol, key: *mut InputKey) -> Status {
    if key.is_null() {
        return Status::INVALID_PARAMETER;
    }
    KEYS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: SimpleTextInput caller supplies storage for exactly one InputKey.
    unsafe {
        key.write(InputKey {
            scan_code: 0,
            unicode_char: 13,
        });
    }
    Status::SUCCESS
}
unsafe extern "efiapi" fn blt(
    this: *mut GraphicsOutputProtocol,
    buffer: *mut GraphicsOutputBltPixel,
    operation: GraphicsOutputBltOperation,
    source_x: usize,
    source_y: usize,
    dest_x: usize,
    dest_y: usize,
    width: usize,
    height: usize,
    delta: usize,
) -> Status {
    if CASE.load(Ordering::SeqCst) == 5 {
        let full_frame = operation == GraphicsOutputBltOperation::BLT_BUFFER_TO_VIDEO
            && (source_x, source_y, dest_x, dest_y) == (0, 0, 0, 0)
            && width == WIDTH.load(Ordering::SeqCst)
            && height == HEIGHT.load(Ordering::SeqCst);
        if !full_frame || KEYS.load(Ordering::SeqCst) == 0 {
            // SAFETY: Forward the original live callback's exact arguments.
            // No protocol borrow is retained across the call or mode mutation.
            let status = unsafe {
                BLT.unwrap()(
                    this, buffer, operation, source_x, source_y, dest_x, dest_y, width, height,
                    delta,
                )
            };
            if full_frame && status == Status::SUCCESS {
                GOP_DRAWS.fetch_add(1, Ordering::SeqCst);
            }
            return status;
        }
        INJECTED.fetch_add(1, Ordering::SeqCst);
    }
    GOP_FAILURES.fetch_add(1, Ordering::SeqCst);
    // SAFETY: This is the live located GOP, installed below without a retained
    // Rust protocol borrow. Restore immediately so firmware text can use GOP.
    unsafe {
        (*this).blt = BLT.unwrap();
    }
    Status::DEVICE_ERROR
}

fn run_case(case: usize) -> Result<(), Status> {
    let entries = [BootMenuEntry {
        name: String::from("Authored child"),
        target: BootTarget {
            path: String::from("\\EFI\\NEXTCORE\\NXTEST.EFI"),
            arguments: String::new(),
            apfs_volume: None,
        },
    }];
    let gop_handle = boot::get_handle_for_protocol::<GraphicsOutput>().map_err(|e| e.status())?;
    let mut gop =
        boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle).map_err(|e| e.status())?;
    let (width, height) = gop.current_mode_info().resolution();
    WIDTH.store(width, Ordering::SeqCst);
    HEIGHT.store(height, Ordering::SeqCst);
    // SAFETY: GraphicsOutput is repr(transparent) over the raw UEFI protocol.
    // Save its address then drop the exclusive borrow before picker acquires it.
    let gop_ptr = (&mut *gop as *mut GraphicsOutput).cast::<GraphicsOutputProtocol>();
    drop(gop);
    // SAFETY: No notification callback or context, live boot services.
    let event =
        unsafe { boot::create_event(boot::EventType::empty(), boot::Tpl::APPLICATION, None, None) }
            .map_err(|e| e.status())?;
    boot::signal_event(&event).map_err(|e| e.status())?;
    CASE.store(case, Ordering::SeqCst);
    for counter in [&KEYS, &INJECTED, &GOP_FAILURES, &GOP_DRAWS, &WRITES] {
        counter.store(0, Ordering::SeqCst);
    }
    report(&format!("NXPICKER: CASE_BEGIN id={case}"));
    // SAFETY: This probe owns the synchronous application execution at TPL
    // APPLICATION, before ExitBootServices. Pointers come from the live system
    // table and located GOP. Only callback fields are replaced, no mode storage
    // is copied or freed. No protocol references survive installation. All
    // callbacks are restored before closing the synthetic event or loading a
    // child, including the expected picker error path. Hooks never allocate,
    // unwind, or call the picker recursively. Atomics track callback observations.
    let result = unsafe {
        let st = table::system_table_raw().ok_or(Status::NOT_READY)?.as_ptr();
        let out = (*st).stdout;
        let input = (*st).stdin;
        let old_color = (*out).set_attribute;
        let old_clear = (*out).clear_screen;
        let old_output = (*out).output_string;
        let old_key = (*input).read_key_stroke;
        let old_event = (*input).wait_for_key;
        let old_blt = (*gop_ptr).blt;
        OUTPUT = Some(old_output);
        BLT = Some(old_blt);
        (*gop_ptr).blt = blt;
        if case == 1 {
            (*out).set_attribute = color;
        }
        if case == 2 {
            (*out).clear_screen = clear;
        }
        if case == 3 || case == 4 {
            (*out).output_string = output;
        }
        (*input).read_key_stroke = key;
        (*input).wait_for_key = event.as_ptr();
        let result = picker::choose(&entries, report);
        (*out).set_attribute = old_color;
        (*out).clear_screen = old_clear;
        (*out).output_string = old_output;
        (*input).read_key_stroke = old_key;
        (*input).wait_for_key = old_event;
        (*gop_ptr).blt = old_blt;
        OUTPUT = None;
        BLT = None;
        result
    };
    boot::close_event(event).map_err(|e| e.status())?;
    let keys = KEYS.load(Ordering::SeqCst);
    let injected = INJECTED.load(Ordering::SeqCst);
    let gop = GOP_FAILURES.load(Ordering::SeqCst);
    let full_draws = GOP_DRAWS.load(Ordering::SeqCst);
    let writes = WRITES.load(Ordering::SeqCst);
    let expected = if case == 4 {
        result == Err(Status::DEVICE_ERROR) && keys == 0 && writes > 0
    } else {
        result == Ok(Some(0)) && keys == 1
    };
    let mut child = false;
    if expected && case != 4 {
        let bytes = include_bytes!(env!("NEXTCORE_PICKER_CHILD"));
        let image = boot::load_image(
            boot::image_handle(),
            boot::LoadImageSource::FromBuffer {
                buffer: bytes,
                file_path: None,
            },
        )
        .map_err(|e| e.status())?;
        child = boot::start_image(image).is_ok();
    }
    let passed = expected
        && injected > 0
        && gop == 1
        && (child == (case != 4))
        && full_draws == usize::from(case == 5);
    report(&format!("NXPICKER: CASE id={case} injected={injected} gop={gop} keys={keys} writes={writes} child={child} passed={passed} full_draws={full_draws}"));
    if passed {
        Ok(())
    } else {
        Err(Status::ABORTED)
    }
}

#[entry]
fn efi_main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }
    for case in 1..=5 {
        if let Err(status) = run_case(case) {
            report(&format!("NXPICKER: FAIL case={case} status={status:?}"));
            return status;
        }
    }
    report("NXPICKER: PASS cases=5 physical_boot_verified=false");
    Status::SUCCESS
}
