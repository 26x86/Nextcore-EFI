//! AArch64 EFI staging entry; executable transition is an explicit test feature.
#![no_std]
#![no_main]
extern crate alloc;
mod arm_pages;
#[cfg(all(target_arch = "aarch64", feature = "arm-kernel-probe"))]
mod arm_transition;
mod firmware_io;

use alloc::format;
use arm_pages::ArmPages;
use firmware_io::{read_file, report};
use nextcore_core::{
    boot_config::{parse_arm64_kernel_target, KernelProfile},
    kc_staging::KcStagingPlan,
    kernel_collection::MAX_INPUT_SIZE,
};
use uefi::{cstr16, entry, CString16, Status};

#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

#[entry]
fn efi_main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::NOT_READY;
    }
    report("NXARM: EFI_ENTRY");
    if !cfg!(target_arch = "aarch64") {
        report("NXARM: UNSUPPORTED_ARCHITECTURE");
        return Status::UNSUPPORTED;
    }
    match run() {
        Ok(()) => Status::SUCCESS,
        Err(status) => {
            report(&format!("NXARM: ERROR status={status:?}"));
            status
        }
    }
}

fn run() -> Result<(), Status> {
    let config = read_file(cstr16!("\\EFI\\OC\\config.plist"), 1024 * 1024)?;
    let target = parse_arm64_kernel_target(&config).map_err(|error| {
        report(&format!("NXARM: CONFIG_INVALID reason={error}"));
        Status::INVALID_PARAMETER
    })?;
    report("NXARM: CONFIG_PARSED");
    let path = CString16::try_from(target.path.as_str()).map_err(|_| Status::INVALID_PARAMETER)?;
    let source = read_file(&path, MAX_INPUT_SIZE as u64)?;
    let stage = KcStagingPlan::new_arm64(&source).map_err(|error| {
        report(&format!("NXARM: KC_INVALID reason={error}"));
        Status::LOAD_ERROR
    })?;
    report(&format!(
        "NXARM: KC_VALIDATED subtype={:#x} arena={}",
        stage.inspection().collection.cpu_subtype,
        stage.arena_size()
    ));
    #[cfg(all(target_arch = "aarch64", feature = "arm-kernel-probe"))]
    if target.profile == KernelProfile::QemuVirtArm64Probe {
        const MARKER: &[u8] = b"NEXTCORE_AUTHORED_ARM64_HANDOFF_V1";
        // Marker selects our fixture, never authentication. ARM64E is rejected
        // here so ordinary ARM64 execution cannot be reported as PAC evidence.
        if stage.inspection().collection.cpu_subtype != 0
            || source
                .windows(MARKER.len())
                .filter(|window| *window == MARKER)
                .count()
                != 1
        {
            report("NXARM: FIXTURE_REJECTED");
            return Err(Status::UNSUPPORTED);
        }
        drop(stage);
        return run_probe(&source, &target.arguments);
    }
    // The production path can stage real ARM64E metadata with its original
    // subtype and opaque fixups, but needs actual platform and trust providers.
    let _profile = target.profile == KernelProfile::XnuArm64Uefi;
    let mut pages = ArmPages::allocate_data(stage.arena_size())?;
    let verification = stage
        .stage_into(pages.bytes_mut())
        .map_err(|_| Status::COMPROMISED_DATA)?;
    report(&format!(
        "NXARM: STAGING_VERIFIED bytes={} copied={} zero_tail={} holes={}",
        verification.arena_bytes,
        verification.copied_bytes,
        verification.zero_tail_bytes,
        verification.hole_bytes
    ));
    report("NXARM: PROVIDERS_PENDING xnu_executed=false macos_boot_verified=false metal_verified=false");
    Err(Status::NOT_READY)
}

#[cfg(all(target_arch = "aarch64", feature = "arm-kernel-probe"))]
fn run_probe(source: &[u8], arguments: &str) -> Result<(), Status> {
    use alloc::{string::String, vec};
    use core::mem::ManuallyDrop;
    use nextcore_core::{
        flat_dt::{self, FlatNode, FlatProperty},
        xnu_arm64_boot_args::Arm64BootVideo,
        xnu_arm64_handoff::{Arm64HandoffPlan, Arm64PlacementInput},
    };
    use uefi::{boot, mem::memory_map::MemoryType};
    const RAM_BASE: u64 = 0x4000_0000;
    const RAM_SIZE: u64 = 0x2000_0000;
    const KERNEL_BASE: u64 = 0x4200_0000;
    const VIRTUAL_BASE: u64 = 0xffff_fe00_0000_0000;
    let mut boot_line = arguments.as_bytes().to_vec();
    boot_line.push(0);
    let tree = FlatNode {
        name: String::new(),
        properties: vec![],
        children: vec![FlatNode {
            name: String::from("chosen"),
            properties: vec![
                FlatProperty {
                    name: String::from("dram-base"),
                    value: RAM_BASE.to_le_bytes().to_vec(),
                },
                FlatProperty {
                    name: String::from("dram-size"),
                    value: RAM_SIZE.to_le_bytes().to_vec(),
                },
                FlatProperty {
                    name: String::from("boot-args"),
                    value: boot_line,
                },
            ],
            children: vec![],
        }],
    };
    let dt = flat_dt::encode(&tree).map_err(|_| Status::INVALID_PARAMETER)?;
    let plan = Arm64HandoffPlan::new(
        source,
        Arm64PlacementInput {
            physical_base: RAM_BASE,
            virtual_base: VIRTUAL_BASE,
            memory_size: RAM_SIZE,
            actual_memory_size: RAM_SIZE,
            kernel_phys: KERNEL_BASE,
            device_tree: &dt,
            command_line: arguments,
            machine_type: 0,
            boot_flags: 0,
            video: Arm64BootVideo::default(),
        },
    )
    .map_err(|error| {
        report(&format!("NXARM: PLACEMENT_INVALID reason={error}"));
        Status::LOAD_ERROR
    })?;
    let layout = *plan.layout();
    let mut pages = ArmPages::allocate(layout.allocation_bytes, Some(layout.kernel_phys))?;
    let verification = plan
        .stage_into(pages.bytes_mut())
        .map_err(|_| Status::COMPROMISED_DATA)?;
    report(&format!(
        "NXARM: STAGING_VERIFIED bytes={} copied={} zero_tail={} holes={}",
        verification.arena_bytes,
        verification.copied_bytes,
        verification.zero_tail_bytes,
        verification.hole_bytes
    ));
    arm_transition::preflight(pages.base(), pages.bytes()).map_err(|status| {
        report("NXARM: CPU_PREFLIGHT_REJECTED");
        status
    })?;
    report("NXARM: PROBE_ONLY");
    report(&format!(
        "NXARM: HANDOFF_READY args={:#x} entry={:#x} stack={:#x}",
        layout.boot_args_phys, layout.entry_phys, layout.stack_top_phys
    ));
    drop(plan);
    drop(dt);
    drop(tree);
    let preview = boot::memory_map(MemoryType::LOADER_DATA).map_err(|e| e.status())?;
    pages.validate_map(&preview)?;
    drop(preview);
    report("NXARM: EXIT_BOOT_SERVICES");
    let pages = ManuallyDrop::new(pages);
    // No firmware operation, allocation or destructor is permitted after EBS.
    // Retain the final map and all caller-owned source buffers by never returning.
    let final_map = unsafe { boot::exit_boot_services(None) };
    if pages.validate_map(&final_map).is_err() {
        arm_transition::halt();
    }
    unsafe {
        arm_transition::enter(
            layout.boot_args_phys,
            layout.entry_phys,
            layout.stack_top_phys,
        )
    }
}
