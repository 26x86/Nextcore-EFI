//! macOS ARM guest preparation and real ARM-to-x86 JIT inside x86 UEFI.
//! The host remains in UEFI; guest physical addresses never become host PCs.
#![no_std]
#![no_main]
extern crate alloc;
mod arm_pages;
mod firmware_io;
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "arm-jit-probe", feature = "arm-jit-trace")
))]
include!(concat!(env!("OUT_DIR"), "/jit_pauth.rs"));
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
    report("NXARMJIT: EFI_ENTRY host=x86_64 guest=arm64");
    if !cfg!(target_arch = "x86_64") {
        return Status::UNSUPPORTED;
    }
    match run() {
        Ok(()) => Status::SUCCESS,
        Err(status) => {
            report(&format!("NXARMJIT: ERROR status={status:?}"));
            status
        }
    }
}
fn run() -> Result<(), Status> {
    let config = read_file(cstr16!("\\EFI\\OC\\config.plist"), 1024 * 1024)?;
    let target = parse_arm64_kernel_target(&config).map_err(|error| {
        report(&format!("NXARMJIT: CONFIG_INVALID reason={error}"));
        Status::INVALID_PARAMETER
    })?;
    report("NXARMJIT: CONFIG_PARSED");
    let path = CString16::try_from(target.path.as_str()).map_err(|_| Status::INVALID_PARAMETER)?;
    let source = read_file(&path, MAX_INPUT_SIZE as u64)?;
    let stage = KcStagingPlan::new_arm64(&source).map_err(|error| {
        report(&format!("NXARMJIT: KC_INVALID reason={error}"));
        Status::LOAD_ERROR
    })?;
    report(&format!(
        "NXARMJIT: KC_VALIDATED subtype={:#x} arena={}",
        stage.inspection().collection.cpu_subtype,
        stage.arena_size()
    ));
    #[cfg(all(target_arch = "x86_64", feature = "arm-jit-trace"))]
    if target.profile == KernelProfile::X86EfiArm64Trace {
        drop(stage);
        return run_trace(&source, &target.arguments, &config);
    }
    #[cfg(all(
        target_arch = "x86_64",
        any(feature = "arm-jit-probe", feature = "arm-jit-trace")
    ))]
    if cfg!(feature = "arm-jit-probe") && target.profile == KernelProfile::X86EfiArm64JitProbe {
        const MARKER: &[u8] = b"NEXTCORE_AUTHORED_ARM64_JIT_V1";
        const PAC_MARKER: &[u8] = b"NEXTCORE_AUTHORED_ARM64E_JIT_PAC_V1";
        let plain_count = source
            .windows(MARKER.len())
            .filter(|w| *w == MARKER)
            .count();
        let pac_count = source
            .windows(PAC_MARKER.len())
            .filter(|w| *w == PAC_MARKER)
            .count();
        let pac =
            stage.inspection().collection.cpu_subtype == 2 && pac_count == 1 && plain_count == 0;
        if !pac
            && (stage.inspection().collection.cpu_subtype != 0
                || plain_count != 1
                || pac_count != 0)
        {
            report("NXARMJIT: FIXTURE_REJECTED");
            return Err(Status::UNSUPPORTED);
        }
        drop(stage);
        return run_probe(&source, &target.arguments, pac);
    }
    let _profile = target.profile == KernelProfile::XnuArm64Uefi;
    let mut pages = ArmPages::allocate_data(stage.arena_size())?;
    let v = stage
        .stage_into(pages.bytes_mut())
        .map_err(|_| Status::COMPROMISED_DATA)?;
    report(&format!(
        "NXARMJIT: STAGING_VERIFIED bytes={} copied={} zero_tail={}",
        v.arena_bytes, v.copied_bytes, v.zero_tail_bytes
    ));
    report("NXARMJIT: PROVIDERS_PENDING xnu_executed=false macos_boot_verified=false metal_verified=false");
    Err(Status::NOT_READY)
}

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "arm-jit-probe", feature = "arm-jit-trace")
))]
#[repr(C)]
#[derive(Default)]
struct JitResult {
    status: u32,
    fault_instruction: u32,
    retired: u64,
    pc: u64,
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    compiled_blocks: u64,
}
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "arm-jit-probe", feature = "arm-jit-trace")
))]
const _: [(); 64] = [(); core::mem::size_of::<JitResult>()];

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "arm-jit-probe", feature = "arm-jit-trace")
))]
unsafe extern "C" {
    #[cfg(feature = "arm-jit-trace")]
    fn vf_boot_run_with_registers(
        ram: *mut u8,
        ram_size: usize,
        ram_base: u64,
        entry: u64,
        args: u64,
        stack: u64,
        code: *mut u8,
        code_bytes: usize,
        budget: u64,
        protect: unsafe extern "C" fn(
            *mut core::ffi::c_void,
            usize,
            i32,
            *mut core::ffi::c_void,
        ) -> i32,
        opaque: *mut core::ffi::c_void,
        initial_x0_x3: *const u64,
        pauth: unsafe extern "C" fn(*mut core::ffi::c_void, u32) -> i32,
        result: *mut JitResult,
    ) -> i32;
    fn vf_boot_run_with_pauth(
        ram: *mut u8,
        ram_size: usize,
        ram_base: u64,
        entry: u64,
        args: u64,
        stack: u64,
        code: *mut u8,
        code_bytes: usize,
        budget: u64,
        protect: unsafe extern "C" fn(
            *mut core::ffi::c_void,
            usize,
            i32,
            *mut core::ffi::c_void,
        ) -> i32,
        opaque: *mut core::ffi::c_void,
        pauth: unsafe extern "C" fn(*mut core::ffi::c_void, u32) -> i32,
        result: *mut JitResult,
    ) -> i32;
    fn vf_efi_jit_protection_open(
        table: *mut core::ffi::c_void,
        storage: *mut core::ffi::c_void,
        bytes: usize,
    ) -> i32;
    fn vf_efi_jit_protect(
        p: *mut core::ffi::c_void,
        n: usize,
        executable: i32,
        opaque: *mut core::ffi::c_void,
    ) -> i32;
}
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "arm-jit-probe", feature = "arm-jit-trace")
))]
unsafe extern "efiapi" {
    fn vf_gop_present(
        bs: *mut core::ffi::c_void,
        ram: *const u8,
        ram_bytes: u64,
        offset: u64,
        width: u32,
        height: u32,
        stride: u32,
        x: u32,
        y: u32,
    ) -> Status;
    fn vf_gop_readback(
        bs: *mut core::ffi::c_void,
        buffer: *mut u8,
        buffer_bytes: u64,
        offset: u64,
        width: u32,
        height: u32,
        stride: u32,
        x: u32,
        y: u32,
    ) -> Status;
}

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "arm-jit-probe", feature = "arm-jit-trace")
))]
fn run_probe(source: &[u8], arguments: &str, pac: bool) -> Result<(), Status> {
    use alloc::{string::String, vec};
    use nextcore_core::{
        flat_dt::{self, FlatNode, FlatProperty},
        xnu_arm64_boot_args::Arm64BootVideo,
        xnu_arm64_handoff::{Arm64HandoffPlan, Arm64PlacementInput},
    };
    const RAM_BASE: u64 = 0x4000_0000;
    const RAM_SIZE: usize = 64 * 1024 * 1024;
    const KERNEL_OFFSET: usize = 32 * 1024 * 1024;
    const VIRTUAL_BASE: u64 = 0xffff_fe00_0000_0000;
    const FRAMEBUFFER_OFFSET: usize = 0x30000;
    let tree = FlatNode {
        name: String::new(),
        properties: vec![],
        children: vec![FlatNode {
            name: "chosen".into(),
            properties: vec![
                FlatProperty {
                    name: "dram-base".into(),
                    value: RAM_BASE.to_le_bytes().to_vec(),
                },
                FlatProperty {
                    name: "dram-size".into(),
                    value: (RAM_SIZE as u64).to_le_bytes().to_vec(),
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
            memory_size: RAM_SIZE as u64,
            actual_memory_size: RAM_SIZE as u64,
            kernel_phys: RAM_BASE + KERNEL_OFFSET as u64,
            device_tree: &dt,
            command_line: arguments,
            machine_type: 0,
            boot_flags: 0,
            video: Arm64BootVideo::default(),
        },
    )
    .map_err(|error| {
        report(&format!("NXARMJIT: PLACEMENT_INVALID reason={error}"));
        Status::LOAD_ERROR
    })?;
    let l = *plan.layout();
    let end = KERNEL_OFFSET
        .checked_add(l.allocation_bytes)
        .filter(|end| *end <= RAM_SIZE)
        .ok_or(Status::OUT_OF_RESOURCES)?;
    let mut ram = ArmPages::allocate_data(RAM_SIZE)?;
    plan.stage_into(&mut ram.bytes_mut()[KERNEL_OFFSET..end])
        .map_err(|_| Status::COMPROMISED_DATA)?;
    let mut code = ArmPages::allocate(64 * 1024, None)?;
    let system = uefi::table::system_table_raw().ok_or(Status::NOT_READY)?;
    let mut protection = [0usize; 2];
    let protection_pointer = protection.as_mut_ptr().cast();
    // SAFETY: firmware table is live, C validates the aligned 16-byte storage.
    if unsafe {
        vf_efi_jit_protection_open(
            system.as_ptr().cast(),
            protection_pointer,
            core::mem::size_of_val(&protection),
        )
    } != 0
    {
        report("NXARMJIT: PROTECTION_UNAVAILABLE");
        return Err(Status::UNSUPPORTED);
    }
    report("NXARMJIT: STAGING_VERIFIED guest_addresses_separate=true");
    report(&format!(
        "NXARMJIT: GUEST_ENTRY_READY entry={:#x} x0={:#x} ram_base={RAM_BASE:#x}",
        l.entry_phys, l.boot_args_phys
    ));
    report("NXARMJIT: JIT_ENTER host_boot_services=active");
    let mut result = JitResult::default();
    // SAFETY: disjoint retained RAM/code allocations, exact C result ABI and
    // validated protection callback. Only emitted x86 bytes execute on host.
    unsafe extern "C" fn pauth_step(context: *mut core::ffi::c_void, word: u32) -> i32 {
        unsafe { pauth::vf_preos_pauth_step(context.cast(), word) }
    }
    let status = unsafe {
        vf_boot_run_with_pauth(
            ram.bytes_mut().as_mut_ptr(),
            RAM_SIZE,
            RAM_BASE,
            l.entry_phys,
            l.boot_args_phys,
            l.stack_top_phys,
            code.bytes_mut().as_mut_ptr(),
            code.bytes(),
            100_000,
            vf_efi_jit_protect,
            protection_pointer,
            pauth_step,
            &mut result,
        )
    };
    let restore =
        unsafe { vf_efi_jit_protect(code.base() as *mut _, code.bytes(), 0, protection_pointer) };
    report(&format!(
        "NXARMJIT: JIT_RETURN status={status} retired={} pc={:#x} blocks={} fault={:#x}",
        result.retired, result.pc, result.compiled_blocks, result.fault_instruction
    ));
    if restore != 0 {
        return Err(Status::DEVICE_ERROR);
    }
    let expected_retired = if pac { 45 } else { 25 };
    if status != 1
        || result.status != 1
        || result.retired != expected_retired
        || result.pc != l.entry_phys + expected_retired * 4
        || result.compiled_blocks == 0
        || result.x0 != l.boot_args_phys
        || result.x1 != 0x20002
        || result.x2 != RAM_BASE + 0x10000
        || result.x3 != plan.boot_args().device_tree_virtual_address()
    {
        return Err(Status::COMPROMISED_DATA);
    }
    let mut expected = [0u8; 32];
    for (index, value) in [
        0x20002,
        plan.boot_args().device_tree_virtual_address(),
        RAM_BASE,
        RAM_SIZE as u64,
    ]
    .into_iter()
    .enumerate()
    {
        expected[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    if ram.bytes_mut()[0x10000..0x10020] != expected {
        return Err(Status::COMPROMISED_DATA);
    }
    report("NXARMJIT: BOOT_ARGS_READBACK_OK");
    if pac {
        let signed = u64::from_le_bytes(ram.bytes_mut()[0x10020..0x10028].try_into().unwrap());
        let authenticated =
            u64::from_le_bytes(ram.bytes_mut()[0x10028..0x10030].try_into().unwrap());
        if signed != 0xbf36_0000_0000_0130 || authenticated != 0x130 {
            return Err(Status::COMPROMISED_DATA);
        }
        report("NXARMJIT: ARM64E_PAC_READBACK_OK");
    }
    let pixels = &ram.bytes_mut()[FRAMEBUFFER_OFFSET..FRAMEBUFFER_OFFSET + 64];
    if !pixels.chunks_exact(4).all(|p| p == [0x33, 0x22, 0x11, 0]) {
        return Err(Status::COMPROMISED_DATA);
    }
    report("NXARMJIT: GUEST_FRAMEBUFFER_OK");
    let services = unsafe { (*system.as_ptr()).boot_services }.cast();
    let presented = unsafe {
        vf_gop_present(
            services,
            ram.bytes_mut().as_ptr(),
            RAM_SIZE as u64,
            FRAMEBUFFER_OFFSET as u64,
            4,
            4,
            16,
            0,
            0,
        )
    };
    if presented != Status::SUCCESS {
        report(&format!(
            "NXARMJIT: GOP_PRESENT_FAILED status={presented:?}"
        ));
        return Err(presented);
    }
    #[repr(align(4))]
    struct GopReadback([u8; 64]);
    let mut captured = GopReadback([0u8; 64]);
    let readback =
        unsafe { vf_gop_readback(services, captured.0.as_mut_ptr(), 64, 0, 4, 4, 16, 0, 0) };
    if readback != Status::SUCCESS {
        return Err(readback);
    }
    // GOP reserved byte has no color meaning; compare all sixteen RGB pixels.
    if !captured
        .0
        .chunks_exact(4)
        .all(|p| p[..3] == [0x33, 0x22, 0x11])
    {
        return Err(Status::COMPROMISED_DATA);
    }
    report("NXARMJIT: GOP_READBACK_OK pixels=16");
    report("NXARMJIT: AUTHORED_HANDOFF_OK xnu_executed=false macos_boot_verified=false metal_verified=false");
    Ok(())
}

/// Explicit incomplete SPTM cold-entry diagnostic for caller-supplied kernels.
/// No SPTM argument/service or runtime platform DT is provisioned. A returned
/// guest halt/fault/budget is recorded, never converted into OS boot.
#[cfg(all(target_arch = "x86_64", feature = "arm-jit-trace"))]
fn run_trace(source: &[u8], arguments: &str, config: &[u8]) -> Result<(), Status> {
    use nextcore_core::{
        boot_config::parse_arm64_trace_configuration,
        xnu_arm64_boot_args::Arm64BootVideo,
        xnu_arm64_handoff::{Arm64HandoffPlan, Arm64PlacementInput},
    };
    let trace = parse_arm64_trace_configuration(config).map_err(|error| {
        report(&format!("NXARMJIT: TRACE_CONFIG_INVALID reason={error}"));
        Status::INVALID_PARAMETER
    })?;
    let path = CString16::try_from(trace.device_tree_path.as_str())
        .map_err(|_| Status::INVALID_PARAMETER)?;
    let dt = read_file(&path, 1024 * 1024)?;
    let plan = Arm64HandoffPlan::new(
        source,
        Arm64PlacementInput {
            physical_base: trace.physical_base,
            virtual_base: trace.virtual_base,
            memory_size: trace.memory_size,
            actual_memory_size: trace.actual_memory_size,
            kernel_phys: trace.kernel_phys,
            device_tree: &dt,
            command_line: arguments,
            machine_type: 0,
            boot_flags: 0,
            video: Arm64BootVideo::default(),
        },
    )
    .map_err(|error| {
        report(&format!("NXARMJIT: TRACE_PLACEMENT_INVALID reason={error}"));
        Status::LOAD_ERROR
    })?;
    let layout = *plan.layout();
    let offset = usize::try_from(layout.kernel_phys - trace.physical_base)
        .map_err(|_| Status::INVALID_PARAMETER)?;
    let memory_size = usize::try_from(trace.memory_size).map_err(|_| Status::INVALID_PARAMETER)?;
    let end = offset
        .checked_add(layout.allocation_bytes)
        .filter(|end| *end <= memory_size)
        .ok_or(Status::BAD_BUFFER_SIZE)?;
    let mut ram = ArmPages::allocate_data(memory_size)?;
    plan.stage_into(&mut ram.bytes_mut()[offset..end])
        .map_err(|_| Status::COMPROMISED_DATA)?;
    let mut code = ArmPages::allocate(64 * 1024, None)?;
    let system = uefi::table::system_table_raw().ok_or(Status::NOT_READY)?;
    let mut protection = [0usize; 2];
    let opaque = protection.as_mut_ptr().cast();
    if unsafe {
        vf_efi_jit_protection_open(
            system.as_ptr().cast(),
            opaque,
            core::mem::size_of_val(&protection),
        )
    } != 0
    {
        return Err(Status::UNSUPPORTED);
    }
    unsafe extern "C" fn pauth_step(context: *mut core::ffi::c_void, word: u32) -> i32 {
        unsafe { pauth::vf_preos_pauth_step(context.cast(), word) }
    }
    report("NXARMJIT: TRACE_STAGING_VERIFIED source_unchanged=true");
    report("NXARMJIT: TRACE_HANDOFF_UNPROVISIONED abi=unprovisioned-sptm-prefix sptm_args=false sptm_services=false platform_device_tree=false");
    let initial = [0, layout.boot_args_phys, 0, 0];
    report(&format!(
        "NXARMJIT: TRACE_ENTER entry={:#x} x0=0 x1={:#x} x2=0 x3=0 budget={}",
        layout.entry_phys, initial[1], trace.instruction_budget
    ));
    let mut result = JitResult::default();
    let status = unsafe {
        vf_boot_run_with_registers(
            ram.bytes_mut().as_mut_ptr(),
            memory_size,
            trace.physical_base,
            layout.entry_phys,
            layout.boot_args_phys,
            layout.stack_top_phys,
            code.bytes_mut().as_mut_ptr(),
            code.bytes(),
            trace.instruction_budget,
            vf_efi_jit_protect,
            opaque,
            initial.as_ptr(),
            pauth_step,
            &mut result,
        )
    };
    let restore = unsafe { vf_efi_jit_protect(code.base() as *mut _, code.bytes(), 0, opaque) };
    report(&format!(
        "NXARMJIT: TRACE_RETURN status={status} retired={} pc={:#x} blocks={} instruction={:#x}",
        result.retired, result.pc, result.compiled_blocks, result.fault_instruction
    ));
    report(&format!(
        "NXARMJIT: TRACE_REGISTERS x0={:#x} x1={:#x} x2={:#x} x3={:#x}",
        result.x0, result.x1, result.x2, result.x3
    ));
    report("NXARMJIT: TRACE_ONLY macos_boot_verified=false metal_verified=false");
    if restore != 0 {
        return Err(Status::DEVICE_ERROR);
    }
    // A completed diagnostic is deliberately not EFI/OS launch success.
    Err(Status::ABORTED)
}
