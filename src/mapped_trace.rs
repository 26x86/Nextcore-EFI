//! Explicit software-defined mapped diagnostic, without normal-startup approval.
use crate::{firmware_io::report, memory_boot, memory_boot_v2, pauth, platform};
use core::ffi::c_void;
use nextcore_core::arm64_stage1_tables::Arm64Stage1Tables;
use nextcore_memory_service::{abi_v2, stage1::MemoryServiceV2};
use uefi::Status;

type Protect = unsafe extern "C" fn(*mut c_void, usize, i32, *mut c_void) -> i32;
unsafe extern "C" {
    fn vf_boot_run_memory_pauth_v2(
        base: u64,
        size: u64,
        entry: u64,
        args: u64,
        stack: u64,
        code: *mut u8,
        code_bytes: usize,
        budget: u64,
        protect: Protect,
        opaque: *mut c_void,
        initial: *const u64,
        pauth: unsafe extern "C" fn(*mut c_void, u32) -> i32,
        options: *const platform::BootOptionsV2,
        controls: *const abi_v2::Controls,
        memory: abi_v2::Callback,
        owner: *mut c_void,
        result: *mut memory_boot_v2::MemoryRunResultV2,
    ) -> i32;
}

#[cfg(feature = "arm-jit-memory-observation")]
struct Observed<'a> {
    service: MemoryServiceV2<'a>,
    ring: [crate::memory_observation::Entry; 64],
    total: u64,
}
#[cfg(feature = "arm-jit-memory-observation")]
unsafe extern "C" fn observed(
    owner: *mut c_void,
    q: *const abi_v2::Request,
    r: *mut abi_v2::Reply,
) -> i32 {
    if owner.is_null()
        || q.is_null()
        || r.is_null()
        || !owner.cast::<Observed<'_>>().is_aligned()
        || !q.is_aligned()
        || !r.is_aligned()
    {
        return -1;
    }
    // SAFETY: run retains disjoint initialized records and a uniquely borrowed
    // owner until this synchronous call returns; no callback can reenter.
    let (owner, request) = unsafe { (&mut *owner.cast::<Observed<'_>>(), q.read()) };
    let reply = owner.service.execute(&request);
    let slot = (owner.total % 64) as usize;
    owner.total = owner.total.saturating_add(1);
    owner.ring[slot] = crate::memory_observation::Entry {
        sequence: owner.total,
        operation: request.operation,
        pc: request.pc,
        address: request.address,
        width: request.width,
        count: request.count,
        result: reply.result,
    };
    // SAFETY: the C runner provides a separate writable full reply record.
    unsafe { r.write(reply) };
    0
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    ram: &mut [u8],
    base: u64,
    virtual_base: u64,
    entry: u64,
    args: u64,
    stack: u64,
    code: &mut [u8],
    budget: u64,
    protect: Protect,
    opaque: *mut c_void,
    initial: &[u64; 4],
    options: &platform::BootOptionsV2,
) -> Result<(i32, memory_boot::MemoryRunResultV1), Status> {
    let tables = Arm64Stage1Tables::new(base, virtual_base, ram.len() as u64)
        .map_err(|_| Status::INVALID_PARAMETER)?;
    let controls = abi_v2::Controls {
        abi_version: 2,
        struct_size: 80,
        profile: abi_v2::PROFILE_FIXED_NC_UNALIGNED,
        sctlr: 0x30d00801,
        ttbr0: tables.ttbr0(),
        ttbr1: tables.ttbr1(),
        tcr: tables.tcr(),
        mair: 0x44,
        epoch: 1,
        ..Default::default()
    };
    report(&alloc::format!("NXARMJIT: TRACE_MAPPINGS_READY granule=16384 profile=3 physical_base={base:#x} virtual_base={virtual_base:#x} memory_size={} table_base={:#x} table_bytes={} ttbr0={:#x} ttbr1={:#x} tcr={:#x} sctlr={:#x} entry={entry:#x}",
        ram.len(),tables.physical_base(),tables.bytes().len(),controls.ttbr0,controls.ttbr1,controls.tcr,controls.sctlr));
    report("NXARMJIT: TRACE_MEMORY_PROVIDER abi=2 mode=mapped-normal-nc-v1");
    let size = ram.len() as u64;
    let service = MemoryServiceV2::new(ram, base, tables.bytes(), tables.physical_base(), controls)
        .map_err(|_| Status::INVALID_PARAMETER)?;
    #[cfg(feature = "arm-jit-memory-observation")]
    let mut service = Observed {
        service,
        ring: [crate::memory_observation::Entry::default(); 64],
        total: 0,
    };
    #[cfg(not(feature = "arm-jit-memory-observation"))]
    let mut service = service;
    #[cfg(feature = "arm-jit-memory-observation")]
    let callback: abi_v2::Callback = observed;
    #[cfg(not(feature = "arm-jit-memory-observation"))]
    let callback: abi_v2::Callback = nextcore_memory_service::stage1::vf_memory_service_step_v2;
    unsafe extern "C" fn pauth_step(context: *mut c_void, word: u32) -> i32 {
        // SAFETY: the C adapter supplies its live, aligned architecture context.
        unsafe { pauth::vf_preos_pauth_step(context.cast(), word) }
    }
    let mut result = memory_boot_v2::MemoryRunResultV2::default();
    // SAFETY: all records and owned code/RAM/tables are disjoint and remain
    // alive throughout this synchronous call. Guest addresses are never host PCs.
    let status = unsafe {
        vf_boot_run_memory_pauth_v2(
            base,
            size,
            entry,
            args,
            stack,
            code.as_mut_ptr(),
            code.len(),
            budget,
            protect,
            opaque,
            initial.as_ptr(),
            pauth_step,
            options,
            &controls,
            callback,
            core::ptr::from_mut(&mut service).cast(),
            &mut result,
        )
    };
    #[cfg(feature = "arm-jit-memory-observation")]
    {
        let retained = service.total.min(64);
        report(&alloc::format!(
            "NXARMJIT: TRACE_MEMORY_OBSERVATION total={} retained={retained}",
            service.total
        ));
        for sequence in service.total - retained..service.total {
            let e = &service.ring[(sequence % 64) as usize];
            report(&alloc::format!("NXARMJIT: TRACE_MEMORY_REQUEST sequence={} operation={} pc={:#x} address={:#x} width={} count={} result={}",e.sequence,e.operation,e.pc,e.address,e.width,e.count,e.result));
        }
    }
    let r = &result.last_reply;
    report(&alloc::format!("NXARMJIT: TRACE_MAPPED_REPLY result={} fault={} address={:#x} output_pa={:#x} descriptor_pa={:#x} level={} context={} metadata_flags={} esr={:#x}",r.result,r.fault,r.address,r.output_pa,r.descriptor_pa,r.level,r.context,r.metadata_flags,r.esr));
    Ok((status, result.base))
}
