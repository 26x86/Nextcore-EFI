//! Authored one-way M=0 -> M=1 through the actual x86 EFI JIT and owned service.
#![no_std]
#![no_main]
extern crate alloc;
mod arm_pages;
#[allow(dead_code)]
mod firmware_io;
include!(concat!(env!("OUT_DIR"), "/jit_pauth.rs"));
use alloc::{format, vec::Vec};
use arm_pages::ArmPages;
use core::ffi::c_void;
use firmware_io::report;
use nextcore_core::runtime_dt::source_identity;
use nextcore_memory_service::{
    abi_v2 as m,
    dynamic::{vf_memory_dynamic_control_v1, vf_memory_dynamic_step_v1, MemoryServiceDynamic},
    dynamic_abi as c,
};
use uefi::{entry, Status};
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;
unsafe extern "C" {
    fn vf_efi_jit_protection_open(table: *mut c_void, storage: *mut c_void, bytes: usize) -> i32;
    fn vf_efi_jit_protect(p: *mut c_void, n: usize, executable: i32, opaque: *mut c_void) -> i32;
    fn vf_boot_run_memory_dynamic(
        base: u64,
        size: u64,
        entry: u64,
        args: u64,
        stack: u64,
        code: *mut u8,
        code_bytes: usize,
        budget: u64,
        protect: unsafe extern "C" fn(*mut c_void, usize, i32, *mut c_void) -> i32,
        opaque: *mut c_void,
        initial: *const u64,
        options: *const platform::BootOptionsV2,
        controls: *const m::Controls,
        memory: m::Callback,
        control: c::Callback,
        owner: *mut c_void,
        result: *mut memory_dynamic::MemoryRunResultDynamic,
    ) -> i32;
}
const RAM_PA: u64 = 0x4000_0000;
const TABLE_PA: u64 = 0x1000_0000;
const SCTLR: u64 = 0x30d0_0802;
const HLT: u32 = 0xd4400000;
const HVC_DECOY: u32 = 0xd4000002; // Explicit unsupported instruction if enable is omitted.
const ISB: u32 = 0xd5033fdf;
const DSB: u32 = 0xd5033f9f;
const TLBI: u32 = 0xd508871f;
const OMIT_ENABLE: bool = false; // Separate external omission-negative build only.
const DATA_LIMIT: usize = 64;
const CONTROL_LIMIT: usize = 16;

fn checked<T, E>(value: Result<T, E>) -> Result<T, Status> {
    value.map_err(|_| Status::COMPROMISED_DATA)
}
fn require(value: bool) -> Result<(), Status> {
    if value {
        Ok(())
    } else {
        Err(Status::COMPROMISED_DATA)
    }
}
fn disjoint(a: u64, n: u64, b: u64, m: u64) -> bool {
    match (a.checked_add(n), b.checked_add(m)) {
        (Some(x), Some(y)) => x <= b || y <= a,
        _ => false,
    }
}
fn hex(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut value = alloc::string::String::new();
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}
fn words(ram: &mut [u8], at: usize, words: &[u32]) {
    for (i, word) in words.iter().enumerate() {
        ram[at + i * 4..at + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}
struct Owner<'a> {
    service: MemoryServiceDynamic<'a>,
    data: Vec<(m::Request, m::Reply)>,
    control: Vec<(c::Request, c::Reply)>,
    reads_at_tlbi: u64,
}
unsafe extern "C" fn observe_data(
    owner: *mut c_void,
    request: *const m::Request,
    reply: *mut m::Reply,
) -> i32 {
    // SAFETY: synchronous canonical caller supplies live aligned records and the
    // sole owner; callbacks never retain pointers or reenter the service.
    let owner = unsafe { &mut *owner.cast::<Owner<'_>>() };
    if owner.data.len() == DATA_LIMIT {
        return 1;
    }
    let request = unsafe { *request };
    let status = unsafe {
        vf_memory_dynamic_step_v1(
            (&mut owner.service as *mut MemoryServiceDynamic<'_>).cast(),
            &request,
            reply,
        )
    };
    if status == 0 {
        owner.data.push((request, unsafe { *reply }));
    }
    status
}
unsafe extern "C" fn observe_control(
    owner: *mut c_void,
    request: *const c::Request,
    reply: *mut c::Reply,
) -> i32 {
    // Same exclusive synchronous owner as the data callback; capacity is reserved
    // before execution, so observation neither allocates nor alters a reply.
    let owner = unsafe { &mut *owner.cast::<Owner<'_>>() };
    if owner.control.len() == CONTROL_LIMIT {
        return 1;
    }
    let request = unsafe { *request };
    let status = unsafe {
        vf_memory_dynamic_control_v1(
            (&mut owner.service as *mut MemoryServiceDynamic<'_>).cast(),
            &request,
            reply,
        )
    };
    if status == 0 {
        let observed = unsafe { *reply };
        owner.control.push((request, observed));
        if request.phase == c::COMMIT && request.operation == c::TLBI {
            owner.reads_at_tlbi = owner.service.table_reads();
        }
    }
    status
}

struct Tables<'a> {
    bytes: &'a mut [u8],
    granule: usize,
    next: usize,
}
impl Tables<'_> {
    fn read(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.bytes[offset..offset + 8].try_into().unwrap())
    }
    fn write(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn map(&mut self, va: u64, descriptor: u64) -> Result<(), Status> {
        let sixteen = self.granule == 16384;
        let page = if sixteen { 14 } else { 12 };
        let bits = if sixteen { 11 } else { 9 };
        let start = if sixteen { 1 } else { 0 };
        let mask = (1u64 << bits) - 1;
        let mut table = if va >> 63 == 0 { 0 } else { self.granule };
        for level in start..=3 {
            let index = ((va >> (page + bits * (3 - level))) & mask) as usize;
            let offset = table + index * 8;
            if offset + 8 > self.bytes.len() {
                return Err(Status::BAD_BUFFER_SIZE);
            }
            if level == 3 {
                self.write(offset, descriptor);
                return Ok(());
            }
            let previous = self.read(offset);
            if previous == 0 {
                let next = self.next * self.granule;
                if next + self.granule > self.bytes.len() {
                    return Err(Status::OUT_OF_RESOURCES);
                }
                self.next += 1;
                self.write(offset, (TABLE_PA + next as u64) | 3);
                table = next;
            } else {
                table = ((previous & 0x0000_ffff_ffff_f000) - TABLE_PA) as usize;
            }
        }
        Err(Status::COMPROMISED_DATA)
    }
}

fn run_case(granule: usize, kind: usize) -> Result<(), Status> {
    let name = ["roundtrip", "fetch-translation", "data-translation"][kind];
    let mut ram = ArmPages::allocate_data(8 * granule)?;
    let mut tables = ArmPages::allocate_data(8 * granule)?;
    let mut code = ArmPages::allocate(64 * 1024, None)?;
    let host_ram = ram.base();
    let host_tables = tables.base();
    let host_code = code.base();
    let ram_bytes = ram.bytes();
    let table_bytes = tables.bytes();
    require(
        disjoint(host_ram, ram_bytes as u64, host_tables, table_bytes as u64)
            && disjoint(host_ram, ram_bytes as u64, host_code, code.bytes() as u64)
            && disjoint(
                host_tables,
                table_bytes as u64,
                host_code,
                code.bytes() as u64,
            )
            && disjoint(RAM_PA, ram_bytes as u64, TABLE_PA, table_bytes as u64),
    )?;
    ram.bytes_mut().fill(0xa5);
    let entry = RAM_PA + granule as u64 - 12;
    let post_va = RAM_PA + granule as u64;
    let target_pa = RAM_PA + 3 * granule as u64;
    let data_va = if kind == 0 {
        RAM_PA + 3 * granule as u64 - 8
    } else {
        RAM_PA + 2 * granule as u64
    };
    let stub = [
        0x91000442,
        if OMIT_ENABLE { 0x91000000 } else { 0xd5181000 },
        ISB,
    ];
    words(ram.bytes_mut(), granule - 12, &stub);
    words(ram.bytes_mut(), granule, &[HVC_DECOY]);
    let tail = if kind == 0 {
        Vec::from([
            0xd5381000, 0xf9400023, 0x91000463, 0xf9000023, 0xa9000c22, 0xa9400823, DSB, TLBI, DSB,
            ISB, 0xf9400020, HLT,
        ])
    } else {
        Vec::from([0xf9400023, HLT])
    };
    words(ram.bytes_mut(), 3 * granule, &tail);
    ram.bytes_mut()[5 * granule - 8..5 * granule].copy_from_slice(&41u64.to_le_bytes());
    let before = ram.bytes_mut().to_vec();
    let mut expected = before.clone();
    if kind == 0 {
        expected[5 * granule - 8..5 * granule].copy_from_slice(&9u64.to_le_bytes());
        expected[2 * granule..2 * granule + 8].copy_from_slice(&42u64.to_le_bytes());
    }
    {
        let mut builder = Tables {
            bytes: tables.bytes_mut(),
            granule,
            next: 2,
        };
        builder.map(RAM_PA, RAM_PA | 0x403)?;
        builder.map(post_va, if kind == 1 { 0 } else { target_pa | 0x403 })?;
        builder.map(
            RAM_PA + 2 * granule as u64,
            if kind == 2 {
                0
            } else {
                RAM_PA + 4 * granule as u64 | 0x403
            },
        )?;
        builder.map(
            RAM_PA + 3 * granule as u64,
            RAM_PA + 2 * granule as u64 | 0x403,
        )?;
    }
    let tables_before = tables.bytes_mut().to_vec();
    let tsz = if granule == 16384 { 17 } else { 16 };
    let tcr = tsz
        | (tsz << 16)
        | (5u64 << 32)
        | if granule == 16384 {
            (2 << 14) | (1 << 30)
        } else {
            2 << 30
        };
    let controls = m::Controls {
        abi_version: 3,
        struct_size: 80,
        profile: 2,
        sctlr: SCTLR,
        ttbr0: TABLE_PA,
        ttbr1: TABLE_PA,
        tcr,
        mair: 0x44,
        epoch: 1,
        ..Default::default()
    };
    let options = platform::BootOptionsV2 {
        abi_version: 2,
        struct_size: 64,
        initial_pstate: 0x3c5,
        ..Default::default()
    };
    let initial = [SCTLR | 1, data_va, 8, 99];
    let stack = RAM_PA + 0x400;
    let mut result = memory_dynamic::MemoryRunResultDynamic::default();
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
    let mut data = Vec::new();
    data.try_reserve_exact(DATA_LIMIT)
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    let mut control = Vec::new();
    control
        .try_reserve_exact(CONTROL_LIMIT)
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    let (status, service_state, table_reads, reads_at_tlbi, data, control) = {
        let mut owner = Owner {
            service: checked(MemoryServiceDynamic::new(
                ram.bytes_mut(),
                RAM_PA,
                tables.bytes_mut(),
                TABLE_PA,
                controls,
            ))?,
            data,
            control,
            reads_at_tlbi: 0,
        };
        let owner_start = (&owner as *const Owner<'_>) as usize as u64;
        let result_start =
            (&result as *const memory_dynamic::MemoryRunResultDynamic) as usize as u64;
        for (start, size) in [
            (owner_start, core::mem::size_of_val(&owner) as u64),
            (result_start, core::mem::size_of_val(&result) as u64),
            (
                owner.data.as_ptr() as usize as u64,
                (owner.data.capacity() * core::mem::size_of::<(m::Request, m::Reply)>()) as u64,
            ),
            (
                owner.control.as_ptr() as usize as u64,
                (owner.control.capacity() * core::mem::size_of::<(c::Request, c::Reply)>()) as u64,
            ),
        ] {
            require(
                disjoint(start, size, host_ram, ram_bytes as u64)
                    && disjoint(start, size, host_tables, table_bytes as u64)
                    && disjoint(start, size, host_code, code.bytes() as u64),
            )?;
        }
        // SAFETY: observer and canonical service exclusively own live borrows;
        // all C input/output/protection/code records are disjoint, callback-only.
        let status = unsafe {
            vf_boot_run_memory_dynamic(
                RAM_PA,
                ram_bytes as u64,
                entry,
                initial[0],
                stack,
                code.bytes_mut().as_mut_ptr(),
                code.bytes(),
                32,
                vf_efi_jit_protect,
                opaque,
                initial.as_ptr(),
                &options,
                &controls,
                observe_data,
                observe_control,
                (&mut owner as *mut Owner<'_>).cast(),
                &mut result,
            )
        };
        (
            status,
            owner.service.final_state(),
            owner.service.table_reads(),
            owner.reads_at_tlbi,
            owner.data,
            owner.control,
        )
    };
    let restored = unsafe { vf_efi_jit_protect(code.base() as *mut _, code.bytes(), 0, opaque) };
    let b = &result.memory.base;
    let e = &b.execution;
    let state = &e.base;
    let final_state = &result.final_control;
    let want_status = if kind == 0 {
        1
    } else if kind == 1 {
        16
    } else {
        17
    };
    let retired = if kind == 0 { 15 } else { 3 };
    let esr = if kind == 0 {
        0
    } else if kind == 1 {
        0x86000007
    } else {
        0x96000007
    };
    let far = if kind == 0 {
        0
    } else if kind == 1 {
        post_va
    } else {
        data_va
    };
    let pc = if kind == 0 {
        post_va + tail.len() as u64 * 4
    } else {
        post_va
    };
    let expected_x = if kind == 0 {
        [9, data_va, 42, 9]
    } else {
        [initial[0], data_va, 9, 99]
    };
    let expected_control = if kind == 0 { 12 } else { 4 };
    let expected_fetch = if kind == 0 { 15 } else { 4 };
    let expected_data = if kind == 0 {
        5
    } else if kind == 1 {
        0
    } else {
        1
    };
    let pending = data
        .iter()
        .find(|(q, _)| q.pc == entry + 8 && q.operation == 1);
    let post = data
        .iter()
        .find(|(q, _)| q.pc == post_va && q.operation == 1);
    let transition = pending.is_some_and(|(q, r)| {
        q.controls.sctlr == SCTLR && q.controls.epoch == 1 && r.value0 == ISB as u64
    }) && post
        .is_some_and(|(q, _)| q.controls.sctlr == SCTLR | 1 && q.controls.epoch == 2);
    let protocol = control.len() == expected_control
        && control.chunks_exact(2).all(|pair| {
            let ((prepare, proposal), (commit, ack)) = (pair[0], pair[1]);
            prepare.phase == c::PREPARE
                && commit.phase == c::COMMIT
                && prepare.operation == commit.operation
                && proposal.result == c::OK
                && ack.result == c::OK
                && proposal.state_tag == c::PROPOSED
                && ack.state_tag == c::KNOWN
                && proposal.token != 0
                && commit.operand == proposal.token
                && ack.token == 0
        });
    let ram_exact = ram.bytes_mut() == expected;
    let tables_exact = tables.bytes_mut() == tables_before;
    let good_final = final_state == &service_state
        && final_state.abi_version == 1
        && final_state.struct_size == 192
        && final_state.state_tag == c::KNOWN
        && final_state.phase == 0
        && final_state.token == 0
        && final_state.revision == 2
        && final_state.epoch == 2
        && final_state.invalidations == u64::from(kind == 0)
        && final_state.architectural.sctlr == SCTLR | 1
        && final_state.architectural == final_state.effective
        && final_state.effective.ttbr0 == controls.ttbr0
        && final_state.effective.ttbr1 == controls.ttbr1
        && final_state.effective.tcr == controls.tcr
        && final_state.effective.mair == controls.mair
        && final_state.effective.hcr == 0
        && final_state.effective.scr == 0
        && final_state.effective.reserved == 0;
    let pass = restored == 0
        && status == want_status
        && state.status == want_status as u32
        && b.abi_version == 3
        && b.struct_size == 512
        && b.provider_status == 0
        && state.retired == retired
        && state.pc == pc
        && [state.x0, state.x1, state.x2, state.x3] == expected_x
        && e.sp == stack
        && e.pstate == 0x3c5
        && e.esr == esr
        && b.guest_far == far
        && b.fetch_requests == expected_fetch
        && b.data_requests == expected_data
        && b.completed_data_operations == if kind == 0 { 5 } else { 0 }
        && state.compiled_blocks
            == if kind == 0 {
                15
            } else if kind == 1 {
                3
            } else {
                4
            }
        && result.memory.last_reply.result == if kind == 0 { m::OK } else { m::GUEST_FAULT }
        && state.fault_instruction == if kind == 2 { tail[0] } else { 0 }
        && (kind == 0
            || (result.memory.last_reply.fsc == 7
                && result.memory.last_reply.level == 3
                && e.elr == pc
                && e.spsr == 0x3c5
                && result.memory.last_reply.address == far
                && b.last_address == far))
        && transition
        && protocol
        && good_final
        && ram_exact
        && tables_exact
        && table_reads > 0
        && (kind != 0 || (reads_at_tlbi > 0 && table_reads > reads_at_tlbi));
    for (index, (q, r)) in data.iter().enumerate() {
        report(&format!("NXDYN: DATA name={name} granule={granule} index={index} pc={:#x} address={:#x} operation={} width={} count={} sctlr={:#x} epoch={} reply={} value0={:#x} value1={:#x} esr={:#x} fsc={} far={:#x}",
            q.pc,q.address,q.operation,q.width,q.count,q.controls.sctlr,q.controls.epoch,r.result,r.value0,r.value1,r.esr,r.fsc,r.address));
    }
    for (index, (q, r)) in control.iter().enumerate() {
        report(&format!("NXDYN: CONTROL name={name} granule={granule} index={index} phase={} operation={} selector={} pc={:#x} operand={:#x} request_revision={} request_epoch={} reply={} tag={} token={} revision={} epoch={} invalidations={} arch={:#x} effective={:#x}",
            q.phase,q.operation,q.selector,q.pc,q.operand,q.revision,q.epoch,r.result,r.state_tag,r.token,r.revision,r.epoch,r.invalidations,r.architectural.sctlr,r.effective.sctlr));
    }
    report(&format!("NXDYN: CASE name={name} granule={granule} status={status} provider={} retired={} blocks={} fetch={} data={} completed={} control={} table_reads={} tlbi_reads={} esr={:#x} far={:#x} elr={:#x} spsr={:#x} pstate={:#x} pc={:#x} x0={:#x} x1={:#x} x2={:#x} x3={:#x} sp={:#x} version={} bytes={} tag={} revision={} epoch={} invalidations={} arch={:#x} effective={:#x} tcr={:#x} ttbr0={:#x} ttbr1={:#x} mair={:#x} transition={} protocol={} ram={} tables={} ram_host={:#x} table_host={:#x} jit_host={:#x} ram_sha={} table_before_sha={} table_after_sha={} pass={}",
        b.provider_status,state.retired,state.compiled_blocks,b.fetch_requests,b.data_requests,b.completed_data_operations,control.len(),table_reads,reads_at_tlbi,
        e.esr,b.guest_far,e.elr,e.spsr,e.pstate,state.pc,state.x0,state.x1,state.x2,state.x3,e.sp,b.abi_version,b.struct_size,
        final_state.state_tag,final_state.revision,final_state.epoch,final_state.invalidations,final_state.architectural.sctlr,
        final_state.effective.sctlr,final_state.effective.tcr,final_state.effective.ttbr0,final_state.effective.ttbr1,final_state.effective.mair,
        transition,protocol,ram_exact,tables_exact,host_ram,host_tables,host_code,hex(&source_identity(ram.bytes_mut())),
        hex(&source_identity(&tables_before)),hex(&source_identity(tables.bytes_mut())),pass));
    require(pass)
}
#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::NOT_READY;
    }
    report("NXDYN: ENTRY host=x86_64 authored=true profile=nextcore-stage1-enable-nc-v1");
    if !cfg!(target_arch = "x86_64") {
        return Status::UNSUPPORTED;
    }
    let mut count = 0;
    for granule in [4096, 16384] {
        for kind in 0..3 {
            if let Err(status) = run_case(granule, kind) {
                report(&format!("NXDYN: FAIL case={count} status={status:?}"));
                return status;
            }
            count += 1;
        }
    }
    report("NXDYN: PASS cases=6 macos_boot_verified=false");
    Status::SUCCESS
}
