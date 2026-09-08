//! Independently authored owned DeviceTree ledger / stage-1 JIT proof inside x86 EFI.
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
use nextcore_memory_service::{
    abi_v2,
    stage1::{vf_memory_service_step_v2, MemoryServiceV2},
};
use uefi::{entry, Status};

#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

unsafe extern "C" {
    fn vf_efi_jit_protection_open(table: *mut c_void, storage: *mut c_void, bytes: usize) -> i32;
    fn vf_efi_jit_protect(p: *mut c_void, n: usize, executable: i32, opaque: *mut c_void) -> i32;
    fn vf_boot_run_memory_v2(
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
        controls: *const abi_v2::Controls,
        memory: abi_v2::Callback,
        owner: *mut c_void,
        result: *mut memory_boot_v2::MemoryRunResultV2,
    ) -> i32;
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

const RAM_PA: u64 = 0x1000_0000;
const TABLE_PA: u64 = 0x3000_0000;
const VA_LO: u64 = 0x2000_0000;
const VA_HI: u64 = 0xffff_8000_2000_0000;
const MARKER: u32 = 0xabcd;
const GUARD: u8 = 0xa5;
const FORCE_WRONG_DT_MAPPING: bool = false; // external negative build changes only this authored flag

use nextcore_core::{
    firmware_dt::FirmwareDeviceTree,
    guest_memory::{Error as LedgerError, GuestMemory, Purpose, ReservationToken},
    runtime_dt,
};

fn require(ok: bool) -> Result<(), Status> {
    if ok {
        Ok(())
    } else {
        Err(Status::COMPROMISED_DATA)
    }
}
fn checked<T, E>(result: Result<T, E>) -> Result<T, Status> {
    result.map_err(|_| Status::COMPROMISED_DATA)
}
fn disjoint(a: u64, n: u64, b: u64, m: u64) -> bool {
    match (a.checked_add(n), b.checked_add(m)) {
        (Some(x), Some(y)) => x <= b || y <= a,
        _ => false,
    }
}
fn address(ledger: &GuestMemory<'_>, token: ReservationToken) -> Result<u64, Status> {
    ledger
        .snapshot()
        .records()
        .find(|r| r.token() == token)
        .map(|r| r.extent().address())
        .ok_or(Status::NOT_FOUND)
}
fn hex(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut result = alloc::string::String::new();
    for b in bytes {
        let _ = write!(result, "{b:02x}");
    }
    result
}
fn authored_source() -> Vec<u8> {
    fn property(bytes: &mut Vec<u8>, name: &str, value: &[u8], flag: bool) {
        let mut key = [0; 32];
        key[..name.len()].copy_from_slice(name.as_bytes());
        bytes.extend(key);
        bytes.extend(((value.len() as u32) | if flag { 1 << 31 } else { 0 }).to_le_bytes());
        bytes.extend(value);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
    }
    let mut bytes = Vec::from([2u32.to_le_bytes(), 0u32.to_le_bytes()].concat());
    property(&mut bytes, "name", b"\0", false);
    property(
        &mut bytes,
        "authored-aperture",
        b"opaque/observed-extent()\0",
        true,
    );
    bytes
}
fn prepare<'a>(
    source: &'a [u8],
    ledger: &GuestMemory<'_>,
) -> Result<runtime_dt::MaterializedTree<'a>, Status> {
    let ids = checked(runtime_dt::template_ids(source))?;
    require(ids.len() == 1)?;
    let snapshot = ledger.snapshot();
    let value = [
        snapshot.aperture().address().to_le_bytes(),
        snapshot.aperture().bytes().to_le_bytes(),
    ]
    .concat();
    checked(runtime_dt::prepare(
        source,
        &[runtime_dt::ProvidedValue {
            property: ids[0],
            provider: "authored/efi-owned-ledger-v1",
            value: &value,
        }],
        runtime_dt::MAX_OUTPUT_BYTES,
    ))
}
fn instructions(value_offset: usize) -> Result<Vec<u32>, Status> {
    require(value_offset % 4 == 0 && value_offset + 12 <= 16380)?;
    let mut words = Vec::from([0x91000063]); // ADD X3,X3,#0
    for (out, offset) in [
        0,
        4,
        value_offset,
        value_offset + 4,
        value_offset + 8,
        value_offset + 12,
    ]
    .iter()
    .enumerate()
    {
        words.push(0xb9400002 | ((*offset as u32 / 4) << 10)); // LDR W2,[X0,#offset]
        words.push(0xb9000022 | ((out as u32) << 10)); // STR W2,[X1,#4*out]
    }
    words.extend([
        0x52800002 | (MARKER << 5),
        0xb9000022 | (6 << 10),
        0xd4400000,
    ]);
    Ok(words)
}
fn run_case(granule: usize, upper: bool, invalid: bool) -> Result<(), Status> {
    let name = if invalid { "invalid-dt" } else { "roundtrip" };
    let mut ram = ArmPages::allocate_data(16 * granule)?;
    let mut tables = ArmPages::allocate_data(16 * granule)?;
    let mut code = ArmPages::allocate(64 * 1024, None)?;
    let host_ram = ram.base();
    let host_tables = tables.base();
    let host_code = code.base();
    require(
        disjoint(
            host_ram,
            ram.bytes() as u64,
            host_tables,
            tables.bytes() as u64,
        ) && disjoint(host_ram, ram.bytes() as u64, host_code, code.bytes() as u64)
            && disjoint(
                host_tables,
                tables.bytes() as u64,
                host_code,
                code.bytes() as u64,
            )
            && disjoint(RAM_PA, ram.bytes() as u64, TABLE_PA, tables.bytes() as u64),
    )?;
    ram.bytes_mut().fill(GUARD);
    let mut ledger = checked(GuestMemory::from_borrowed(RAM_PA, ram.bytes_mut()))?;
    let guard = checked(ledger.allocate(granule as u64, granule as u64, Purpose::ProviderData))?;
    let guest_code =
        checked(ledger.allocate(granule as u64, granule as u64, Purpose::KernelImage))?;
    let dt = checked(ledger.allocate(granule as u64, granule as u64, Purpose::RuntimeDeviceTree))?;
    let stack = checked(ledger.allocate(granule as u64, granule as u64, Purpose::Stack))?;
    let output = checked(ledger.allocate(granule as u64, granule as u64, Purpose::ProviderData))?;
    let code_pa = address(&ledger, guest_code)?;
    let dt_pa = address(&ledger, dt)?;
    let stack_pa = address(&ledger, stack)?;
    let output_pa = address(&ledger, output)?;
    let aperture = ledger.aperture();
    let va_base = if upper { VA_HI } else { VA_LO };
    let va_for = |pa: u64| va_base + (pa - aperture.address());
    let entry = va_for(code_pa);
    let dt_va = va_for(dt_pa);
    let output_va = va_for(output_pa);
    let stack_top = va_for(stack_pa) + granule as u64;
    require(entry != code_pa && dt_va != dt_pa && output_va != output_pa)?;
    let source = authored_source();
    let source_before = source.clone();
    let wire = prepare(&source, &ledger)?.bytes().to_vec();
    let parsed = checked(FirmwareDeviceTree::parse(&wire))?;
    let property = parsed
        .root()
        .properties()
        .iter()
        .find(|p| p.name() == "authored-aperture")
        .ok_or(Status::NOT_FOUND)?;
    require(property.value().len() == 16)?;
    let value_offset = property.offset() + 36;
    let words = instructions(value_offset)?;
    let program: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    checked(ledger.copy_into(guest_code, 0, &program))?;
    let before_stale = checked(ledger.with_guest_memory(|_, ram| ram.to_vec()))?;
    let old = checked(ledger.bind_device_tree(
        ledger.snapshot().stamp(),
        dt,
        prepare(&source, &ledger)?,
    ))?;
    checked(ledger.release(guard))?;
    let stale_rejected = ledger.commit_device_tree(old) == Err(LedgerError::StaleSnapshot);
    let after_stale = checked(ledger.with_guest_memory(|_, ram| ram.to_vec()))?;
    require(stale_rejected && before_stale == after_stale)?;
    // No C JIT call exists before the stale rejection above.
    let prepared = checked(ledger.bind_device_tree(
        ledger.snapshot().stamp(),
        dt,
        prepare(&source, &ledger)?,
    ))?;
    require(prepared.bytes() == wire)?;
    checked(ledger.commit_device_tree(prepared))?;
    let mut expected = checked(ledger.with_guest_memory(|_, ram| ram.to_vec()))?;
    let mut expected_output = Vec::from(&wire[..8]);
    expected_output.extend_from_slice(&wire[value_offset..value_offset + 16]);
    expected_output.extend(MARKER.to_le_bytes());
    if !invalid {
        let off = (output_pa - aperture.address()) as usize;
        expected[off..off + 28].copy_from_slice(&expected_output);
    }
    {
        let mut builder = Tables {
            bytes: tables.bytes_mut(),
            granule,
            next: 2,
        };
        builder.map(entry, code_pa | 0x403)?;
        builder.map(
            dt_va,
            if invalid || FORCE_WRONG_DT_MAPPING {
                0
            } else {
                dt_pa | 0x403
            },
        )?;
        builder.map(output_va, output_pa | 0x403)?;
        builder.map(va_for(stack_pa), stack_pa | 0x403)?;
    }
    let tables_before = tables.bytes_mut().to_vec();
    let tsz = if granule == 16384 { 17 } else { 16 };
    let tcr = tsz
        | (tsz << 16)
        | if granule == 16384 {
            (2 << 14) | (1 << 30)
        } else {
            2 << 30
        };
    let controls = abi_v2::Controls {
        abi_version: 2,
        struct_size: 80,
        profile: 1,
        sctlr: 0x30d00803,
        ttbr0: TABLE_PA,
        ttbr1: TABLE_PA + granule as u64,
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
    let initial = [dt_va, output_va, 0x13579bdf, 0x2468ace0];
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
    let mut result = memory_boot_v2::MemoryRunResultV2::default();
    let status = checked(
        ledger.with_guest_memory(|base, ram| -> Result<i32, Status> {
            let size = ram.len() as u64;
            let mut service = checked(MemoryServiceV2::new(
                ram,
                base,
                tables.bytes_mut(),
                TABLE_PA,
                controls,
            ))?;
            // SAFETY: synchronous callback; service holds the exclusive RAM and
            // immutable table loans, all C records and owned code remain live/disjoint.
            Ok(unsafe {
                vf_boot_run_memory_v2(
                    base,
                    size,
                    entry,
                    initial[0],
                    stack_top,
                    code.bytes_mut().as_mut_ptr(),
                    code.bytes(),
                    32,
                    vf_efi_jit_protect,
                    opaque,
                    initial.as_ptr(),
                    &options,
                    &controls,
                    vf_memory_service_step_v2,
                    (&mut service as *mut MemoryServiceV2<'_>).cast(),
                    &mut result,
                )
            })
        }),
    )??;
    let restored = unsafe { vf_efi_jit_protect(code.base() as *mut _, code.bytes(), 0, opaque) };
    let observed = checked(ledger.with_guest_memory(|_, ram| ram.to_vec()))?;
    let output_offset = (output_pa - aperture.address()) as usize;
    let output_bytes = &observed[output_offset..output_offset + 28];
    let tables_unchanged = tables.bytes_mut() == tables_before;
    let ram_exact = observed == expected;
    let base = &result.base;
    let execution = &base.execution;
    let state = &execution.base;
    let retired = if invalid { 1 } else { 16 };
    let want_status = if invalid { 17 } else { 1 };
    let esr = if invalid { 0x96000007 } else { 0 };
    let far = if invalid { dt_va } else { 0 };
    let pass = restored == 0
        && status == want_status
        && state.status == want_status as u32
        && base.abi_version == 2
        && base.struct_size == 320
        && base.provider_status == 0
        && state.retired == retired
        && state.pc == entry + 4 * retired
        && state.compiled_blocks == if invalid { 2 } else { 16 }
        && state.x0 == dt_va
        && state.x1 == output_va
        && state.x2 == if invalid { initial[2] } else { MARKER as u64 }
        && state.x3 == initial[3]
        && execution.sp == stack_top
        && execution.esr == esr
        && base.guest_far == far
        && base.fetch_requests == if invalid { 2 } else { 16 }
        && base.data_requests == if invalid { 1 } else { 13 }
        && base.completed_data_operations == if invalid { 0 } else { 13 }
        && result.last_reply.result
            == if invalid {
                abi_v2::GUEST_FAULT
            } else {
                abi_v2::OK
            }
        && result.last_reply.fsc == if invalid { 7 } else { 0 }
        && state.fault_instruction == if invalid { words[1] } else { 0 }
        && (!invalid
            || (result.last_reply.level == 3
                && execution.elr == entry + 4
                && execution.spsr == 0x3c5
                && result.last_reply.address == dt_va
                && base.last_address == dt_va))
        && stale_rejected
        && ram_exact
        && tables_unchanged
        && source == source_before;
    report(&format!("NXDT: DATA name={name} granule={granule} upper={upper} source={} wire={} output={} value_offset={value_offset} ram_sha={} tables_before_sha={} tables_after_sha={}",
        hex(&source),hex(&wire),hex(output_bytes),hex(&runtime_dt::source_identity(&observed)),
        hex(&runtime_dt::source_identity(&tables_before)),hex(&runtime_dt::source_identity(tables.bytes_mut()))));
    report(&format!("NXDT: CASE name={name} granule={granule} upper={upper} status={status} provider={} retired={} blocks={} fetch={} data={} completed={} esr={:#x} far={:#x} reply={} fsc={} pc={:#x} x2={:#x} stale={} ram={} tables={} ram_pa={:#x} ram_bytes={} code_pa={:#x} dt_pa={:#x} stack_pa={:#x} output_pa={:#x} entry={:#x} dt_va={:#x} output_va={:#x} sp={:#x} ram_host={:#x} table_host={:#x} jit_host={:#x} pass={}",
        base.provider_status,state.retired,state.compiled_blocks,base.fetch_requests,base.data_requests,
        base.completed_data_operations,execution.esr,base.guest_far,result.last_reply.result,result.last_reply.fsc,
        state.pc,state.x2,stale_rejected,ram_exact,tables_unchanged,aperture.address(),aperture.bytes(),code_pa,dt_pa,stack_pa,output_pa,
        entry,dt_va,output_va,execution.sp,host_ram,host_tables,host_code,pass));
    require(pass)
}
#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::NOT_READY;
    }
    report("NXDT: ENTRY host=x86_64 authored=true profile=nextcore-stage1-fixed-nc-v1");
    if !cfg!(target_arch = "x86_64") {
        return Status::UNSUPPORTED;
    }
    let mut count = 0;
    for granule in [4096, 16384] {
        for upper in [false, true] {
            for invalid in [false, true] {
                if let Err(status) = run_case(granule, upper, invalid) {
                    report(&format!("NXDT: FAIL case={count} status={status:?}"));
                    return status;
                }
                count += 1;
            }
        }
    }
    report("NXDT: PASS cases=8 macos_boot_verified=false");
    Status::SUCCESS
}
