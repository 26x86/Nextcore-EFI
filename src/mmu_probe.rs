//! Independently authored immutable stage-1 native JIT proof inside x86 EFI.
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
    stage1::{MemoryServiceV2, vf_memory_service_step_v2},
};
use uefi::{Status, entry};

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

const RAM_PA: u64 = 0x1000_0000;
const TABLE_PA: u64 = 0x3000_0000;
const LEAF: u64 = 0x403;
const HLT: u32 = 0xd4400000;
const KEEP_X1: u32 = 0x91000021; // ADD X1,X1,#0: observable native ALU block.
const SEED: u64 = 0x8877_6655_ffee_aa80;
const VALUE: u64 = 0x1122_3344_c0de_ab81;
const PAIR0: u64 = 0xabcdef01_87654321;
const PAIR1: u64 = 0x76543210_fedcba98;

#[derive(Clone, Copy)]
enum Kind {
    Scalar {
        word: u32,
        width: usize,
        sign: u8,
        store: bool,
    },
    Pair {
        mode: u8,
        failure: u8,
        load: bool,
    },
    Fetch {
        permission: bool,
    },
    Unaligned {
        store: bool,
        failure: u8,
    },
}
#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    kind: Kind,
}
const SCALARS: [Case; 13] = [
    Case {
        name: "strb",
        kind: Kind::Scalar {
            word: 0x39000001,
            width: 1,
            sign: 0,
            store: true,
        },
    },
    Case {
        name: "ldrb",
        kind: Kind::Scalar {
            word: 0x39400001,
            width: 1,
            sign: 0,
            store: false,
        },
    },
    Case {
        name: "ldrsb-w",
        kind: Kind::Scalar {
            word: 0x39c00001,
            width: 1,
            sign: 32,
            store: false,
        },
    },
    Case {
        name: "ldrsb-x",
        kind: Kind::Scalar {
            word: 0x39800001,
            width: 1,
            sign: 64,
            store: false,
        },
    },
    Case {
        name: "strh",
        kind: Kind::Scalar {
            word: 0x79000001,
            width: 2,
            sign: 0,
            store: true,
        },
    },
    Case {
        name: "ldrh",
        kind: Kind::Scalar {
            word: 0x79400001,
            width: 2,
            sign: 0,
            store: false,
        },
    },
    Case {
        name: "ldrsh-w",
        kind: Kind::Scalar {
            word: 0x79c00001,
            width: 2,
            sign: 32,
            store: false,
        },
    },
    Case {
        name: "ldrsh-x",
        kind: Kind::Scalar {
            word: 0x79800001,
            width: 2,
            sign: 64,
            store: false,
        },
    },
    Case {
        name: "str-w",
        kind: Kind::Scalar {
            word: 0xb9000001,
            width: 4,
            sign: 0,
            store: true,
        },
    },
    Case {
        name: "ldr-w",
        kind: Kind::Scalar {
            word: 0xb9400001,
            width: 4,
            sign: 0,
            store: false,
        },
    },
    Case {
        name: "ldrsw",
        kind: Kind::Scalar {
            word: 0xb9800001,
            width: 4,
            sign: 64,
            store: false,
        },
    },
    Case {
        name: "str-x",
        kind: Kind::Scalar {
            word: 0xf9000001,
            width: 8,
            sign: 0,
            store: true,
        },
    },
    Case {
        name: "ldr-x",
        kind: Kind::Scalar {
            word: 0xf9400001,
            width: 8,
            sign: 0,
            store: false,
        },
    },
];

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

fn failure_descriptor(failure: u8, normal: u64) -> u64 {
    match failure {
        1 => 0,
        2 => normal & !(1 << 10),
        3 => normal | (1 << 7),
        4 => 0x5000_0000 | LEAF,
        5 => normal | (1 << 2),
        _ => normal,
    }
}

fn run_case(case: Case, granule: usize, upper: bool) -> Result<(), Status> {
    let va = if upper {
        0xffff_8000_2000_0000
    } else {
        0x2000_0000
    };
    let data_va = va + 4 * granule as u64;
    let split_va = data_va + granule as u64 - 8;
    let first_pa = RAM_PA + 4 * granule as u64;
    let second_pa = RAM_PA + 9 * granule as u64;
    let mut ram = ArmPages::allocate_data(16 * granule)?;
    let mut tables = ArmPages::allocate_data(16 * granule)?;
    let mut code = ArmPages::allocate(64 * 1024, None)?;
    let mut initial = [data_va, VALUE, PAIR0, PAIR1];
    let mut expected_registers = initial;
    let mut instructions = Vec::from([KEEP_X1]);
    let mut expected_status = 1;
    let mut expected_retired = 3;
    let mut expected_provider = 0;
    let mut expected_fsc = 0;
    let mut expected_reply = abi_v2::OK;
    let mut expected_far = 0;
    let mut expected_data = 1;
    let mut expected_completed = 1;
    let mut second_descriptor = second_pa | LEAF;
    let mut code_descriptor = RAM_PA | LEAF;
    let mut failure_load = false;
    match case.kind {
        Kind::Scalar {
            word,
            width,
            sign,
            store,
        } => {
            instructions.push(word);
            let raw = if width == 8 {
                SEED
            } else {
                SEED & ((1u64 << (width * 8)) - 1)
            };
            if !store {
                let value = if sign == 0 {
                    raw
                } else {
                    ((raw << ((8 - width) * 8)) as i64 >> ((8 - width) * 8)) as u64
                };
                expected_registers[1] = if sign == 32 {
                    u64::from(value as u32)
                } else {
                    value
                };
            }
        }
        Kind::Pair {
            mode,
            failure,
            load,
        } => {
            initial[0] = if mode == 1 { split_va - 8 } else { split_va };
            expected_registers = initial;
            second_descriptor = failure_descriptor(failure, second_descriptor);
            if failure == 0 {
                // Authored STP/LDP X2,X3 with offset, pre-index or post-index X0.
                instructions.push(match mode {
                    1 => 0xa9808c02,
                    2 => 0xa8810c02,
                    _ => 0xa9000c02,
                });
                instructions.push(if mode == 2 { 0xa97f0c02 } else { 0xa9400c02 });
                expected_registers[0] = initial[0]
                    + match mode {
                        1 => 8,
                        2 => 16,
                        _ => 0,
                    };
                expected_retired = 4;
                expected_data = 2;
                expected_completed = 2;
            } else {
                instructions.push(if load { 0xa9400c02 } else { 0xa9000c02 });
                expected_retired = 1;
                expected_data = 1;
                expected_completed = 0;
                failure_load = load;
                expected_far = data_va + granule as u64;
                if failure <= 3 {
                    expected_status = 17;
                    expected_reply = abi_v2::GUEST_FAULT;
                    expected_fsc = match failure {
                        1 => 7,
                        2 => 11,
                        _ => 15,
                    };
                } else {
                    expected_status = 4;
                    expected_provider = if failure == 4 { 5 } else { 1 };
                    expected_reply = if failure == 4 {
                        abi_v2::UNAVAILABLE
                    } else {
                        abi_v2::UNSUPPORTED
                    };
                }
            }
        }
        Kind::Fetch { permission } => {
            code_descriptor = if permission {
                RAM_PA | LEAF | (1 << 53)
            } else {
                0
            };
            expected_status = 16;
            expected_retired = 0;
            expected_data = 0;
            expected_completed = 0;
            expected_reply = abi_v2::GUEST_FAULT;
            expected_fsc = if permission { 15 } else { 7 };
            expected_far = va;
        }
        Kind::Unaligned { store, failure } => {
            // Split one ordinary 8-byte transfer across nonadjacent pages.
            initial[0] = data_va + granule as u64 - 4;
            expected_registers = initial;
            instructions.push(if store { 0xf9000001 } else { 0xf9400001 });
            second_descriptor = failure_descriptor(failure, second_descriptor);
            if failure == 0 {
                if !store {
                    expected_registers[1] = SEED;
                }
            } else {
                expected_retired = 1;
                expected_completed = 0;
                failure_load = !store;
                expected_far = data_va + granule as u64;
                if failure <= 3 {
                    expected_status = 17;
                    expected_reply = abi_v2::GUEST_FAULT;
                    expected_fsc = match failure {
                        1 => 7,
                        2 => 11,
                        _ => 15,
                    };
                } else {
                    expected_status = 4;
                    expected_provider = if failure == 4 { 5 } else { 1 };
                    expected_reply = if failure == 4 {
                        abi_v2::UNAVAILABLE
                    } else {
                        abi_v2::UNSUPPORTED
                    };
                }
            }
        }
    }
    instructions.push(HLT);
    for (index, word) in instructions.iter().enumerate() {
        ram.bytes_mut()[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    ram.bytes_mut()[4 * granule..4 * granule + 8].copy_from_slice(&SEED.to_le_bytes());
    let split = 5 * granule - 8;
    ram.bytes_mut()[split..split + 8].copy_from_slice(&SEED.to_le_bytes());
    ram.bytes_mut()[9 * granule..9 * granule + 8].copy_from_slice(&VALUE.to_le_bytes());
    if matches!(case.kind, Kind::Unaligned { .. }) {
        ram.bytes_mut()[5 * granule - 4..5 * granule].copy_from_slice(&SEED.to_le_bytes()[..4]);
        ram.bytes_mut()[9 * granule..9 * granule + 4].copy_from_slice(&SEED.to_le_bytes()[4..]);
    }
    let mut expected_ram = ram.bytes_mut().to_vec();
    match case.kind {
        Kind::Scalar {
            width, store: true, ..
        } => expected_ram[4 * granule..4 * granule + width]
            .copy_from_slice(&VALUE.to_le_bytes()[..width]),
        Kind::Pair { failure: 0, .. } => {
            expected_ram[split..split + 8].copy_from_slice(&PAIR0.to_le_bytes());
            expected_ram[9 * granule..9 * granule + 8].copy_from_slice(&PAIR1.to_le_bytes());
        }
        Kind::Unaligned {
            store: true,
            failure: 0,
        } => {
            expected_ram[5 * granule - 4..5 * granule].copy_from_slice(&VALUE.to_le_bytes()[..4]);
            expected_ram[9 * granule..9 * granule + 4].copy_from_slice(&VALUE.to_le_bytes()[4..]);
        }
        _ => {}
    }
    {
        let mut builder = Tables {
            bytes: tables.bytes_mut(),
            granule,
            next: 2,
        };
        builder.map(va, code_descriptor)?;
        builder.map(data_va, first_pa | LEAF)?;
        builder.map(data_va + granule as u64, second_descriptor)?;
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
        profile: if matches!(case.kind, Kind::Unaligned { .. }) {
            abi_v2::PROFILE_FIXED_NC_UNALIGNED
        } else {
            abi_v2::PROFILE_FIXED_NC
        },
        sctlr: if matches!(case.kind, Kind::Unaligned { .. }) {
            0x30d00801
        } else {
            0x30d00803
        },
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
    let stack = data_va + 2 * granule as u64;
    let system = uefi::table::system_table_raw().ok_or(Status::NOT_READY)?;
    let mut protection = [0usize; 2];
    let opaque = protection.as_mut_ptr().cast();
    // SAFETY: live firmware system table and aligned C-owned protection record.
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
    let status = {
        let mut service = MemoryServiceV2::new(
            ram.bytes_mut(),
            RAM_PA,
            tables.bytes_mut(),
            TABLE_PA,
            controls,
        )
        .map_err(|_| Status::INVALID_PARAMETER)?;
        // SAFETY: service retains the exclusive RAM and immutable table borrows.
        // Code, controls, initial state, result and protection records are disjoint.
        // The callback is synchronous and only emitted x86 instructions execute.
        unsafe {
            vf_boot_run_memory_v2(
                RAM_PA,
                (16 * granule) as u64,
                va,
                initial[0],
                stack,
                code.bytes_mut().as_mut_ptr(),
                code.bytes(),
                16,
                vf_efi_jit_protect,
                opaque,
                initial.as_ptr(),
                &options,
                &controls,
                vf_memory_service_step_v2,
                (&mut service as *mut MemoryServiceV2<'_>).cast(),
                &mut result,
            )
        }
    };
    let restored = unsafe { vf_efi_jit_protect(code.base() as *mut _, code.bytes(), 0, opaque) };
    let base = &result.base;
    let execution = &base.execution;
    let state = &execution.base;
    let actual_registers = [state.x0, state.x1, state.x2, state.x3];
    let expected_pc = va + 4 * expected_retired;
    let expected_esr = if expected_reply == abi_v2::GUEST_FAULT {
        if expected_status == 16 {
            0x86000000 | expected_fsc
        } else {
            0x96000000 | expected_fsc | if failure_load { 0 } else { 64 }
        }
    } else {
        0
    };
    let observed_far = if expected_reply == abi_v2::GUEST_FAULT {
        expected_far
    } else {
        0
    };
    let passed = restored == 0
        && status == expected_status
        && state.status == expected_status as u32
        && base.abi_version == 2
        && base.struct_size == 320
        && base.provider_status == expected_provider
        && state.retired == expected_retired
        && state.pc == expected_pc
        && state.fault_instruction
            == if expected_status == 17 {
                instructions[1]
            } else {
                0
            }
        && actual_registers == expected_registers
        && execution.sp == stack
        && execution.esr == expected_esr
        && base.guest_far == observed_far
        && base.fetch_requests == expected_retired + u64::from(expected_status != 1)
        && base.data_requests == expected_data
        && base.completed_data_operations == expected_completed
        && ((expected_retired == 0 && state.compiled_blocks == 0)
            || (expected_retired > 0 && state.compiled_blocks > 0))
        && result.last_reply.result == expected_reply
        && result.last_reply.fsc == expected_fsc as u32
        && (expected_reply != abi_v2::GUEST_FAULT
            || (result.last_reply.level == 3
                && execution.elr == expected_pc
                && execution.spsr == 0x3c5))
        && (expected_reply == abi_v2::OK || result.last_reply.address == expected_far)
        && (expected_reply == abi_v2::OK || base.last_address == expected_far)
        && ram.bytes_mut() == expected_ram
        && tables.bytes_mut() == tables_before;
    report(&format!(
        "NXMMU: CASE name={} granule={} upper={} status={} provider={} retired={} blocks={} fetch={} data={} completed={} esr={:#x} far={:#x} reply={} fsc={} pass={}",
        case.name,
        granule,
        upper,
        status,
        base.provider_status,
        state.retired,
        state.compiled_blocks,
        base.fetch_requests,
        base.data_requests,
        base.completed_data_operations,
        execution.esr,
        base.guest_far,
        result.last_reply.result,
        result.last_reply.fsc,
        passed
    ));
    if !passed {
        report(&format!(
            "NXMMU: MISMATCH_ABI version={} size={} fault={:#x} elr={:#x} spsr={:#x} sp={:#x} last={:#x} level={} context={} restore={}",
            base.abi_version,
            base.struct_size,
            state.fault_instruction,
            execution.elr,
            execution.spsr,
            execution.sp,
            base.last_address,
            result.last_reply.level,
            result.last_reply.context,
            restored
        ));
        report(&format!(
            "NXMMU: MISMATCH pc={:#x} expected_pc={:#x} registers={actual_registers:x?} expected={expected_registers:x?} ram={} tables={}",
            state.pc,
            expected_pc,
            ram.bytes_mut() == expected_ram,
            tables.bytes_mut() == tables_before
        ));
        return Err(Status::COMPROMISED_DATA);
    }
    Ok(())
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::NOT_READY;
    }
    report("NXMMU: ENTRY host=x86_64 profile=nextcore-stage1-fixed-nc-v1 authored=true");
    if !cfg!(target_arch = "x86_64") {
        return Status::UNSUPPORTED;
    }
    let mut count = 0;
    for granule in [4096, 16384] {
        for upper in [false, true] {
            let mut cases = Vec::from(SCALARS);
            for (mode, name) in [(0, "pair-offset"), (1, "pair-pre"), (2, "pair-post")] {
                cases.push(Case {
                    name,
                    kind: Kind::Pair {
                        mode,
                        failure: 0,
                        load: false,
                    },
                });
            }
            for (failure, store, load) in [
                (1, "pair-store-translation", "pair-load-translation"),
                (2, "pair-store-af", "pair-load-af"),
                (4, "pair-store-backing", "pair-load-backing"),
                (5, "pair-store-attribute", "pair-load-attribute"),
            ] {
                cases.push(Case {
                    name: store,
                    kind: Kind::Pair {
                        mode: 0,
                        failure,
                        load: false,
                    },
                });
                cases.push(Case {
                    name: load,
                    kind: Kind::Pair {
                        mode: 0,
                        failure,
                        load: true,
                    },
                });
            }
            cases.push(Case {
                name: "pair-store-permission",
                kind: Kind::Pair {
                    mode: 0,
                    failure: 3,
                    load: false,
                },
            });
            cases.push(Case {
                name: "fetch-translation",
                kind: Kind::Fetch { permission: false },
            });
            cases.push(Case {
                name: "fetch-permission",
                kind: Kind::Fetch { permission: true },
            });
            for (failure, store, load) in [
                (0, "unaligned-store", "unaligned-load"),
                (
                    1,
                    "unaligned-store-translation",
                    "unaligned-load-translation",
                ),
                (2, "unaligned-store-af", "unaligned-load-af"),
                (4, "unaligned-store-backing", "unaligned-load-backing"),
                (5, "unaligned-store-attribute", "unaligned-load-attribute"),
            ] {
                cases.push(Case {
                    name: store,
                    kind: Kind::Unaligned {
                        store: true,
                        failure,
                    },
                });
                cases.push(Case {
                    name: load,
                    kind: Kind::Unaligned {
                        store: false,
                        failure,
                    },
                });
            }
            cases.push(Case {
                name: "unaligned-store-permission",
                kind: Kind::Unaligned {
                    store: true,
                    failure: 3,
                },
            });
            for case in cases {
                if let Err(error) = run_case(case, granule, upper) {
                    report(&format!("NXMMU: FAIL completed={count} status={error:?}"));
                    return error;
                }
                count += 1;
            }
        }
    }
    report(&format!(
        "NXMMU: PASS cases={count} macos_boot_verified=false"
    ));
    Status::SUCCESS
}
