//! Independently authored eight-bit ASID and MMFR0 native JIT proof inside x86 EFI.
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
const VALUE: u64 = 0x1122_3344_c0de_ab81;
const LOW: u64 = 0x2000_0000;
const HIGH: u64 = 0xffff_8000_2000_0000;
// Exact LLVM18 assembly of docs/fixtures/asid_scalar.S; verifier reassembles it.
const WORDS: [u32; 10] = [0xf9000002, 0xf9400023, 0xeb02007f, 0x540000c1, 0xd5380700, 0xd5382041, 0xd5382002, 0xd5382023, 0xd4400000, 0x14000000];
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


fn run_case(granule: usize, profile: u32, upper: bool, a1: bool, tag: u64) -> Result<(), Status> {
    let mut ram=ArmPages::allocate(16*granule,None)?;
    let mut tables=ArmPages::allocate(16*granule,None)?;
    let mut code=ArmPages::allocate(64*1024,None)?;
    ram.bytes_mut().fill(0); tables.bytes_mut().fill(0);
    for (i,word) in WORDS.iter().enumerate() {
        ram.bytes_mut()[i*4..i*4+4].copy_from_slice(&word.to_le_bytes());
    }
    let low_data=LOW+4*granule as u64;
    let high_data=HIGH+4*granule as u64;
    {
        let mut builder=Tables{bytes:tables.bytes_mut(),granule,next:2};
        for va in [LOW,HIGH] {
            builder.map(va,RAM_PA|LEAF)?;
            builder.map(va+4*granule as u64,(RAM_PA+4*granule as u64)|LEAF)?;
        }
    }
    let tables_before=tables.bytes_mut().to_vec();
    let mut expected_ram=ram.bytes_mut().to_vec();
    expected_ram[4*granule..4*granule+8].copy_from_slice(&VALUE.to_le_bytes());
    let tsz=if granule==16384 {17} else {16};
    let tcr=tsz|(tsz<<16)|(5<<32)|(u64::from(a1)<<22)|
        if granule==16384 {(2<<14)|(1<<30)} else {2<<30};
    let tag1=tag^0xff;
    let controls=abi_v2::Controls{abi_version:2,struct_size:80,profile,
        sctlr:if profile==1 {0x30d00803} else {0x30d00801},
        ttbr0:TABLE_PA|(tag<<48),ttbr1:(TABLE_PA+granule as u64)|(tag1<<48),
        tcr,mair:0x44,epoch:1,..Default::default()};
    let initial=[low_data,high_data,VALUE,0];
    let options=platform::BootOptionsV2{abi_version:2,struct_size:64,initial_pstate:0x3c5,..Default::default()};
    let entry=if upper {HIGH} else {LOW};
    let stack=low_data+granule as u64;
    let system=uefi::table::system_table_raw().ok_or(Status::NOT_READY)?;
    let mut protection=[0usize;2];
    let opaque=protection.as_mut_ptr().cast();
    // SAFETY: live firmware system table and aligned C-owned protection record.
    if unsafe {vf_efi_jit_protection_open(system.as_ptr().cast(),opaque,
        core::mem::size_of_val(&protection))}!=0 {return Err(Status::UNSUPPORTED);}
    let mut result=memory_boot_v2::MemoryRunResultV2::default();
    let status={
        let mut service=MemoryServiceV2::new(ram.bytes_mut(),RAM_PA,tables.bytes_mut(),TABLE_PA,controls)
            .map_err(|_|Status::INVALID_PARAMETER)?;
        // SAFETY: unique disjoint live RAM/code/tables/records; synchronous callback.
        unsafe {vf_boot_run_memory_v2(RAM_PA,(16*granule) as u64,entry,initial[0],stack,
            code.bytes_mut().as_mut_ptr(),code.bytes(),32,vf_efi_jit_protect,opaque,
            initial.as_ptr(),&options,&controls,vf_memory_service_step_v2,
            (&mut service as *mut MemoryServiceV2<'_>).cast(),&mut result)}
    };
    // SAFETY: same retained code allocation and initialized protection owner.
    let restored=unsafe {vf_efi_jit_protect(code.base() as *mut _,code.bytes(),0,opaque)};
    let base=&result.base; let execution=&base.execution; let state=&execution.base;
    let registers=[state.x0,state.x1,state.x2,state.x3];
    let passed=restored==0 && status==1 && state.status==1 && state.retired==9
        && state.pc==entry+36 && state.fault_instruction==0 && state.compiled_blocks>0
        && registers==[0x0f100005,tcr,controls.ttbr0,controls.ttbr1]
        && execution.sp==stack && execution.esr==0 && base.abi_version==2 && base.struct_size==320
        && base.provider_status==0 && base.fetch_requests==9 && base.data_requests==2
        && base.completed_data_operations==2 && result.last_reply.result==0
        && ram.bytes_mut()==expected_ram && tables.bytes_mut()==tables_before;
    report(&format!("NXASID: CASE granule={granule} profile={profile} upper={upper} a1={a1} tag0={tag} tag1={tag1} status={status} retired={} fetch={} data={} completed={} provider={} mmfr0={:#x} tcr={:#x} ttbr0={:#x} ttbr1={:#x} pass={passed}",
        state.retired,base.fetch_requests,base.data_requests,base.completed_data_operations,
        base.provider_status,registers[0],registers[1],registers[2],registers[3]));
    if passed {Ok(())} else {Err(Status::COMPROMISED_DATA)}
}

#[entry]
fn main()->Status {
    if uefi::helpers::init().is_err() {return Status::NOT_READY;}
    report("NXASID: ENTRY host=x86_64 authored=true profile=immutable-asid8-el1");
    if !cfg!(target_arch="x86_64") {return Status::UNSUPPORTED;}
    let mut count=0;
    for granule in [4096,16384] {for profile in [1,3] {for upper in [false,true] {
        for a1 in [false,true] {for tag in [0,1,127,255] {
            if let Err(error)=run_case(granule,profile,upper,a1,tag) {
                report(&format!("NXASID: FAIL completed={count} status={error:?}")); return error;
            }
            count+=1;
        }}
    }}}
    report(&format!("NXASID: PASS cases={count} physical_boot_verified=false macos_boot_verified=false"));
    Status::SUCCESS
}
