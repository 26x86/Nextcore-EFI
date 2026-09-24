//! Authored hierarchical-permission transactions in the actual x86 EFI JIT.
#![no_std]
#![no_main]
extern crate alloc;
mod arm_pages;
#[allow(dead_code)]
mod firmware_io;
include!(concat!(env!("OUT_DIR"), "/jit_pauth.rs"));
use alloc::format;
use arm_pages::ArmPages;
use core::ffi::c_void;
use firmware_io::report;
use nextcore_memory_service::{abi::{FETCH, LOAD, STORE}, abi_v2, stage1::{MemoryServiceV2, vf_memory_service_step_v2}};
use uefi::{entry, Status};

#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;
unsafe extern "C" {
    fn vf_efi_jit_protection_open(table:*mut c_void, storage:*mut c_void, bytes:usize)->i32;
    fn vf_efi_jit_protect(p:*mut c_void,n:usize,executable:i32,opaque:*mut c_void)->i32;
    fn vf_boot_run_memory_v2(base:u64,size:u64,entry:u64,args:u64,stack:u64,
        code:*mut u8,code_bytes:usize,budget:u64,
        protect:unsafe extern "C" fn(*mut c_void,usize,i32,*mut c_void)->i32,
        opaque:*mut c_void,initial:*const u64,options:*const platform::BootOptionsV2,
        controls:*const abi_v2::Controls,memory:abi_v2::Callback,owner:*mut c_void,
        result:*mut memory_boot_v2::MemoryRunResultV2)->i32;
}
const RAM_PA:u64=0x1000_0000;
const TABLE_PA:u64=0x3000_0000;
const LOW:u64=0x2000_0000;
const HIGH:u64=0xffff_8000_2000_0000;
const VALUE:u64=0x1122_3344_c0de_ab81;
// Reassembled from docs/fixtures/hierarchy_scalar.S by the verifier.
const WORDS:[u32;5]=[0xf9400002,0xd4400000,0xf9000001,0xd4400000,0xd4400000];

struct Tables<'a>{bytes:&'a mut[u8],granule:usize,next:usize}
impl Tables<'_>{
    fn map(&mut self,va:u64,leaf:u64,parent:u8,xn:u8,choice:usize)->Result<u64,Status>{
        let (page,bits,start) = if self.granule==16384{(14,11,1)}else{(12,9,0)};
        let mask=(1u64<<bits)-1;
        let mut table=if va>>63==0{0}else{self.granule};
        let ap_level=start+choice%(3-start);
        let xn_level=start+(choice+1)%(3-start);
        for level in start..=3 {
            let at=table+(((va>>(page+bits*(3-level)))&mask)as usize)*8;
            if at+8>self.bytes.len(){return Err(Status::BAD_BUFFER_SIZE);}
            if level==3 {
                self.bytes[at..at+8].copy_from_slice(&leaf.to_le_bytes());
                return Ok(TABLE_PA+at as u64);
            }
            let mut descriptor=u64::from_le_bytes(self.bytes[at..at+8].try_into().unwrap());
            if descriptor==0 {
                let next=self.next*self.granule;
                if next+self.granule>self.bytes.len(){return Err(Status::OUT_OF_RESOURCES);}
                self.next+=1;descriptor=(TABLE_PA+next as u64)|3;
            }
            if level==ap_level{descriptor|=u64::from(parent)<<61;}
            if level==xn_level{descriptor|=u64::from(xn)<<59;}
            self.bytes[at..at+8].copy_from_slice(&descriptor.to_le_bytes());
            let address_mask=if self.granule==4096{0x0000_ffff_ffff_f000}else{0x0000_ffff_ffff_c000};
            table=((descriptor&address_mask)-TABLE_PA)as usize;
        }
        Err(Status::COMPROMISED_DATA)
    }
}

// Independent expected rows: bit0 EL1 write, bit1 EL0 read, bit2 EL0 write,
// bit3 EL1 execute. EL1 read and EL0 execute are otherwise always permitted.
const MATRIX:[[u8;4];4]=[
    [9,9,8,8], [7,9,10,8], [8,8,8,8], [10,8,10,8],
];

fn run_case(id:usize,granule:usize,profile:u32,ap:u8,parent:u8,xn:u8,el:u32,warm:bool,op:u32)->Result<(),Status>{
    let upper=(ap^parent^(el as u8))&1!=0;
    let target=if upper{HIGH}else{LOW};
    // Data instructions execute through the opposite root, independent of target restrictions.
    let program=if upper{LOW}else{HIGH};
    let entry=if op==FETCH{target}else{program};
    let mut ram=ArmPages::allocate_data(16*granule)?;
    let mut tables=ArmPages::allocate_data(16*granule)?;
    let mut code=ArmPages::allocate(64*1024,None)?;
    let selected=if op==STORE{&WORDS[2..4]}else{&WORDS[0..2]};
    for(i,word)in selected.iter().enumerate(){ram.bytes_mut()[i*4..i*4+4].copy_from_slice(&word.to_le_bytes());}
    ram.bytes_mut()[4*granule..4*granule+4].copy_from_slice(&WORDS[4].to_le_bytes());
    let target_pa=RAM_PA+4*granule as u64;
    let descriptor_pa={
        let mut builder=Tables{bytes:tables.bytes_mut(),granule,next:2};
        builder.map(program,RAM_PA|0x403,0,0,0)?;
        builder.map(target,target_pa|0x403|(u64::from(ap)<<6),parent,xn,(ap+parent)as usize)?
    };
    let tables_before=tables.bytes_mut().to_vec();
    let mut expected_ram=ram.bytes_mut().to_vec();
    let row=MATRIX[ap as usize][parent as usize];
    let allowed=match op {
        LOAD=>el==1 || row&2!=0,
        STORE=>if el==1{row&1!=0}else{row&4!=0},
        _=>if el==1{row&8!=0 && xn&1==0}else{xn&2==0},
    };
    if allowed && op==STORE{expected_ram[4*granule..4*granule+8].copy_from_slice(&VALUE.to_le_bytes());}
    let tsz=if granule==16384{17}else{16};
    let tcr=tsz|(tsz<<16)|(5<<32)|if granule==16384{(2<<14)|(1<<30)}else{2<<30};
    let controls=abi_v2::Controls{abi_version:2,struct_size:80,profile,
        sctlr:if profile==1{0x30d00803}else{0x30d00801},ttbr0:TABLE_PA|(0x21<<48),
        ttbr1:(TABLE_PA+granule as u64)|(0x87<<48),tcr,mair:0x44,epoch:1,..Default::default()};
    let pstate=if el==0{0x3c0}else{0x3c5};
    let options=platform::BootOptionsV2{abi_version:2,struct_size:64,initial_pstate:pstate,..Default::default()};
    let initial=[target,VALUE,0x8877_6655_4433_2211,0x1020_3040_5060_7080];
    let mut expected_registers=initial;
    if allowed && op==LOAD{expected_registers[2]=u64::from(WORDS[4]);}
    let stack=program+8*granule as u64;
    let system=uefi::table::system_table_raw().ok_or(Status::NOT_READY)?;
    let mut protection=[0usize;2];let opaque=protection.as_mut_ptr().cast();
    // SAFETY: live firmware table and correctly aligned owned protection storage.
    if unsafe{vf_efi_jit_protection_open(system.as_ptr().cast(),opaque,core::mem::size_of_val(&protection))}!=0{return Err(Status::UNSUPPORTED);}
    let mut result=memory_boot_v2::MemoryRunResultV2::default();
    let status={
        let mut service=MemoryServiceV2::new(ram.bytes_mut(),RAM_PA,tables.bytes_mut(),TABLE_PA,controls).map_err(|_|Status::INVALID_PARAMETER)?;
        if warm{
            let request=abi_v2::Request{abi_version:2,struct_size:160,operation:LOAD,width:8,count:1,
                current_el:1,pstate:0x3c5,address:target,pc:program,controls,..Default::default()};
            if service.execute(&request).result!=abi_v2::OK{return Err(Status::COMPROMISED_DATA);}
        }
        // SAFETY: disjoint live owned allocations; callback is synchronous and retains no pointers.
        unsafe{vf_boot_run_memory_v2(RAM_PA,(16*granule)as u64,entry,initial[0],stack,
            code.bytes_mut().as_mut_ptr(),code.bytes(),8,vf_efi_jit_protect,opaque,initial.as_ptr(),
            &options,&controls,vf_memory_service_step_v2,(&mut service as *mut MemoryServiceV2<'_>).cast(),&mut result)}
    };
    // SAFETY: same retained code allocation and initialized protection owner.
    let restored=unsafe{vf_efi_jit_protect(code.base()as *mut _,code.bytes(),0,opaque)};
    let base=&result.base;let execution=&base.execution;let state=&execution.base;
    let retired=if allowed{if op==FETCH{1}else{2}}else{0};
    let expected_status=if allowed{1}else if op==FETCH{16}else{17};
    let expected_esr=if allowed{0}else{((u64::from(if op==FETCH{0x20+el}else{0x24+el}))<<26)|(1<<25)|15|if op==STORE{64}else{0}};
    let reply=&result.last_reply;
    let fault_ok=allowed || (reply.result==abi_v2::GUEST_FAULT && reply.fsc==15 && reply.level==3
        && reply.context==if warm{abi_v2::CACHED_LEAF}else{abi_v2::LEAF}
        && reply.descriptor_pa==descriptor_pa && reply.output_pa==target_pa && reply.address==target
        && execution.elr==entry && execution.spsr==pstate && base.guest_far==target);
    let passed=restored==0 && status==expected_status && state.status==expected_status as u32
        && state.retired==retired && state.pc==entry+4*retired
        && state.fault_instruction==if !allowed && op!=FETCH{selected[0]}else{0}
        && [state.x0,state.x1,state.x2,state.x3]==expected_registers && execution.sp==stack
        && execution.esr==expected_esr && base.provider_status==0
        && base.fetch_requests==retired+u64::from(!allowed)
        && base.data_requests==u64::from(op!=FETCH)
        && base.completed_data_operations==u64::from(allowed && op!=FETCH)
        && fault_ok && ram.bytes_mut()==expected_ram && tables.bytes_mut()==tables_before;
    report(&format!("NXPERM: CASE id={id} granule={granule} profile={profile} ap={ap} parent={parent} xn={xn} el={el} warm={warm} op={op} upper={upper} allowed={allowed} status={status} retired={} fetch={} data={} completed={} provider={} reply={} level={} context={} esr={:#x} pass={passed}",
        state.retired,base.fetch_requests,base.data_requests,base.completed_data_operations,base.provider_status,reply.result,reply.level,reply.context,execution.esr));
    if passed{Ok(())}else{Err(Status::COMPROMISED_DATA)}
}

#[entry]
fn main()->Status{
    if uefi::helpers::init().is_err(){return Status::NOT_READY;}
    report("NXPERM: ENTRY host=x86_64 authored=true profile=immutable-hierarchy");
    let mut id=0;
    // First case distinguishes implemented hierarchy from old unsupported table bits.
    if let Err(e)=run_case(id,4096,1,1,2,0,1,false,FETCH){report(&format!("NXPERM: FAIL completed={id} status={e:?}"));return e;}
    id+=1;
    for granule in [4096,16384]{for profile in [1,3]{
        for ap in 0..4{for parent in 0..4{for el in [0,1]{for warm in [false,true]{for op in [FETCH,LOAD,STORE]{
            if let Err(e)=run_case(id,granule,profile,ap,parent,0,el,warm,op){report(&format!("NXPERM: FAIL completed={id} status={e:?}"));return e;}id+=1;
        }}}}}
        for xn in [1,2]{for parent in [0,2]{for el in [0,1]{for warm in [false,true]{for op in [FETCH,LOAD,STORE]{
            if let Err(e)=run_case(id,granule,profile,1,parent,xn,el,warm,op){report(&format!("NXPERM: FAIL completed={id} status={e:?}"));return e;}id+=1;
        }}}}}
    }}
    report(&format!("NXPERM: PASS cases={id} physical_boot_verified=false macos_boot_verified=false"));Status::SUCCESS
}
