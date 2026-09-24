//! EL1 identity-map preflight and architecture-only handoff. No firmware calls.
use core::arch::{asm, global_asm};
use uefi::Status;
global_asm!(include_str!("arm_transition.S"));
unsafe extern "C" {
    fn nxc_arm_enter(args: u64, entry: u64, stack: u64) -> !;
    static nxc_arm_enter_end: u8;
}

fn identity(address: u64) -> bool {
    let translated: u64;
    // SAFETY: called only at EL1 with Boot Services active. Translation probes
    // update PAR but do not read/write the pointed-to memory or change mappings.
    unsafe {
        asm!("at s1e1r, {address}", "isb", "mrs {translated}, par_el1",
            address = in(reg) address, translated = out(reg) translated,
            options(nostack, preserves_flags));
    }
    translated & 1 == 0 && (translated & 0x0000_ffff_ffff_f000) == address & !4095
}

pub fn preflight(base: u64, bytes: usize) -> Result<(), Status> {
    let el: u64;
    unsafe {
        asm!("mrs {0}, CurrentEL", out(reg) el, options(nomem, nostack));
    }
    if el != 4 {
        return Err(Status::UNSUPPORTED);
    }
    let sctlr: u64;
    let features: u64;
    unsafe {
        asm!("mrs {0}, sctlr_el1", "mrs {1}, id_aa64mmfr2_el1",
        out(reg) sctlr, out(reg) features, options(nomem, nostack));
    }
    if sctlr & (1 << 25) != 0 || (features >> 20) & 15 != 0 {
        return Err(Status::UNSUPPORTED);
    }
    let end = base
        .checked_add(bytes as u64)
        .ok_or(Status::INVALID_PARAMETER)?;
    if bytes == 0 || base % 4096 != 0 || bytes % 4096 != 0 || end > (1u64 << 48) {
        return Err(Status::INVALID_PARAMETER);
    }
    if sctlr & 1 != 0 {
        for page in (base..end).step_by(4096) {
            if !identity(page) {
                return Err(Status::UNSUPPORTED);
            }
        }
        let code_start = nxc_arm_enter as *const () as usize as u64;
        let code_end = core::ptr::addr_of!(nxc_arm_enter_end) as usize as u64;
        for page in ((code_start & !4095)..=code_end).step_by(4096) {
            if !identity(page) {
                return Err(Status::UNSUPPORTED);
            }
        }
    }
    Ok(())
}

/// Caller has exited Boot Services, retained all page owners, revalidated the
/// final allocation map, and must never return or run an allocator/destructor.
pub unsafe fn enter(args: u64, entry: u64, stack: u64) -> ! {
    unsafe { nxc_arm_enter(args, entry, stack) }
}

pub fn halt() -> ! {
    loop {
        unsafe {
            asm!("msr daifset, #15", "wfi", options(nomem, nostack));
        }
    }
}
