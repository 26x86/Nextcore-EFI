//! Owned firmware pages with 16 KiB-aligned usable ranges and map validation.
use core::{ptr::NonNull, slice};
use uefi::{
    boot::{self, AllocateType},
    mem::memory_map::{MemoryMap, MemoryType},
    Status,
};

pub struct ArmPages {
    original: NonNull<u8>,
    count: usize,
    base: u64,
    bytes: usize,
    memory_type: MemoryType,
}
impl ArmPages {
    pub fn allocate(bytes: usize, fixed: Option<u64>) -> Result<Self, Status> {
        Self::allocate_kind(bytes, fixed, MemoryType::LOADER_CODE)
    }
    pub fn allocate_data(bytes: usize) -> Result<Self, Status> {
        Self::allocate_kind(bytes, None, MemoryType::LOADER_DATA)
    }
    fn allocate_kind(
        bytes: usize,
        fixed: Option<u64>,
        memory_type: MemoryType,
    ) -> Result<Self, Status> {
        if bytes == 0
            || bytes % 16384 != 0
            || bytes > isize::MAX as usize
            || fixed.is_some_and(|base| base == 0 || base % 16384 != 0)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let count = bytes
            .checked_div(4096)
            .and_then(|n| n.checked_add(if fixed.is_some() { 0 } else { 3 }))
            .ok_or(Status::OUT_OF_RESOURCES)?;
        let original = boot::allocate_pages(
            fixed.map_or(AllocateType::AnyPages, AllocateType::Address),
            memory_type,
            count,
        )
        .map_err(|e| e.status())?;
        let start = original.as_ptr() as usize as u64;
        // Establish ownership before any calculation can reject firmware data.
        let mut owner = Self {
            original,
            count,
            base: start,
            bytes,
            memory_type,
        };
        let base = start.checked_add(16383).ok_or(Status::OUT_OF_RESOURCES)? & !16383;
        owner.base = base;
        let allocation_end = start
            .checked_add((count * 4096) as u64)
            .ok_or(Status::COMPROMISED_DATA)?;
        if fixed.is_some_and(|expected| expected != base)
            || base
                .checked_add(bytes as u64)
                .is_none_or(|end| end > allocation_end)
        {
            return Err(Status::COMPROMISED_DATA);
        }
        let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|e| e.status())?;
        owner.validate_map(&map)?;
        // SAFETY: owner holds the exact allocation, range was verified above.
        unsafe {
            (base as *mut u8).write_bytes(0, bytes);
        }
        Ok(owner)
    }
    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the exclusive owner initialized and retains this full range.
        unsafe { slice::from_raw_parts_mut(self.base as *mut u8, self.bytes) }
    }
    pub fn validate_map(&self, map: &impl MemoryMap) -> Result<(), Status> {
        let meta = map.meta();
        if meta.desc_version != 1
            || meta.desc_size < core::mem::size_of::<uefi::boot::MemoryDescriptor>()
            || meta.map_size == 0
            || meta.map_size % meta.desc_size != 0
            || meta.map_size / meta.desc_size > 4096
        {
            return Err(Status::COMPROMISED_DATA);
        }
        let end = self
            .base
            .checked_add(self.bytes as u64)
            .ok_or(Status::COMPROMISED_DATA)?;
        let mut total = 0u64;
        for d in map.entries() {
            let limit = d
                .phys_start
                .checked_add(
                    d.page_count
                        .checked_mul(4096)
                        .ok_or(Status::COMPROMISED_DATA)?,
                )
                .ok_or(Status::COMPROMISED_DATA)?;
            let lo = self.base.max(d.phys_start);
            let hi = end.min(limit);
            if lo < hi {
                if d.ty != self.memory_type || d.phys_start % 4096 != 0 {
                    return Err(Status::COMPROMISED_DATA);
                }
                total = total.checked_add(hi - lo).ok_or(Status::COMPROMISED_DATA)?;
            }
        }
        if total != self.bytes as u64 {
            return Err(Status::COMPROMISED_DATA);
        }
        let mut cursor = self.base;
        for _ in 0..4096 {
            if cursor == end {
                return Ok(());
            }
            let mut next = cursor;
            for d in map.entries() {
                let limit = d.phys_start + d.page_count * 4096;
                if d.phys_start <= cursor && cursor < limit {
                    next = next.max(limit.min(end));
                }
            }
            if next == cursor {
                return Err(Status::COMPROMISED_DATA);
            }
            cursor = next;
        }
        Err(Status::COMPROMISED_DATA)
    }
}
impl Drop for ArmPages {
    fn drop(&mut self) {
        // SAFETY: original pointer/count have one private owner, and no slice
        // may survive this destructor. The EBS path wraps this owner first.
        let _ = unsafe { boot::free_pages(self.original, self.count) };
    }
}
