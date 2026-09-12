//! Allocation-free metadata observation around the unchanged physical memory service.
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use nextcore_memory_service::{
    abi::{Reply, Request},
    MemoryService,
};

pub const CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub sequence: u64,
    pub operation: u32,
    pub pc: u64,
    pub address: u64,
    pub width: u32,
    pub count: u32,
    pub result: u32,
}

pub struct ObservedMemory<'a> {
    service: MemoryService<'a>,
    ring: [Entry; CAPACITY],
    next: usize,
    len: usize,
    total: u64,
}

impl<'a> ObservedMemory<'a> {
    pub fn new(service: MemoryService<'a>) -> Self {
        Self {
            service,
            ring: [Entry::default(); CAPACITY],
            next: 0,
            len: 0,
            total: 0,
        }
    }

    pub fn execute(&mut self, request: &Request) -> Reply {
        let reply = self.service.execute(request);
        self.total = self.total.saturating_add(1);
        self.ring[self.next] = Entry {
            sequence: self.total,
            operation: request.operation,
            pc: request.pc,
            address: request.address,
            width: request.width,
            count: request.count,
            result: reply.result,
        };
        self.next = (self.next + 1) % CAPACITY;
        self.len = (self.len + 1).min(CAPACITY);
        reply
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        let first = if self.len == CAPACITY { self.next } else { 0 };
        (0..self.len).map(move |offset| &self.ring[(first + offset) % CAPACITY])
    }

    pub const fn total(&self) -> u64 {
        self.total
    }
}

/// Forward the existing ABI through the observing owner; no output or allocation.
///
/// # Safety
/// The owner must point to a live uniquely borrowed ObservedMemory. Request is
/// an initialized readable full Request; reply is writable for one full Reply.
/// All pointers must have their type's alignment and valid provenance. These
/// objects are separate and overlap neither RAM/code nor each other. The owner,
/// its borrowed RAM and both records remain live with no concurrent access or
/// reentrancy until return. Null/misaligned inputs are rejected before access.
pub unsafe extern "C" fn callback(
    owner: *mut c_void,
    request: *const Request,
    reply: *mut Reply,
) -> i32 {
    if owner.is_null()
        || request.is_null()
        || reply.is_null()
        || !(owner as usize).is_multiple_of(core::mem::align_of::<ObservedMemory<'_>>())
        || !(request as usize).is_multiple_of(core::mem::align_of::<Request>())
        || !(reply as usize).is_multiple_of(core::mem::align_of::<Reply>())
    {
        return -1;
    }
    // SAFETY: Caller provides a valid initialized non-overlapping request record.
    let request = unsafe { request.read() };
    // SAFETY: Caller exclusively owns this live wrapper and its RAM for the call.
    let result = unsafe { (&mut *owner.cast::<ObservedMemory<'_>>()).execute(&request) };
    // SAFETY: Caller provides a separate aligned writable full reply record.
    unsafe { reply.write(result) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextcore_memory_service::abi::*;

    fn request(operation: u32, address: u64) -> Request {
        Request {
            abi_version: ABI_VERSION,
            struct_size: 80,
            operation,
            pc: address,
            address,
            width: 4,
            count: 1,
            current_el: 1,
            ..Request::default()
        }
    }

    fn same_reply(a: Reply, b: Reply) {
        assert_eq!(
            (
                a.abi_version,
                a.struct_size,
                a.result,
                a.fault,
                a.value0,
                a.value1,
                a.address,
                a.esr,
                a.epoch,
                a.reserved
            ),
            (
                b.abi_version,
                b.struct_size,
                b.result,
                b.fault,
                b.value0,
                b.value1,
                b.address,
                b.esr,
                b.epoch,
                b.reserved
            )
        );
    }

    #[test]
    fn replies_and_ram_match_plain_service_for_success_and_rejections() {
        let mut plain_ram = [0xa5; 64];
        let mut observed_ram = plain_ram;
        {
            let mut plain = MemoryService::new(&mut plain_ram, 0x4000).unwrap();
            let mut observed =
                ObservedMemory::new(MemoryService::new(&mut observed_ram, 0x4000).unwrap());
            let mut store = request(STORE, 0x4010);
            store.count = 2;
            store.value0 = 0x12345678;
            store.value1 = 0x89abcdef;
            let mut invalid = store;
            invalid.width = 3;
            for r in [
                request(FETCH, 0x4000),
                store,
                request(LOAD, 0x4010),
                invalid,
                request(FETCH, 0x4001),
                request(LOAD, 0x4040),
            ] {
                let expected = plain.execute(&r);
                let actual = observed.execute(&r);
                same_reply(expected, actual);
                let last = observed.entries().last().unwrap();
                assert_eq!(
                    (
                        last.operation,
                        last.pc,
                        last.address,
                        last.width,
                        last.count,
                        last.result
                    ),
                    (
                        r.operation,
                        r.pc,
                        r.address,
                        r.width,
                        r.count,
                        expected.result
                    )
                );
            }
            assert_eq!(observed.total(), 6);
            assert_eq!(observed.entries().count(), 6);
        }
        assert_eq!(observed_ram, plain_ram);
    }

    #[test]
    fn ring_wrap_is_chronological_without_changing_replies() {
        let mut ram = [0; 64];
        let mut observed = ObservedMemory::new(MemoryService::new(&mut ram, 0x4000).unwrap());
        assert_eq!(observed.entries().count(), 0);
        for sequence in 1..=130 {
            let mut r = request(LOAD, 0x4000);
            r.pc = sequence * 4;
            assert_eq!(observed.execute(&r).result, OK);
        }
        assert_eq!(observed.total(), 130);
        assert_eq!(observed.entries().count(), CAPACITY);
        for (index, entry) in observed.entries().enumerate() {
            assert_eq!(
                (entry.sequence, entry.pc),
                (67 + index as u64, (67 + index as u64) * 4)
            );
        }
        observed.total = u64::MAX;
        observed.execute(&request(LOAD, 0x4000));
        assert_eq!(observed.total(), u64::MAX);
        assert_eq!(observed.entries().last().unwrap().sequence, u64::MAX);
    }

    #[test]
    fn callback_forwards_and_rejects_null_or_misaligned_records() {
        let mut ram = [0x5a; 64];
        let mut observed = ObservedMemory::new(MemoryService::new(&mut ram, 0x4000).unwrap());
        let r = request(LOAD, 0x4000);
        let mut reply = Reply::default();
        let owner = (&mut observed as *mut ObservedMemory<'_>).cast::<c_void>();
        // SAFETY: Owner, request and reply are separate live aligned records.
        assert_eq!(unsafe { callback(owner, &r, &mut reply) }, 0);
        assert_eq!((reply.result, reply.value0), (OK, 0x5a5a5a5a));
        let before = reply;
        for (o, q, p) in [
            (
                core::ptr::null_mut(),
                &r as *const Request,
                &mut reply as *mut Reply,
            ),
            (owner, core::ptr::null(), &mut reply),
            (owner, &r, core::ptr::null_mut()),
            (owner.cast::<u8>().wrapping_add(1).cast(), &r, &mut reply),
            (
                owner,
                core::ptr::from_ref(&r).cast::<u8>().wrapping_add(1).cast(),
                &mut reply,
            ),
            (
                owner,
                &r,
                core::ptr::from_mut(&mut reply)
                    .cast::<u8>()
                    .wrapping_add(1)
                    .cast(),
            ),
        ] {
            // SAFETY: Intentionally invalid null/misaligned pointers must be rejected
            // before any access; the other pointers retain their valid ownership.
            assert_eq!(unsafe { callback(o, q, p) }, -1);
        }
        assert_eq!(observed.total(), 1);
        same_reply(before, reply);
    }
}
