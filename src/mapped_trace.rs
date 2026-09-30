//! Explicit software-defined mapped diagnostic, without normal-startup approval.
use crate::{firmware_io::report, memory_boot, memory_boot_v2, pauth, platform};
use core::ffi::c_void;
use nextcore_core::arm64_stage1_tables::{Arm64Stage1Tables, Stage1Alias};
use nextcore_memory_service::{abi, abi_v2, stage1::MemoryServiceV2};
use uefi::Status;

type Protect = unsafe extern "C" fn(*mut c_void, usize, i32, *mut c_void) -> i32;
const FIRST_FLOW_EDGES: usize = 32;
const LAST_FLOW_EDGES: usize = 16;
const WATCH_FOLLOW_EDGES: usize = 16;

#[derive(Clone, Copy, Default)]
struct FlowEdge {
    sequence: u64,
    from: u64,
    to: u64,
}

struct FetchWatch {
    from: u64,
    visits: u64,
    fallthrough: u64,
    first_taken: Option<FlowEdge>,
    follow: [FlowEdge; WATCH_FOLLOW_EDGES],
    follow_count: usize,
}

struct LoadWatch {
    pc: u64,
    threshold: Option<u64>,
    requests: u64,
    successful: u64,
    first_address: u64,
    last_address: u64,
    last_value0: u64,
    last_value1: u64,
    forward: u64,
    backward: u64,
    repeated: u64,
    value_changes: u64,
    first_threshold_sequence: u64,
    first_threshold_from: u64,
    first_threshold_address: u64,
}

struct StoreWatch {
    pc: u64,
    requests: u64,
    successful: u64,
    first_address: u64,
    first_value: u64,
    first_width: u32,
    first_count: u32,
    last_address: u64,
    last_value: u64,
    forward: u64,
    backward: u64,
    repeated: u64,
}

impl StoreWatch {
    fn configured() -> Option<Self> {
        let raw = option_env!("NEXTCORE_RESEARCH_STORE_WATCH_PC")?;
        let pc = u64::from_str_radix(raw.strip_prefix("0x")?, 16).ok()?;
        Some(Self {
            pc,
            requests: 0,
            successful: 0,
            first_address: 0,
            first_value: 0,
            first_width: 0,
            first_count: 0,
            last_address: 0,
            last_value: 0,
            forward: 0,
            backward: 0,
            repeated: 0,
        })
    }

    fn record(&mut self, request: &abi_v2::Request, reply: &abi_v2::Reply) {
        if request.operation != abi::STORE || request.pc != self.pc {
            return;
        }
        self.requests = self.requests.saturating_add(1);
        if reply.result != abi_v2::OK {
            return;
        }
        if self.successful == 0 {
            self.first_address = request.address;
            self.first_value = request.value0;
            self.first_width = request.width;
            self.first_count = request.count;
        } else if request.address > self.last_address {
            self.forward = self.forward.saturating_add(1);
        } else if request.address < self.last_address {
            self.backward = self.backward.saturating_add(1);
        } else {
            self.repeated = self.repeated.saturating_add(1);
        }
        self.successful = self.successful.saturating_add(1);
        self.last_address = request.address;
        self.last_value = request.value0;
    }
}

impl LoadWatch {
    fn configured() -> Option<Self> {
        let raw = option_env!("NEXTCORE_RESEARCH_MEMORY_WATCH_PC")?;
        let pc = u64::from_str_radix(raw.strip_prefix("0x")?, 16).ok()?;
        let threshold = match option_env!("NEXTCORE_RESEARCH_MEMORY_WATCH_THRESHOLD") {
            Some(raw) => Some(u64::from_str_radix(raw.strip_prefix("0x")?, 16).ok()?),
            None => None,
        };
        Some(Self {
            pc,
            threshold,
            requests: 0,
            successful: 0,
            first_address: 0,
            last_address: 0,
            last_value0: 0,
            last_value1: 0,
            forward: 0,
            backward: 0,
            repeated: 0,
            value_changes: 0,
            first_threshold_sequence: 0,
            first_threshold_from: 0,
            first_threshold_address: 0,
        })
    }

    fn record(&mut self, request: &abi_v2::Request, reply: &abi_v2::Reply) {
        if request.operation != abi::LOAD || request.pc != self.pc {
            return;
        }
        self.requests = self.requests.saturating_add(1);
        if reply.result != abi_v2::OK {
            return;
        }
        if self.successful == 0 {
            self.first_address = request.address;
        } else {
            if let Some(threshold) = self.threshold {
                if self.first_threshold_sequence == 0
                    && self.last_address < threshold
                    && request.address >= threshold
                {
                    self.first_threshold_sequence = self.successful.saturating_add(1);
                    self.first_threshold_from = self.last_address;
                    self.first_threshold_address = request.address;
                }
            }
            if request.address > self.last_address {
                self.forward = self.forward.saturating_add(1);
            } else if request.address < self.last_address {
                self.backward = self.backward.saturating_add(1);
            } else {
                self.repeated = self.repeated.saturating_add(1);
            }
            if reply.value0 != self.last_value0
                || (request.count == 2 && reply.value1 != self.last_value1)
            {
                self.value_changes = self.value_changes.saturating_add(1);
            }
        }
        self.successful = self.successful.saturating_add(1);
        self.last_address = request.address;
        self.last_value0 = reply.value0;
        self.last_value1 = reply.value1;
    }
}

impl FetchWatch {
    fn configured() -> Option<Self> {
        let raw = option_env!("NEXTCORE_RESEARCH_FETCH_WATCH_PC")?;
        let from = u64::from_str_radix(raw.strip_prefix("0x")?, 16).ok()?;
        Some(Self {
            from,
            visits: 0,
            fallthrough: 0,
            first_taken: None,
            follow: [FlowEdge::default(); WATCH_FOLLOW_EDGES],
            follow_count: 0,
        })
    }

    fn record(&mut self, previous: u64, pc: u64, sequence: u64) {
        if previous == self.from {
            self.visits = self.visits.saturating_add(1);
            if self.from.checked_add(4) == Some(pc) {
                self.fallthrough = self.fallthrough.saturating_add(1);
            } else if self.first_taken.is_none() {
                self.first_taken = Some(FlowEdge {
                    sequence,
                    from: previous,
                    to: pc,
                });
            }
        }
        if self.first_taken.is_some()
            && previous.checked_add(4) != Some(pc)
            && self.follow_count < WATCH_FOLLOW_EDGES
        {
            self.follow[self.follow_count] = FlowEdge {
                sequence,
                from: previous,
                to: pc,
            };
            self.follow_count += 1;
        }
    }
}

#[derive(Default)]
struct FetchFlow {
    successful_fetches: u64,
    previous_pc: Option<u64>,
    edge_count: u64,
    first: [FlowEdge; FIRST_FLOW_EDGES],
    last: [FlowEdge; LAST_FLOW_EDGES],
    watch: Option<FetchWatch>,
}

impl FetchFlow {
    fn configured() -> Self {
        Self {
            watch: FetchWatch::configured(),
            ..Self::default()
        }
    }

    fn record(&mut self, pc: u64) {
        self.successful_fetches = self.successful_fetches.saturating_add(1);
        if let Some(previous) = self.previous_pc {
            if let Some(watch) = &mut self.watch {
                watch.record(previous, pc, self.successful_fetches);
            }
            if previous.checked_add(4) != Some(pc) {
                let edge = FlowEdge {
                    sequence: self.successful_fetches,
                    from: previous,
                    to: pc,
                };
                if self.edge_count < FIRST_FLOW_EDGES as u64 {
                    self.first[self.edge_count as usize] = edge;
                }
                self.last[(self.edge_count % LAST_FLOW_EDGES as u64) as usize] = edge;
                self.edge_count = self.edge_count.saturating_add(1);
            }
        }
        self.previous_pc = Some(pc);
    }
}
unsafe extern "C" {
    #[cfg_attr(
        feature = "arm-jit-fp-research",
        link_name = "vf_boot_run_memory_fp_research_v2"
    )]
    #[cfg_attr(
        not(feature = "arm-jit-fp-research"),
        link_name = "vf_boot_run_memory_pauth_v2"
    )]
    fn vf_boot_run_memory_trace_v2(
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
        #[cfg(feature = "arm-jit-fp-research")] initial_cpacr: u64,
        options: *const platform::BootOptionsV2,
        controls: *const abi_v2::Controls,
        memory: abi_v2::Callback,
        owner: *mut c_void,
        result: *mut memory_boot_v2::MemoryRunResultV2,
    ) -> i32;
}

struct Observed<'a> {
    service: MemoryServiceV2<'a>,
    aliases: [Option<Stage1Alias>; 2],
    fetches: [u64; 2],
    successful_fetches: [u64; 2],
    first_fetch: [Option<u64>; 2],
    flow: FetchFlow,
    load_watch: Option<LoadWatch>,
    store_watch: Option<StoreWatch>,
    #[cfg(feature = "arm-jit-memory-observation")]
    ring: [crate::memory_observation::Entry; 64],
    #[cfg(feature = "arm-jit-memory-observation")]
    total: u64,
}
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
    if let Some(watch) = &mut owner.load_watch {
        watch.record(&request, &reply);
    }
    if let Some(watch) = &mut owner.store_watch {
        watch.record(&request, &reply);
    }
    if request.operation == abi::FETCH {
        if reply.result == abi_v2::OK {
            owner.flow.record(request.address);
        }
        for (index, alias) in owner.aliases.iter().enumerate() {
            if let Some(alias) = alias {
                if request.address >= alias.virtual_base
                    && request.address < alias.virtual_base + alias.bytes
                {
                    owner.fetches[index] = owner.fetches[index].saturating_add(1);
                    if reply.result == abi_v2::OK {
                        owner.successful_fetches[index] =
                            owner.successful_fetches[index].saturating_add(1);
                    }
                    owner.first_fetch[index].get_or_insert(request.address);
                }
            }
        }
    }
    #[cfg(feature = "arm-jit-memory-observation")]
    {
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
    }
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
    aliases: &[Stage1Alias],
) -> Result<(i32, memory_boot::MemoryRunResultV1), Status> {
    let tables = Arm64Stage1Tables::new_with_aliases(base, virtual_base, ram.len() as u64, aliases)
        .map_err(|error| {
            report(&alloc::format!(
                "NXARMJIT: TRACE_LINKED_MAP_INVALID reason={error:?}"
            ));
            Status::INVALID_PARAMETER
        })?;
    if aliases.len() == 2 {
        report("NXARMJIT: SELECTED_STARTUP_LINKED_MAPPED aliases=2 entry_abi=false executed=false");
    }
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
    report(&alloc::format!(
        "NXARMJIT: TRACE_MAPPINGS_READY granule=16384 profile=3 physical_base={base:#x} virtual_base={virtual_base:#x} memory_size={} table_base={:#x} table_bytes={} ttbr0={:#x} ttbr1={:#x} tcr={:#x} sctlr={:#x} entry={entry:#x}",
        ram.len(),
        tables.physical_base(),
        tables.bytes().len(),
        controls.ttbr0,
        controls.ttbr1,
        controls.tcr,
        controls.sctlr
    ));
    report("NXARMJIT: TRACE_MEMORY_PROVIDER abi=2 mode=mapped-normal-nc-v1");
    #[cfg(feature = "arm-jit-fp-research")]
    report("NXARMJIT: TRACE_FP_EXECUTION profile=partial-baseline source=software-defined-virtual-efi isa_conformant=false normal_provider_ready=false initial_cpacr=0x300000 target_startup_verified=false");
    let size = ram.len() as u64;
    let service = MemoryServiceV2::new(
        &mut *ram,
        base,
        tables.bytes(),
        tables.physical_base(),
        controls,
    )
    .map_err(|_| Status::INVALID_PARAMETER)?;
    let mut service = Observed {
        service,
        aliases: [aliases.first().copied(), aliases.get(1).copied()],
        fetches: [0; 2],
        successful_fetches: [0; 2],
        first_fetch: [None; 2],
        flow: FetchFlow::configured(),
        load_watch: LoadWatch::configured(),
        store_watch: StoreWatch::configured(),
        #[cfg(feature = "arm-jit-memory-observation")]
        ring: [crate::memory_observation::Entry::default(); 64],
        #[cfg(feature = "arm-jit-memory-observation")]
        total: 0,
    };
    let callback: abi_v2::Callback = observed;
    unsafe extern "C" fn pauth_step(context: *mut c_void, word: u32) -> i32 {
        // SAFETY: the C adapter supplies its live, aligned architecture context.
        unsafe { pauth::vf_preos_pauth_step(context.cast(), word) }
    }
    let mut result = memory_boot_v2::MemoryRunResultV2::default();
    // SAFETY: all records and owned code/RAM/tables are disjoint and remain
    // alive throughout this synchronous call. Guest addresses are never host PCs.
    let status = unsafe {
        vf_boot_run_memory_trace_v2(
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
            #[cfg(feature = "arm-jit-fp-research")]
            0x300000,
            options,
            &controls,
            callback,
            core::ptr::from_mut(&mut service).cast(),
            &mut result,
        )
    };
    if aliases.len() == 2 {
        report(&alloc::format!(
            "NXARMJIT: TRACE_SELECTED_FETCH_RANGE sptm_requests={} sptm_success={} sptm_first={:#x} txm_requests={} txm_success={} txm_first={:#x}",
            service.fetches[0],
            service.successful_fetches[0],
            service.first_fetch[0].unwrap_or(0),
            service.fetches[1],
            service.successful_fetches[1],
            service.first_fetch[1].unwrap_or(0),
        ));
    }
    let flow = &service.flow;
    report(&alloc::format!(
        "NXARMJIT: TRACE_FETCH_FLOW successful={} nonsequential={} first_retained={} last_retained={}",
        flow.successful_fetches,
        flow.edge_count,
        flow.edge_count.min(FIRST_FLOW_EDGES as u64),
        if flow.edge_count > FIRST_FLOW_EDGES as u64 {
            flow.edge_count.min(LAST_FLOW_EDGES as u64)
        } else {
            0
        }
    ));
    if let Some(watch) = &flow.watch {
        let first = watch.first_taken.unwrap_or_default();
        report(&alloc::format!(
            "NXARMJIT: TRACE_FETCH_WATCH from={:#x} visits={} fallthrough={} first_taken_sequence={} first_taken_to={:#x} follow_retained={}",
            watch.from, watch.visits, watch.fallthrough, first.sequence, first.to, watch.follow_count
        ));
        for edge in watch.follow.iter().take(watch.follow_count) {
            report(&alloc::format!(
                "NXARMJIT: TRACE_FETCH_WATCH_EDGE sequence={} from={:#x} to={:#x}",
                edge.sequence,
                edge.from,
                edge.to
            ));
        }
    }
    if let Some(watch) = &service.load_watch {
        report(&alloc::format!(
            "NXARMJIT: TRACE_LOAD_WATCH pc={:#x} requests={} successful={} first_address={:#x} last_address={:#x} forward={} backward={} repeated={} value_changes={}",
            watch.pc,
            watch.requests,
            watch.successful,
            watch.first_address,
            watch.last_address,
            watch.forward,
            watch.backward,
            watch.repeated,
            watch.value_changes,
        ));
        if let Some(threshold) = watch.threshold {
            report(&alloc::format!(
                "NXARMJIT: TRACE_LOAD_THRESHOLD pc={:#x} threshold={threshold:#x} first_sequence={} from={:#x} address={:#x}",
                watch.pc,
                watch.first_threshold_sequence,
                watch.first_threshold_from,
                watch.first_threshold_address,
            ));
        }
    }
    if let Some(watch) = &service.store_watch {
        report(&alloc::format!(
            "NXARMJIT: TRACE_STORE_WATCH pc={:#x} requests={} successful={} first_address={:#x} first_value={:#x} first_width={} first_count={} last_address={:#x} last_value={:#x} forward={} backward={} repeated={}",
            watch.pc,
            watch.requests,
            watch.successful,
            watch.first_address,
            watch.first_value,
            watch.first_width,
            watch.first_count,
            watch.last_address,
            watch.last_value,
            watch.forward,
            watch.backward,
            watch.repeated,
        ));
    }
    for edge in flow
        .first
        .iter()
        .take(flow.edge_count.min(FIRST_FLOW_EDGES as u64) as usize)
    {
        report(&alloc::format!(
            "NXARMJIT: TRACE_FETCH_EDGE sample=first sequence={} from={:#x} to={:#x}",
            edge.sequence,
            edge.from,
            edge.to
        ));
    }
    if flow.edge_count > FIRST_FLOW_EDGES as u64 {
        let retained = flow.edge_count.min(LAST_FLOW_EDGES as u64);
        for index in flow.edge_count - retained..flow.edge_count {
            let edge = &flow.last[(index % LAST_FLOW_EDGES as u64) as usize];
            report(&alloc::format!(
                "NXARMJIT: TRACE_FETCH_EDGE sample=last sequence={} from={:#x} to={:#x}",
                edge.sequence,
                edge.from,
                edge.to
            ));
        }
    }
    #[cfg(feature = "arm-jit-memory-observation")]
    {
        let retained = service.total.min(64);
        report(&alloc::format!(
            "NXARMJIT: TRACE_MEMORY_OBSERVATION total={} retained={retained}",
            service.total
        ));
        for sequence in service.total - retained..service.total {
            let e = &service.ring[(sequence % 64) as usize];
            report(&alloc::format!(
                "NXARMJIT: TRACE_MEMORY_REQUEST sequence={} operation={} pc={:#x} address={:#x} width={} count={} result={}",
                e.sequence,
                e.operation,
                e.pc,
                e.address,
                e.width,
                e.count,
                e.result
            ));
        }
    }
    let r = &result.last_reply;
    report(&alloc::format!(
        "NXARMJIT: TRACE_MAPPED_REPLY result={} fault={} address={:#x} output_pa={:#x} descriptor_pa={:#x} level={} context={} metadata_flags={} esr={:#x}",
        r.result,
        r.fault,
        r.address,
        r.output_pa,
        r.descriptor_pa,
        r.level,
        r.context,
        r.metadata_flags,
        r.esr
    ));
    let first_store = service.store_watch.as_ref().and_then(|watch| {
        (watch.successful != 0 && watch.first_width == 8 && watch.first_count == 1)
            .then_some((watch.first_address, watch.first_value))
    });
    drop(service);
    if let Some((address, value)) = first_store {
        if let Some(offset) = address
            .checked_sub(virtual_base)
            .and_then(|offset| usize::try_from(offset).ok())
        {
            if let Some(bytes) = ram.get(offset..offset.saturating_add(8)) {
                let observed = u64::from_le_bytes(bytes.try_into().unwrap());
                report(&alloc::format!(
                    "NXARMJIT: TRACE_STORE_READBACK address={address:#x} value={value:#x} observed={observed:#x} matches={}",
                    observed == value
                ));
            }
        }
    }
    Ok((status, result.base))
}
