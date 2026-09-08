# BP34 actual x86 EFI one-way MMU enable caller

Status: implemented and verified with authored x86 OVMF execution. Root approved the design before implementation and authorized this bounded caller
and supplied immutable EFI base `93286527c9624d4ca8d46d2c4221fa58a4aa0854`.
Implementation uses a separate `codex/arm64e-dynamic-efi-probe` worktree. BP33/NXDT,
BP32/NXMMU and default firmware binaries remain unchanged. Root owns dependency
pins, parent metadata, Git index, commits and publication.

## Frozen inputs and current state

ISE runtime is `/home/sharh/work/bp34-ise-dynamic-control/runtime`. Its 69-file
manifest `/home/sharh/work/bp34-runtime-source-freeze.json` has SHA-256
`72f5e7e58ad42c1428cbced6c261d37783061c13b45639a465faada7d51dc7d3`.
The immutable ISE source commit is `0d722886753268ec366f068823c37ea10132fb43`.
The implementation contract is `docs/DYNAMIC_MEMORY_CONTROL_V1.md`; the native
C/Rust authored fixture is `runtime/test_dynamic_provider.rs`. The final host
proof and captured six-case Arm comparison already passed. They do not exercise
the actual x86 EFI boot wrapper or firmware allocation/protection path.

This slice supplies that actual EFI consumer. It does not widen the profile or
modify the CPU/service implementation. Outside-tree Cargo path patches select
the frozen ISE and canonical Core while root prepares final dependency pins.

## Integration and stable ABI

Add a small opt-in `arm-jit-dynamic-probe` feature and a separate `NXDYN` binary.
It reuses the existing stage-1 build capability and optional service package.
Only this feature additionally includes canonical `memory_dynamic.rs` and links
`memory_dynamic.c`. Track `memory_dynamic.h` and `memory_dynamic.inc` as C rebuild
inputs for all native builds because the shared jit.c includes the dispatcher;
old entries do not gain a new external C linkage requirement.

The new entry is `vf_boot_run_memory_dynamic`: existing base/size/entry/args/stack,
code/protection/budget, explicit x0-x3/options/Controls80, then separate data and
control callbacks, a common exclusively owned service, and Result512. The data
layout stays 160/128 but uses discriminator3/profile2; control request/reply is
192/192. Result512 contains the unchanged 320-byte memory prefix and final control
reply at offset320. Existing v1/v2 acceptance and result layouts remain unchanged.

`MemoryServiceDynamic::new` starts only at M=0, epoch1, a complete supported EL1
seed, with A=1/C=I=0, little endian, MAIR0x44, inactive HCR/SCR, fixed granule/IPS,
I/F masked and unsupported BTYPE absent. Architectural revision and effective
epoch are distinct. Only the documented one-way enable and local barrier/TLBI
operations are used. There is no resume, mutable-table or live M=1 root-update
contract in this probe.

## Owned backing and transition placement

Each case allocates real, owned ArmPages for RAM, immutable tables and generated
x86 code. Check full host spans and guest RAM/table spans for disjointness and
checked arithmetic. The caller retains all owners, exclusively lends RAM and
immutably lends tables to the service, restores writable/NX code protection after
execution, and only then releases the allocations. No guest host pointer alias
is provided to the JIT. All data and tables are authored.

For each 4KiB/16KiB granule, put the transition stub at the last 12 bytes of an
owned RAM page: an observable ADD, MSR SCTLR_EL1 with only M enabled, then ISB SY.
The complete ISB instruction is identity mapped and byte-identical before and
after enable. The immediate following numeric PC maps to a different physical
page containing the actual payload. Its old physical backing holds a deliberately
unsupported HVC decoy. The nonidentity mapping therefore affects the very next
fetch after ISB; merely updating a displayed M bit cannot satisfy the test.

The service's effective snapshot intentionally stays at M=0 until ISB, which is
this deterministic profile's choice. The fixture only relies on the guaranteed
post-ISB mapping. It does not assert that physical Arm always delays effects until
ISB. Guard rejection before enable is an unsupported-profile/backing result,
whereas a missing leaf after ISB is an actual guest translation fault.

## Authored six-case matrix

Use both granules and three outcomes:

1. Successful nonidentity execution: read SCTLR, scalar load/add/store, pair store
   and load over discontiguous physical backing, DSB SY / VMALLE1 / DSB SY / ISB,
   translated scalar readback and HLT fixture completion. Match exact register
   results, full RAM effects, final architectural/effective controls, revision2,
   epoch2 and invalidation generation1. The basic program has 15 retired
   instructions and five acknowledged data operations. Native block and callback
   counts are recorded and checked against the exact authored sequence.
2. Missing post-ISB code leaf: the stub's three instructions retire, then the
   immediate next fetch reports EL1 instruction translation level3, ESR0x86000007,
   FAR/ELR at that next VA, and unchanged RAM. Final acknowledged M=1/epoch2 remain
   known; the fault is not mislabeled as a failed enable.
3. Missing translated data leaf: the same enable succeeds, the first translated
   payload load reports read translation level3, ESR0x96000007, exact data FAR and
   payload ELR, no load retirement or destination change, and unchanged RAM.

Initial PSTATE is exactly 0x3c5 (EL1h with DAIF masked). The authored ADDs do not
set flags. Fault SPSR must remain 0x3c5, fault ELR must equal the unretired fault
PC, and SP is preserved. The owned observer/output/code records are separately
allocated or stack-owned and must not alias guest RAM or immutable tables.

All code and mappings are synthetic and independently assembled. The host native
fixture informs the supported semantics, while actual EFI receipts establish the
new firmware connection. The earlier captured Arm comparison is kept separately
identified rather than being relabeled as an EFI or physical-hardware result.

## Protocol observation and integrity

Wrap the two canonical synchronous callbacks with a bounded observer that records
requests and returned replies without changing them. Allocate observer capacity
before JIT entry; callback capacity overflow fails explicitly. Bind one owner to
one run; never retry or resume uncertain/failed control state. The observer must
show PREPARE/COMMIT pairs for each successful control instruction, old effective
M=0/epoch1 on the guarded ISB fetch, and effective M=1/epoch2 on the next fetch.
A control callback acknowledgement is not counted as another guest retirement.

Compare the final C acknowledged snapshot with `service.final_state()` while the
owner is live. Capture version/size, known-state tag, architectural/effective
SCTLR/TTBR/TCR/MAIR, revision/epoch/invalidation count, exact PC/registers/SP,
native blocks, data/fetch/control counts, table reads, fault instruction and
ESR/FAR/ELR/SPSR/level. Compare complete RAM to an independently constructed image;
preserve guard bytes and table contents and emit before/after SHA-256 evidence.
No result with a host-uncertain tag can pass as a precise guest success.

## Independent reader and compiled omission negative

A standalone host reader validates the full report envelope, exact six distinct
case identities, exact numeric/key sets, bounded u64 values and checked host spans,
raw terminal PASS/FAIL markers, callback observations, control transitions, hashes
and independent full-RAM reconstruction. It must not accept an envelope merely
because individual rows contain pass=true. Role-keyed input hashes include the
runner and preserve same-basename inputs; before/after hashes must agree.

Reader mutation tests cover a false envelope, missing/duplicate cases, conflicting
terminal markers, missing or extra fields, changed counters/ESR/state transition,
forged RAM hash and overflowing host spans. They incorporate the independent BP33
reader review findings in this new tool; BP33 files remain owned by root/GPU.

Build a separate copied-source negative that omits the authored SCTLR enable by
replacing only that synthetic instruction with a supported ADD, while keeping
ISB, mappings, expected final state and payload results unchanged. M stays zero;
the subsequent fetch reaches the old physical HVC decoy instead of the translated
payload. The unchanged success harness must fail on actual execution and retain
that boundary, empty data effects and unchanged guards. HVC is intentionally
unsupported (native status8); its stop is not an implementation of HVC-to-EL2
semantics. A build error or arbitrary timeout cannot count as negative success.

## Acceptance and limits

Required: exact frozen runtime hashes, actual x86 OVMF six-case success/fault
matrix, bounded complete callback records, strict independent reader, assembler
word agreement, actual compiled omission failure, positive source/binary
preservation and unchanged older/default source. Root handles final canonical
pins and publication and may later incorporate the BP33 reader-only fix commit.

The profile has immutable tables, one CPU, one-way enable, no handler execution,
no general M=1 control writes or PAC expansion. No original OS/firmware bytes,
DeviceTree/boot-args assumptions, manufactured platform values or normal macOS
boot claim are introduced. This is a prerequisite for the eventual original boot
path, not evidence that that path is already complete.

## Verified result and review correction

The actual x86_64 OVMF/TCG release binary passed all six cases. Each granule has
these exact observations:

| Case | Status | Retired | Native blocks | Fetch callbacks | Data / completed | Control callbacks |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Nonidentity roundtrip | 1 | 15 | 15 | 15 | 5 / 5 | 12 |
| Post-ISB fetch translation fault | 16 | 3 | 3 | 4 | 0 / 0 | 4 |
| Translated data read fault | 17 | 3 | 4 | 4 | 1 / 0 | 4 |

The complete matrix contains 58 data/fetch records and 40 control records.
Independent assembly matches all 16 fixture words. The strict reader reconstructs
full RAM, checks all callback records, exact ESR/FAR/ELR/SPSR, preserved backing and
known final state. Thirty copied-report/raw-file controls reject malformed
acceptance evidence. A separate reader recognizes only the actual compiled
omission boundary: status8, three retired instructions, four generated blocks,
four physical fetches, no data effects, unchanged guarded RAM, one ISB proposal /
commit pair, and architectural/effective M0 at revision1/epoch1.

Independent review found that a digest-shaped serial field alone did not bind a
report to actual raw bytes. The corrected public tools require an existing raw
serial file, its exact SHA-256 and identical sanitized marker sequence. Missing
raw files, changed bytes, forged digests, and changed markers with a recomputed
digest are all rejected. Historical captures remain intact; a new actual six-case
and omission replay passed after the reader correction.

Existing `NXARMJIT` and `NXMMU` release builds link successfully with the same
frozen runtime; this is a linkage regression check, not a repeat of their earlier
actual EFI matrices. The historical build uses Core `f77c98f0` and EFI base
`93286527` through an isolated workspace, plus ISE `0d722886`. Root will integrate
later Core UEFI SHA-256 code-generation corrections and canonical dependency pins
before publication. Historical binary/source identities must not be relabeled as
those later canonical builds.

## Reproduction after parent dependency integration

Run from the recursive parent checkout with the Rust x86_64-unknown-uefi target,
clang/lld, QEMU x86_64 and OVMF installed. Output directories must not already
exist. The feature remains opt-in and has no picker/default entry.

```sh
cargo build --locked --manifest-path nextcore/Cargo.toml -p nextcore-efi \
  --release --target x86_64-unknown-uefi --features arm-jit-dynamic-probe --bin NXDYN
python3 nextcore/crates/nextcore-efi/tools/verify_dynamic_ovmf.py \
  --efi-probe nextcore/target/x86_64-unknown-uefi/release/NXDYN.efi \
  --output /absolute/new/dynamic-ovmf
python3 nextcore/crates/nextcore-efi/tools/check_dynamic_capture.py \
  --report /absolute/new/dynamic-ovmf/report.json \
  --output /absolute/new/dynamic-reader-controls.json
```

`--serial` may explicitly locate the raw log; otherwise each checker requires the
report's sibling `serial.log`. Reports are not sufficient by themselves. The
runner supports explicit OVMF paths and a timeout of at most 60 seconds. Retain the
raw log, report, runner source and role-keyed input hashes together.

For the compiled omission control, copy only the EFI crate into a separate
outside-tree directory (exclude `.git`, `target`, and Python caches), preserve the
same frozen Cargo dependency revisions and lockfile, and replace exactly one
`const OMIT_ENABLE: bool = false;` with `const OMIT_ENABLE: bool = true;` in the
copied `src/dynamic_probe.rs`. This changes only the authored MSR word to the
supported ADD. Use a separate Cargo target directory, build `NXDYN` with the same
feature, and invoke the unchanged runner. Its exit status must be 1. Then require:

```sh
python3 nextcore/crates/nextcore-efi/tools/check_dynamic_omission.py \
  --report /absolute/new/omission-ovmf/report.json \
  --output /absolute/new/omission-validation.json
```

A timeout, missing log, arbitrary failure or M1 translation fault cannot pass this
negative checker. Preserve the original positive sources and binary and record
both identities. No original Apple input is needed for any of these commands.
