# BP32 authored x86 EFI stage-1 probe contract

Root approved this isolated EFI worktree based on
74956333503abe5724b13d22b1337d18a380bbf7. Add an opt-in `NXMMU` test binary;
normal entry and all existing NXARMJIT profiles retain their current behavior.
CPU implementation belongs to the separate ISE stage-1 worktree. Do not modify
ISE, Core, parent files, dependency revisions, module inventory or Git index.

Use the fixed-profile memory v2 ABI exactly: Controls80, Request160, Reply128,
Run320. Include canonical result definitions and the canonical no_std service.
MemoryServiceV2 retains exclusive RAM and immutable table image borrows through
the synchronous C call. Code/protection/result/control/owner storage are separate.
Never cast a guest VA/PA into a host executable pointer.

The fixture is independently authored. Both granules and lower/upper VA ranges
must execute generated x86 code fetched through nonidentity translation. Scalar
and pair data uses VA != PA. A pair spans adjacent VA pages backed by nonadjacent
PA pages. Check precise failure state and unchanged RAM/registers for a rejected
second page. Keep controls and table image immutable during each bounded run.
Use actual OVMF on an x86 host with existing W^X protection callbacks. Each run
has a small fixed instruction budget; no original assets/configuration are read.

Build wiring adds the v2 C/Rust files and tracks all transitive new headers and
private includes. Final binaries and replay results require CPU source freeze.
Retain all previous M=0/PAC/IRQ/CCMP regression entry points. Add a controlled
negative observation to prove the authored nonidentity expectation is enforced.
Report actual native blocks, callback counts, precise status/ESR/FAR and data
readback; do not infer unseen effects. This demonstrates an immutable software
MMU profile, not dynamic controls, normal Apple mappings, SPTM or macOS boot.

## Authored matrix and observable assertions

The initial matrix has 108 cases: 27 independently named cases repeated for
4 KiB/16 KiB and lower/upper VA ranges. Every run starts at EL1h, DAIF masked,
SCTLR=0x30d00803 and MAIR=0x44. Both TTBR roots are whole-granule aligned and
refer only into the immutable table image. The maximum budget is 16 instructions.

* Thirteen unsigned-immediate scalar forms cover byte/halfword/W/X loads and
  stores plus signed loads into W/X. Expected values are computed from authored
  byte data, with exact W upper-half clearing and sign behavior checked.
* Three 64-bit pair cases cover offset/pre/post addressing and base writeback.
  An eight-byte first element ends one VA page, and the next element uses a
  different PA page with an intentional physical gap. All RAM bytes are checked.
* Pair loads and stores independently reject the second page for translation,
  AF, unavailable backing and unsupported attributes. A store also checks a
  read-only second-page permission fault. Expected zero completed transfers and
  unchanged destination registers/base/RAM establish failure atomicity.
* Fetch invalid/PXN cases fault before any native block executes. Data faults
  occur after one authored ADD instruction, proving a native block executed
  before the exact fault boundary.

Assertions cover return/status equality, v2 ABI version/size, provider status,
retirement, PC, visible X0-X3 and SP, native blocks and callback counters,
ESR/FAR/ELR/SPSR, exact leaf FSC/level, original faulting instruction, and the
entire immutable table and RAM contents. Missing backing has provider status
and no fabricated guest ESR/FAR. These are leaf-level EL1 tests; all descriptor
levels, EL0 behavior and 32-bit pairs have separate CPU/walker evidence.

The files `docs/fixtures/stage1_scalar.S` and `stage1_pair.S` provide independent
assembler-readable forms of the authored instruction encodings. No original
kernel or target device tree is read by this binary or harness.

The planned negative control is a separate generated copy of the authored EFI
source: its code leaf incorrectly uses the guest VA as its output PA while all
expected execution/readback values stay unchanged. This produces an unavailable
backing result and must fail the ordinary harness. Keep the mutated source,
binary and failure receipt outside the module and retain the positive source.
This is a wrong-mapping negative control, not an original-kernel modification
or a claimed native decoder mutation.

After parent integration, build and execute with:

```sh
cargo build -p nextcore-efi --release --target x86_64-unknown-uefi \
  --features arm-jit-stage1-probe --bin NXMMU
python3 nextcore/crates/nextcore-efi/tools/verify_stage1_ovmf.py \
  --efi-probe target/x86_64-unknown-uefi/release/NXMMU.efi \
  --output /path/to/new-stage1-replay
```

During isolated development, an external workspace supplies path patches for
Core40833dc, the ISE worktree and its memory-service package, while
NEXTCORE_PREOS_RUNTIME selects the same ISE runtime directory. Dependency pins
inside this EFI worktree remain owned by root and are unchanged by the probe.

## Recorded result

Actual x86 OVMF execution passed all 108 cases. The strengthened host reader
independently checked every numeric status/counter/ESR/FAR/FSC field against the
authored matrix, with exact case identities and key sets. Raw fields and serial
markers are retained. Inputs are hashed by role, preserving distinct files that
share a basename; the runner itself is also hashed before and after execution.
Four host-reader tests cover numeric false-success cases, malformed shapes and
same-basename provenance.

The positive EFI SHA-256 is
`589d48ea8e4da5cfdfb764f29759ae7032ce8574cd65adf786617a8240e94692`.
Its 60-file runtime manifest has SHA-256
`5b7bed1dfaf821592a1f6c95b408a9a5b9205cbfefa7eca35b703b8ce0221808`.
All recorded runtime and linked EFI source hashes still matched after execution.
The separate whole-implementation manifest also contains docs/tools; its
different hash does not imply a different linked runtime.

The wrong-VA-as-PA negative was rejected on the first fetch: provider unavailable,
zero retirement/native blocks, no data request and no guest ESR/FAR. The ordinary
success harness returned exit 1 as required. The positive binary and source were
preserved. Existing NXARMJIT default/v1 linkage was also checked during caller
development; broader legacy runtime regression evidence belongs to the ISE proof
and parent integration rather than being relabeled as these 108 M=1 cases.

The isolated evidence directory contains `ovmf-final-r2/report.json` (strict
positive), `ovmf-negative-va-as-pa/report.json` (expected failure), exact command
records, source manifests, assembler receipt and reader tests. Root owns the
final dependency pin and publication. This result demonstrates the stated fixed
software profile only; normal macOS boot and target handoff remain unverified.
