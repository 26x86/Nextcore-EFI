# BP33 authored DeviceTree EFI consumer contract

Status: implemented authored EFI consumer; design preceded code.
Base EFI f3f7938fba5a90aea9849edd1ef932a6bf60084e. Canonical dependencies select
Core f77c98f0b457ab488f37e5be10a608a364d996c7 and the immutable BP32 ISE
revision. Historical proof below used outside-tree source patches; canonical
standalone and parent validation retain their own binary/source identities.

## Current and desired state

The ledger is host-tested and compiles for UEFI. This slice supplies the missing
actual x86 EFI consumer: firmware-owned ArmPages -> exclusive ledger loan ->
code/DT/stack/output reservations -> source-bound authored DT transformer -> typed
commit -> scoped MemoryServiceV2 -> generated x86 code executing authored ARM loads
and stores through nonidentity stage-1 mappings.

A new opt-in `arm-jit-dt-probe` feature and `NXDT` binary reuse the existing stage-1
build capability. Default binaries, picker, original traces and product profiles
are unchanged. Actual guest allocation attributes continue to be checked by
ArmPages; the ledger observes backing length and receives an explicit guest base.

## Authored allocation and data contract

Test both 4KiB and 16KiB granules and lower/upper VA ranges. Each case owns separate
firmware allocations for guest RAM, immutable page tables and generated x86 code.
Host extents and guest RAM/table extents must be disjoint. RAM is initialized to a
nonzero guard byte before its exclusive ledger loan. Guest code, DT, stack and
output reservations each have a whole-granule capacity and explicit purpose.
First-fit addresses come from actual ledger records; no copied host pointer is
used as a guest PA. Chosen VA mappings are deliberately nonidentity and correspond
to these records rather than a second guessed physical placement.

The synthetic source contains a literal root name and a flagged `authored-aperture`
property, with an uninterpreted authored expression body. The explicit replacement
is two little-endian u64 values: observed guest base and actual RAM length. The
replacement property is identified by exact source hash and parsed source offset.
The generated DT property value is located using a checked structural parse, not
assumed to be an Apple target property or guessed runtime ABI.

The authored guest reads the real serialized root header and all 16 replacement
bytes through its DT VA. It uses aligned 32-bit accesses (flattened DT only promises
four-byte wire alignment) and writes the exact values plus an authored marker to
its output reservation. Code generation uses independent public A64 unsigned
load/store and MOVZ encodings, validated against an assembler fixture. There is a
strict instruction budget and no original input.

Before JIT entry, a prepared DT is deliberately made stale by a reservation
release. Commit must return StaleSnapshot without entering the JIT or changing
RAM. A fresh snapshot and newly prepared patch are then committed. The scoped RAM
loan explicitly advances generation; arbitrary execution closure errors do not
promise rollback. The service and all backing loans end before owners are freed.

## Actual outcomes and negative control

Eight cases: two granules x two VA ranges x correct/invalid DT mapping. The invalid
mapping installs an invalid DT leaf, while leaving code mapped, so the first DT
load must produce an actual guest translation fault at the DT VA. It must report
the exact read Data Abort ESR/FSC/level/FAR and no retired load or output/marker
write. This tests a wrong DT VA mapping in the running x86 EFI JIT, without inventing
a substitute value or labeling absent backing as a guest fault.

Positive cases compare complete RAM against an independently assembled expected
image, including code, serialized DT, stack, output and unreserved guards. Table
bytes must remain unchanged. Guest returned/stored words, PC, retirement, native
blocks, callback requests/completions, ESR/FAR and reply fields are recorded.

A strict host reader retains raw case fields, decodes emitted authored DT bytes
independently, validates exact case identity sets and numerical counters, and
compares output bytes to values decoded from that DT and observed aperture. Input
EFI/OVMF/runner hashes are role-keyed before and after execution. A separate
wrong-mapping-only binary replay against the positive expectation is an expected
failure, demonstrating that pass markers or hard-coded values cannot hide it.

## Limits and acceptance

No original assets or values, no manufacturing defaults, no target-DT schema,
no SPTM/normal Apple handoff and no usable macOS boot claim. The evidence is actual
x86 OVMF execution of the authored allocation/DT/provider/JIT connection only.

Acceptance: positive and expected-fault matrix, strict independent decoding,
actual wrong-mapping negative, unchanged full RAM/table guards where required,
explicit stale rejection before JIT, assembler word verification, and source/binary
hashes. Root reviews and owns canonical pins and publication afterward.

## Recorded result and replay

The final image passed all eight cases on an x86 OVMF computer with TCG. Four
positive cases each retired 16 instructions, compiled 16 native blocks and
completed 13 data operations. Four invalid-DT cases each retired the preceding
ADD only, compiled two blocks, and reported read translation level 3 with ESR
0x96000007 and FAR equal to the configured DT VA. The output marker stayed at
the initial guard bytes in each fault case. All eight cases rejected a stale
patch before the sole JIT invocation.

The independent host decoder validated the root header, exact authored schema,
explicit 16-byte aperture property and guest output. It reconstructed the entire
expected RAM image and matched SHA-256, covering serialized DT, instructions,
stack, output, released reservation and unreserved guards. Table hashes matched
before/after. Eight tampered-capture checks were rejected even where pass=true
remained present. The assembler fixture independently matched all 16 instructions.

A separate copied source changed only FORCE_WRONG_DT_MAPPING to true, leaving the
normal success expectation intact. Actual EFI stopped at the first DT load with
1 retired instruction, two blocks and the same read translation exception. The
ordinary success harness returned exit 1 and retained its failure receipt.

Positive EFI SHA-256: `f4856180a7bc7eba65284b47b12fef77d11734bc08c6b1578bd3b50903025082`.
Core source is byte-identical to ledger commit
`f77c98f0b457ab488f37e5be10a608a364d996c7`; ISE is
`720d7c61140e39da0f457192bd88138a52017e22`. The build used outside-tree
path patches while retaining this EFI worktree's dependency pin lines for root
to integrate. This metadata distinction is preserved in the isolated receipts.

Run from the parent checkout root with the integrated dependency pins
(choose new output directories):

```sh
cargo build --locked --manifest-path nextcore/Cargo.toml -p nextcore-efi --release \
  --target x86_64-unknown-uefi --features arm-jit-dt-probe --bin NXDT
python3 nextcore/crates/nextcore-efi/tools/verify_dt_ledger_ovmf.py \
  --efi-probe nextcore/target/x86_64-unknown-uefi/release/NXDT.efi \
  --output /path/to/new-dt-ledger-replay
python3 nextcore/crates/nextcore-efi/tools/check_dt_ledger_capture.py \
  --report /path/to/new-dt-ledger-replay/report.json \
  --output /path/to/new-dt-ledger-reader-checks.json
```

For the actual negative control, make an external source copy and change only the
constant FORCE_WRONG_DT_MAPPING from false to true; build to another target
directory and run the unchanged harness. Success is the expected harness exit 1
plus the recorded translation exception and guard output, not just any build/run
failure. Preserve the positive source and binary. The fixture accepts no original
OS inputs. No product boot policy or execution budget is relaxed by this probe.

Independent reader review found that the initial capture checker validated rows
but omitted the report envelope and host u64 bounds. The corrected shared reader
requires actual raw serial, the exact ordered eight-case matrix, complete
PASS/FAIL/entry markers, scope flags, input hash roles, recomputed row evidence and
checked host spans. The checker rejects28 copied malformed controls, including
the three formerly accepted CLI reports. Historical8-case captures are unchanged
and record their original reader identity; fresh canonical runs use this stricter
reader and bind raw serial SHA-256.

Canonical integration now selects Core147f4c4, whose UEFI-only software SHA-256
feature corrects an actual debug LLVM code-generation failure. The f77 ledger
implementation and historical DT evidence above remain unchanged. Existing
NXAPFS debug all-features CI stays enabled; final canonical replay also executes
it before the authored firmware matrices.
