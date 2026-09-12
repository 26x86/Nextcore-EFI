# Authored ASID8 and MMFR0 EFI consumer

## Current Status

`NXASID` is an optional, authored x86 EFI consumer of the native JIT and the
canonical immutable memory service. It is built with `arm-jit-stage1-probe`.
It does not consume an original operating-system image or change normal startup.

The 64 cases cover both immutable profiles (1 and 3), both 4KiB and 16KiB
granules, lower and upper instruction addresses, both A1 selections, and TTBR0
tags 0, 1, 127 and 255. TTBR1 carries the complementary eight-bit tag. Every case
stores through the lower data alias and loads through its upper alias; the
guest compares the values before reading MMFR0, TCR, TTBR0 and TTBR1.

The host requires the exact model MMFR0 value `0x0f100005`, full tagged TTBR and
TCR readback, nine retired instructions, two completed data operations, no
provider error, exact final PC/SP, and preservation of all other RAM and tables.
Instruction words are independently assembled from `fixtures/asid_scalar.S` and
compared with the embedded Rust array before each firmware run.

Actual OVMF execution passed all 64 cases. A separately built copy of the same
probe against preceding ISE `5cd1e44413958450875392d8a431dba15bb76f2e` rejected
the first tagged context with `INVALID_PARAMETER`, before guest execution.
The old control qualifies changed admission; it is not a successful memory test.

## Evidence boundaries

This probe observes tagged context admission, guest control readback and actual
alias transfers. It does not expose the internal TLB tag. Independent native
ASID tests inspect the actual selected tag and reject compiled implementations
that force zero, ignore A1 or choose a tag from the virtual-address region.
Immutable contexts remain fixed throughout execution. Dynamic context changes,
ASID reuse, stage-2 translation, physical boot and macOS desktop output are not
established by this probe.

`tools/verify_asid_ovmf.py` accepts only complete LF-terminated UART records,
collapses adjacent identical console/serial observations, checks the exact case
set and final marker, and verifies input/EFI/ESP hashes. A partial or arbitrary
PASS line cannot satisfy its success gate. The bounded QEMU process is stopped
and reaped before the final receipt is written.

## Reproduction

Build `NXASID` for `x86_64-unknown-uefi` with the stage-1 probe feature, then run
the verifier with `--efi-probe` and a fresh `--output` directory. Its
`--expect-old-rejection` mode is reserved for the identical probe built against
the preceding runtime; it requires the exact first-context rejection and no
case records. Keep current and old build/source identities with the receipts.
