# Opt-in EFI native memory provider v1

## Current and intended behavior

The existing x86 EFI trace uses the direct native RAM entry point. This change adds only the explicit `arm-jit-memory-provider` build feature, which enables the existing trace and authored probe features and routes `run_trace` through the canonical ISE `MemoryService` and `vf_boot_run_memory_v1`. Generic staging, authored probe behavior, and trace builds without this feature retain their existing paths. The guest regime remains M=0 and the current trace budgets remain unchanged.

## Ownership and ABI contract

The optional service dependency is the existing allocation-free package in ISE runtime/memory-service. The C request/reply records and Rust service types remain single-owned there; the 192-byte result is included from canonical runtime/memory_boot.rs. EFI does not define a second decoder, walker, callback protocol, or result shape. Root owns the final immutable ISE dependency revision.

For x86_64-unknown-uefi, Rust extern C and the C runtime compiled for x86_64-pc-windows-msvc use the Microsoft x64 calling convention. The generated entry retains its existing ms_abi convention. Request and reply records each have size 80 and alignment 8; the run result has size 192 and alignment 8. Full C/Rust field-offset and callback behavior are already covered by the independent host integration proof; actual OVMF execution will test this firmware ABI.

The service owns the exclusive mutable borrow of the entire staged RAM allocation for a lexical scope covering the synchronous C call. The owner remains in place until the call returns; no RAM slice, reentrant callback, or concurrent access exists during that scope. The generated code receives no RAM host pointer. Code pages occupy a separate retained EFI allocation; protection storage, options, initial registers, and the result are disjoint stack objects. C validates known record/code overlap and range overflow; the Rust caller is responsible for real allocation lifetime and exclusivity. Boot Services stay active throughout JIT protection and diagnostic reporting.

## Diagnostics and errors

The existing trace return/register/platform/exception lines are preserved. A distinct provider-build marker and provider result line report ABI version, provider_status, guest FAR, last requested/failing address, fetch/data request counters, and completed data operations. Provider errors remain host/provider failures and are not described as guest aborts. The diagnostic returns EFI ABORTED after reporting, as the existing trace does. No guest Metal, MMU-enabled execution, normal OS startup, or physical-machine success is inferred.

## Validation plan

Use an external isolated Cargo workspace with path patches and persistent targets. Freeze/hash the exact ISE runtime before building. Build both provider and ordinary trace binaries. Run the existing authored scalar 11-case and pair 6-case OVMF suites against provider mode while accounting for its documented one-instruction native blocks. Add independent serial assertions for provider counters and exact FAR; add an authored out-of-backing-range fixture to prove provider_status without a fabricated ESR/FAR or retired memory operation. Preserve serial logs, binary/source hashes, reproduction commands, and a failed negative control outside repository until root integrates the public evidence.

## Scope ownership

This worktree owns the optional feature/dependency declaration, build linkage for canonical memory_boot.c/rs and headers, the trace call around the existing run/result section, and this contract. The tiered trace parser work is owned separately; no parser changes, root pins, metadata, commits, or pushes are made here.

## Verified outcome

The linked provider executes under actual x86 OVMF: scalar 11/11, pair 6/6, six independent provider boundary fixtures, and one separately built callback-transport-failure fixture pass. All 17 scalar/pair cases additionally match exact fetch/data/completed counters; data-alignment cases expose the expected guest FAR. A real direct-path binary computes the correct byte fixture result but fails the provider-specific verifier, establishing the bypass negative control. SP-alignment FAR is recorded without asserting an architectural value. No post-fault RAM observation or physical-machine success is claimed.

The source and service dependency are pinned to ISE 41e8997c4b8d6f029ed3a3fbec0669374046ab6f. Its 18 frozen provider source/harness hashes are unchanged. A rebuild after pinning produced the identical provider binary SHA256 9f3d7a3efc21e20c26844e716dabb64005930cf1bb6802005efb1b6ae2ff0b40. Host/UEFI feature-enabled Cargo metadata and both provider/default trace builds pass. The external reproducible evidence bundle records exact binary/source hashes and the separate failure-injection source.
