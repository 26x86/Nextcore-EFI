# Bounded Memory Request Observation

## Current Status

Root owns the opt-in trace feature and post-execution report integration. This adapter wraps the unchanged `nextcore-memory-service` physical-memory implementation and its existing request/reply ABI. No ISE code, memory permission, instruction budget or readiness behavior changes here.

## Target State

`ObservedMemory::new(service)` takes ownership of a `MemoryService`. `execute(&Request)` calls the original service exactly once, records the request metadata and returned result, then returns the identical reply. A fixed ring retains the last 64 entries in chronological order through `entries()`. `total()` counts all requests, including rejected requests. Sequence numbers start at one and saturate at `u64::MAX`; the ring continues advancing without overflow or allocation. Diagnostic limits remain far below this saturation boundary.

`Entry` contains only sequence, operation, PC, address, width, count and reply result. It never contains guest instruction words, store values or loaded values. The adapter neither prints nor allocates; the caller reports entries only after execution returns. Original-image coordinates must remain in isolated output.

## Callback Safety

`callback` has the existing `abi::Callback` signature. Null or misaligned owner/request/reply pointers return `-1` without memory access or service execution. For all other inputs the caller supplies a live uniquely borrowed `ObservedMemory`, one initialized readable `Request`, and one writable `Reply`. These full aligned objects must not overlap one another, guest RAM or JIT code. Their lifetimes cover the call; execution is synchronous, single-threaded and not reentrant. Alignment checks cannot establish provenance, lifetime or non-overlap; those remain the same caller obligations as the original service callback. The reply pointer may refer to uninitialized storage because the callback writes it without creating a reference. Valid calls return zero after forwarding through `ObservedMemory::execute`.

## Validation

Module-local tests compare every reply field and final RAM against the plain service for fetch, load, store, malformed, alignment-fault and out-of-range requests. They verify empty/partial/wrapped ring order, preserved metadata, saturating counters, and null/misaligned callback rejection without side effects. A separate `no_std` wrapper compiles the actual module for `x86_64-unknown-uefi`. Root owns authored firmware comparison and the feature wiring. These checks do not establish original-kernel progress or macOS boot.

Observed on 2026-09-12 with Rust/Cargo 1.97.1 and the unchanged ISE `002d2eff` memory service: all three grouped tests pass; `no_std` UEFI release code generation and target Clippy with `-D warnings` pass. The scratch wrapper is retained at `work/memory-observation-check`, with artifacts in `/tmp/nextcore-memory-observation-target-20260912`. Miri is not installed in this toolchain; no Miri result is claimed. Callback lifetime and non-overlap obligations still require the caller's integration review.
