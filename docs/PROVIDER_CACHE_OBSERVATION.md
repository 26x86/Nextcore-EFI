# Provider Cache EFI Observation

The v1 provider uses run-local native entries keyed by freshly fetched PC,
instruction word and EL. Every instruction still fetches through the canonical
Rust memory service. The ISE contract is `docs/PROVIDER_NATIVE_CACHE.md` in the
pinned module. This change does not raise budgets or enable normal startup.

`arm-jit-provider-uncached` compiles the same C sources with
`NEXTCORE_DISABLE_PROVIDER_CACHE` for a separate comparison binary.
`arm-jit-protection-observation` wraps the existing firmware protection callback,
forwards each call once, and returns the exact status. It counts writable and
executable attempts and nonzero results without allocating or printing during
execution. The final writable restore uses the same wrapper. A synchronous,
non-reentrant call retains separate observer and firmware context records.

After restoration, `TRACE_PROTECTION_CALLS` reports the counts and
`includes_restore=true`. Successful runs have one more writable than executable
attempt. These are actual callback attempts, not inferred compile counts;
`compiled_blocks` continues to mean native entries executed.

The parent `verify_provider_cache_ovmf.py` runs separately built cached and
uncached EFI files against an authored framebuffer consumer and a 65,536-step
BFM loop. Both original acceptance checks must pass, observed execution and
request windows must match, uncached counts must equal retirements plus restore,
and cached counts must decrease with zero protection failures. Full GOP RGB
readback remains part of framebuffer acceptance.

Release builds of both variants pass. Target Clippy passes with the existing
`duplicated_attributes` and `manual_is_multiple_of` lint categories excluded;
an unrestricted `-D warnings` run still reports pre-existing generated-platform
and `arm_pages.rs` warnings. No physical macOS boot or persistent display is
established by these authored checks.
