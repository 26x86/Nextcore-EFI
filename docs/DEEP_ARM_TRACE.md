# Deep ARM diagnostic build

BP35 adds the separate opt-in feature `arm-jit-deep-trace`. It includes the existing tiered diagnostic and M=0 Rust memory provider so actual instruction fetch counts remain observable. Ordinary builds and existing64/8 or256/1024/4096 selection semantics retain their old parser paths.

The new build invokes Core's distinct `parse_arm64_trace_configuration_with_deep_tier`. `Trace.DiagnosticTier` must explicitly select the string `deep-16384` together with budget16384 and the existing software IRQ profile. A missing selector retains the old4096-tier behavior in this already-tiered build. The old default/with_limit API never accepts16384.

The build emits `TRACE_DEEP_DIAGNOSTIC_BUILD maximum=16384`. Only a validated deep-selected request emits `TRACE_DEEP_DIAGNOSTIC_SELECTED tier=16384`; an ordinary lower-tier request in the same image does not. Existing tiered and memory-provider markers stay intact. All unchanged DT-template, placement, incomplete-SPTM, platform and SCTLR.M gates continue to apply.

The authored actual x86 EFI gate requires16384 retired instructions/fetches/native entries, exact arithmetic/PC readback, no data transfers or exception, and input preservation. A separate externally clamped4096 binary must fail that16384 expectation through actual lower retirement, not a build failure or timeout. The same image separately exercises old4096 and64 budgets; normal firmware rejects the new selected config before guest entry.

Original diagnostic execution follows the separately reviewed explicit CLI only after that authored gate. An earlier fault remains a real bounded stop; a budget stop is never called an unsupported opcode or full macOS startup. This feature does not enable the BP34 dynamic profile, mutable guest page tables, a normal SPTM provider, or guest Metal.

Canonical integration selects Corebab7ac4 (the explicit parser plus UEFI software
SHA-256 correction) and ISE0d722886. BP33 DT and BP34 dynamic-MMU consumers remain
separate opt-in capabilities. The earlier Core development patch/ISE720 authored
proof and original diagnostic retain their distinct binary/source identities.
Final canonical builds and actual deep/lower-tier replay are separate evidence.
