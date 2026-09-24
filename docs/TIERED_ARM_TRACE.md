# Opt-in tiered ARM trace

Feature `arm-jit-tiered-trace` implies the existing authored probe and trace
features. It is not enabled by default. Only that feature uses Core's explicit
diagnostic parser limit of 4096 and prints
`TRACE_TIERED_DIAGNOSTIC maximum=4096`. Without it the EFI trace calls the
original 64/8 parser entry.

External tooling must opt in explicitly. Budgets above 64 are limited to the
256/1024/4096 tiers. Start with an authored 256-instruction loop; original
diagnostics may advance to the next tier only after a budget return at the
previous one. Existing register, memory-placement, platform, exception and
firmware-template validation remains active. No SPTM, native MMU, normal OS
boot or Metal support is inferred from this feature.
