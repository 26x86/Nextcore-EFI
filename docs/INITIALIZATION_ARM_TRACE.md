# Initialization diagnostic build

`arm-jit-initialization-trace` includes the existing long, deep, tiered and v1
physical-memory provider features. Its distinct Core parser accepts the exact
`initialization-67108864` selector only with budget 67,108,864 and the named
software IRQ profile. Without that selector the prior limits remain in effect.
Earlier parser/build capabilities reject the new selector.

The build emits `TRACE_INITIALIZATION_DIAGNOSTIC_BUILD maximum=67108864`.
Only a validated initialization selection emits
`TRACE_INITIALIZATION_DIAGNOSTIC_SELECTED tier=67108864`. The host requires both
markers, inherited build capabilities and memory-provider results. The existing
600-second host timeout cap remains in force.

This diagnostic permits an experiment through a collection's large initial
fixup workload. The measured original input has over one million encoded nodes,
while the previous bounded request window belongs to the early nodes. The larger
instruction bound is not evidence of correct transformed values, complete fixup
traversal, kernel initialization or a physical desktop.

Run the authored cached arithmetic consumer with exact retirement and unchanged
inputs, plus an old-build rejection, before original input. Preserve any earlier
fault as the actual stop. Keep original registers, memory semantics, readiness
gates and incomplete-platform labeling unchanged. No service response is invented
and no original pointer is changed by the loader for this diagnostic.
