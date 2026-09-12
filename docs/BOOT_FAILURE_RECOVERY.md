# Boot target failure recovery

Current: a failed child image ends BOOTX64 even when an interactive picker is
configured. Diagnostic stdout uses a macro that panics on firmware output error.

Decision: only explicit interactive picker mode retries selection. After a
returned load/start failure, display the status and require a key acknowledgment
before reopening the menu. Escape at the menu still returns ABORTED. Direct
noninteractive targets retain their original one-attempt return status. Required
input failures are returned; no unattended retry or alternative target is chosen.
Diagnostic stdout is best effort and serial reporting remains independent.

This recovery assumes an EFI application returned with boot services available.
It does not recover a kernel panic, hang, or return after ExitBootServices.
Verification must exercise the production BOOTX64 with a missing target, a key
acknowledgment, a new menu choice and a real authored child image invocation.
