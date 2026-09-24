# Firmware watchdog ownership

## Current Status

BOOTX64 and NXARMJIT disable the firmware watchdog immediately after UEFI helper
initialization, before configuration reads, picker waits or guest execution.
The installed uefi 0.40 typed API `boot::set_watchdog_timer(0, 0x10000, None)`
passes zero seconds, an application-owned code and no diagnostic data. Zero
seconds disables the watchdog. The firmware call is made exactly once; failures
retain the actual firmware status, are reported and do not abort application
execution. Guest CPU state, instruction budgets and readiness gates are unchanged.

The separate `NXWATCHDOG` binary requires `watchdog-probe`. It first checks the
production wrapper with an injected DEVICE_ERROR and exact call arguments. It
then arms the actual firmware watchdog for two seconds, disables it through the
production helper, and stalls for three seconds. `watchdog-probe-armed` leaves
the actual timer armed as a negative control. The host must observe reset in
the control and survival only after successful disablement; marker-only output
without the firmware negative control does not establish timer operation.

Source contract: installed uefi 0.40 `src/boot.rs`, `set_watchdog_timer`, forwards
to EFI_BOOT_SERVICES.SetWatchdogTimer. The UEFI Boot Manager specification
section 3.1.2 requires an initial five-minute watchdog before launching an EFI
application. The application assumes responsibility for its own execution.

## Target State

Retain actual OVMF positive and armed negative evidence, then separately test
long original-image diagnostics and physical firmware. A watchdog reset is a
possible cause of missing terminal output, not proof of the original failure
cause. This change does not establish physical macOS boot or a desktop.
