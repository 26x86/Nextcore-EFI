# Visible configuration recovery

## Current Status

BOOTX64 retains a visible recovery state when its own loaded-image filesystem
cannot supply a usable `\EFI\OC\config.plist`. The screen shows that exact
path and the actual load/size/parse/empty-menu reason. Enter retries only the
same file through the current loaded image's filesystem; Escape returns the
original configuration status to firmware. There is no timer-driven retry,
volume search, implicit target, file write or NVRAM operation.

Each retry closes the previous filesystem/file handles before opening the same
path again and repeats the existing 1 MiB bound and full menu parsing. Empty
files, oversized files, nonregular paths, short reads, malformed input and no
enabled entries remain distinct failures. A valid configuration retains its
ShowPicker policy and existing child-return behavior, including NOT_READY.

The screen first attempts to clear stale firmware graphics. Clear failure is
reported with its actual status but remains optional; required text is still
written and validated. Required recovery text uses the typed Simple Text Output `output_string` API,
so its actual firmware error is preserved rather than converted through a
formatting error. The ready marker follows a successful required write. Input
uses the existing Simple Text Input event and key service; service errors are
returned unchanged. Enter and Escape are the only accepted recovery actions.
Diagnostic logging cannot replace a successfully displayed recovery screen.

Actual OVMF verification passes ten authored recovery cases, including an initial
read failure followed by explicit retry and intended-child execution, persistent
missing/empty/malformed/no-entry states, Escape, required output/input failures,
and optional clear failure followed by successful retry. The same host checker
rejects the pre-change baseline as expected. Three existing picker regressions
also pass on the exact default BOOTX64: load error recovery, child error recovery,
and direct-mode error return without retry. A captured 1280x800 OVMF screen shows
the path, reason and Enter/Escape controls without the stale firmware logo.

The probe uses authored filesystem/console wrappers around production BOOTX64;
these cases do not cover every firmware implementation or certify all possible
file-service failures. No original-image bytes are used in this evidence.

## Target State

Preserve the recovery and existing picker gates on subsequent changes.
Physical keyboard/display usability and normal macOS readiness require their
own evidence; this recovery UI does not establish either.
