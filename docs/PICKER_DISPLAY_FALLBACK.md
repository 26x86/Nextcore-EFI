# Picker optional display failure contract

## Current Status

The BOOTX64 picker has a GOP renderer and a Simple Text Output fallback.
Failure to locate/open GOP, render its current resolution, or submit the menu
through GOP switches to text output. Text color selection and screen clearing
are presentation operations: their failure must not prevent a text menu write.
They retain firmware defaults/current contents and emit a serial diagnostic.

After the user has accepted a displayed selection, the starting-message redraw
is optional in either renderer. Its failure must preserve the selected index,
report the display failure on serial, and return the selection to the caller.
LoadImage and StartImage remain the caller's responsibility.

## Target State

A firmware implementation that rejects optional presentation requests can still
display the picker and dispatch a selected system. Required initial menu writes
and keyboard/event errors remain errors: a failed menu is not silently treated
as visible, and there is no automatic blind boot.

## Validation

- Build BOOTX64 for `x86_64-unknown-uefi`.
- Run existing Core boot-picker rendering/navigation tests.
- On instrumented firmware, independently fail SetAttribute and ClearScreen;
  confirm text menu writes are attempted and a visible menu accepts selection.
- Fail the confirmation redraw after a successful menu and Enter input; confirm
  PICKER_DISPLAY_WARNING precedes PICKER_BOOT with the same selected index.
- Fail the initial text menu write; confirm the picker returns an error without
  dispatch. Fail a keyboard/event operation; confirm no selection is fabricated.
- Verify GOP failure still drops the protocol guard before text output.

Build and host tests are not firmware fault-injection or physical display proof.
This change does not establish kernel entry, post-ExitBootServices display,
macOS installation, userspace, or graphics acceleration.

## Authored OVMF fault injection

`NXPICKER` compiles the same `picker.rs` used by BOOTX64. The separate
`picker-fallback-probe` feature adds no hooks to BOOTX64. Run this deliberately
faulty protocol adapter only in a disposable OVMF instance, never deploy it as
a normal boot application.

Build NXTEST first, then set `NEXTCORE_PICKER_CHILD` to its absolute EFI output
path while building NXPICKER. NXPICKER embeds only that authored child image.

```sh
cargo build -p nextcore-efi --release --target x86_64-unknown-uefi --features test-child --bin NXTEST
NEXTCORE_PICKER_CHILD=/absolute/path/to/NXTEST.efi cargo build -p nextcore-efi --release --target x86_64-unknown-uefi --features picker-fallback-probe --bin NXPICKER
python3 tools/verify_picker_fallback_ovmf.py --efi-probe /absolute/path/to/NXPICKER.efi --output /tmp/picker-fallback-new-run
```

The Linux runner requires QEMU and `/usr/share/OVMF/OVMF_{CODE,VARS}_4M.fd`.
On Windows the build environment variable can be set with PowerShell and the
runner invoked through WSL using `/mnt/c/...` paths. Output must be a new
directory. It contains the exact QEMU command, serial log and JSON result.

Cases 1-4 fail the first real GOP Blt callback, then restore it immediately
so OVMF text rendering can use GOP. Case 5 forwards the initial full-screen
BufferToVideo operation to real GOP and counts its successful completion. Only
after Enter does it reject the matching full-screen confirmation redraw; text
callbacks remain unchanged. Non-full-screen firmware operations are forwarded.
The probe temporarily replaces the real
console callbacks, and uses a signaled event and authored Enter key. It restores
all callbacks and the original input event before loading the child.

| Case | Injected failure | Required result |
| --- | --- | --- |
| 1 | SetAttribute returns UNSUPPORTED | Text fallback, selection 0, NXTEST executes |
| 2 | ClearScreen returns DEVICE_ERROR | Text fallback, selection 0, NXTEST executes |
| 3 | OutputString fails after Enter | Confirmation warning, selection 0, NXTEST executes |
| 4 | First OutputString fails | DEVICE_ERROR, zero key reads, no child |
| 5 | Final GOP confirmation Blt fails after a successful full-screen draw and Enter | GOP readiness, confirmation warning, selection 0, NXTEST executes |

On 2026-09-12 all five cases passed in x86 Q35/Nehalem OVMF with TCG. The
captured serial stream showed four NXTEST entries and the three warning types.
Case 5 required exactly one successful full-screen GOP draw, one injected GOP
failure, and one accepted key. Its isolated serial segment required the ordered
GOP-ready, confirmation-warning, boot-selection and child-entry markers, with
no text-renderer fallback. The initial text-write negative still performed no
key read and started no child. The unchanged production `picker.rs` was used.
The five-case report and serial log are preserved in
`docs/picker-gop-confirmation-20260912`; probe SHA-256 is
`7fda85b0834c71a086ab7dd075b6ca3a3cb25b8e5b08200aab8583cd534491cd`.
This is actual UEFI protocol-failure execution evidence, with authored input;
it does not establish physical keyboard input or physical screen visibility.
