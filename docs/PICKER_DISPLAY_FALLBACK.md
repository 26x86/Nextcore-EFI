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
