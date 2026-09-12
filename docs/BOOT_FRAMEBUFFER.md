# Owned Guest Framebuffer GOP Adapter

## Current Status

The adapter connects a caller-owned contiguous guest image to the current GOP mode. The opt-in trace consumer reserves the buffer through Core, populates boot-video fields and presents guest writes after bounded execution. It does not establish normal startup readiness.

## Target State

`boot_framebuffer::CurrentGop` acquires the typed `uefi` 0.40 `GraphicsOutput` protocol and validates its current resolution. `Geometry` exposes width, height, `width * 4` row bytes and the exact byte length. Dimensions must be nonzero and at most 8192, bounding one frame to 256 MiB. These are adapter limits, not a promise that firmware can allocate that amount.

`present(&[u8])` accepts exactly one contiguous little-endian XRGB8888 frame (byte order blue, green, red, unused). It creates a typed BLT buffer without casts, ignores the unused byte, and calls `BufferToVideo` at `(0, 0)`. The input slice remains unchanged. `readback()` uses `VideoToBltBuffer` on the same GOP and returns BGRX bytes with zero unused bytes. Every allocation uses `try_reserve_exact`; allocation failure returns `OUT_OF_RESOURCES`. Geometry changes between acquisition and transfer return `MEDIA_CHANGED`, before the typed GOP bounds assertions can be reached.

## Protocol and Ownership Contract

The scoped GOP guard remains owned by `CurrentGop`; the caller must drop it while boot services are active. No mode change or CPU access to the physical framebuffer is used. PixelBltOnly, RGB, BGR and bitmask devices use the same BLT conversion path, with firmware responsible for hardware pixel layout and stride. The guest buffer always has its own contiguous stride. Protocol acquisition and BLT errors are returned to the caller. Optional failure is not a successful display result.

The primary binding source is the installed, version-pinned `uefi` 0.40 implementation of `proto/console/gop.rs`, including `GraphicsOutput::current_mode_info`, `BltOp`, `BltRegion` and the documented BGR reserved-byte `BltPixel` representation. The adapter relies on the firmware protocol's valid-pointer contract through those safe typed bindings; it adds no guessed FFI or raw memory mapping.

## Validation

Module-local host tests check geometry bounds, contiguous stride, exact buffer length, channel order and preservation of caller data. An independent scratch manifest compiles the actual module for `x86_64-unknown-uefi`. The parent repository's `verify_boot_framebuffer_ovmf.py` fixture checks actual OVMF presentation and readback using geometry and pixels obtained from encoded boot arguments. Host tests and target code generation alone are build verification, not physical hardware or macOS desktop evidence.

The trace selector is `Trace.Video = gop-framebuffer`. Protocol acquisition or placement failure reports `TRACE_VIDEO_UNAVAILABLE` and continues through the existing validated headless handoff. A successful transfer reports `TRACE_VIDEO_PRESENTED`. The additional diagnostic-only `arm-jit-video-readback` build feature reads GOP pixels before subsequent console text can overwrite them and records exact RGB equality plus hashes. This is a single presentation while boot services are active; persistent display, firmware exit and physical boot remain unverified.

Observed adapter checks on 2026-09-12: all four tests passed using a `#![no_std]` wrapper that imports the actual module by path. Release code generation for `x86_64-unknown-uefi` and target Clippy with `-D warnings` passed. The environment used Rust/Cargo 1.97.1, edition 2021 and exact `uefi = 0.40.0`; this module introduces no MSRV change. The scratch manifest is retained at `work/efi-adapter-check/Cargo.toml`, with target artifacts in `/tmp/nextcore-gop-adapter-target-20260912`. No physical hardware result is claimed by these checks.
