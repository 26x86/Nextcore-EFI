# Nextcore-EFI

Freestanding UEFI applications for the Nextcore macOS compatibility layer.
The primary ARM64e execution target is an **x86 computer at EFI startup**:
`NXARMJIT.efi` links the ISE ARM-to-x86 JIT and software PAC provider directly.
Core and ISE are immutable Git dependencies, so this repository also builds
without the integration workspace or sibling source directories.

```sh
rustup target add x86_64-unknown-uefi
cargo build --release --target x86_64-unknown-uefi --features arm-jit --bin NXARMJIT
cargo build --release --target x86_64-unknown-uefi --features arm-jit-probe --bin NXARMJIT
```

Install Clang and LLD before building. The first command produces the default
staging/provider boundary. The second opts into independently authored fixtures:
ARM64e translated execution, PAC/AUT and GOP readback have passed in x86 OVMF.
The `arm-jit-trace` diagnostic requires an explicit startup ABI and instruction
budget. The original macOS 27 kernel reached seven translated instructions before
an unsupported system register; SPTM arguments/services and a resolved platform
device tree are not provided, so this is not a valid macOS cold-boot result.

The BOOTX64 picker and existing x86 diagnostics remain separate entry points.
BOOTAA64 is an optional native-ARM diagnostic, not a host requirement. QEMU/OVMF
runs firmware tests during development; the EFI runtime does not spawn or depend
on a host operating-system process. Guest Metal and sustained macOS boot remain
unverified. Prior release provenance is preserved in `repository.json`.


Firmware DeviceTree templates are rejected explicitly before diagnostic entry,
with their unresolved count reported. Authored runtime trees and a native
three-register TPIDR readback fixture are covered by the bounded prefix harness.
