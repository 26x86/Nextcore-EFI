# NextCore EFI

UEFI boot selection, platform services and explicit APFS Jumpstart driver loading.

Source snapshot: [65d1e85db2dfcd4e1c07656bb0bfc315d36fac83](https://github.com/26x86/26x86/commit/65d1e85db2dfcd4e1c07656bb0bfc315d36fac83).

Repository release: `26x86-Nextcore-EFI-v0.1.2`. Cargo package version is preserved from source.

Public source only; no Apple firmware, filesystem driver payload, operating-system image or private research input is bundled. Module checks establish their stated source/build boundary; they do not establish installed macOS boot, guest Metal or physical hardware support.

## Fixed dependencies

- [Core](https://github.com/26x86/Nextcore-Core/tree/26x86-Nextcore-Core-v0.1.2)
