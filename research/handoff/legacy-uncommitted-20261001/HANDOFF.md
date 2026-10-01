# Historical public variants for nextcore-efi

## Current Status

This archive preserves 3 frozen public files from an older standalone module checkout at source baseline `ed9ba25598a52fdf1ba55badfee0d953afdbc20e`. Each file retains its original module-relative path and exact UTF-8 bytes, including the historical README and repository metadata when present. The archived files are uncommitted variants and therefore are not asserted to equal that baseline commit's files.

The active module implementation, API, build configuration and top-level license remain those of authoritative main base `252d9ccbd1c2920c232cff998cf0d1fba941e010`. The archived source and descriptions are unfinished historical material; they do not establish compilation, tests, EFI execution, macOS boot, Metal or physical-device acceptance. Hash checks establish preservation only.

## Target State

Retain these independently authored public variants in this module's own public history so another local environment can review them against current main. No parent repository flattening or new execution path is introduced. Source revision ancestry must be independently verified before deleting legacy branches or checkouts.

## Provenance and licenses

The authoritative repository is [Nextcore-EFI](https://github.com/26x86/Nextcore-EFI). [manifest.json](manifest.json) lists every original path, source baseline, SHA-256, Git blob identity, byte count and file mode. The frozen [LICENSE.txt](LICENSE.txt) is retained byte for byte with its copyright notices, four redistribution conditions and disclaimer. The module's current top-level [LICENSE.txt](../../../LICENSE.txt) is also retained without modification.

Historical repository manifests retain their original paths and labels for exact preservation. Their entries do not select or generate current active code. No raw restore media, extracted proprietary assets, binaries or private execution records are part of this archive.

## Open questions

OPEN_QUESTION: Verification: Reconcile any selected historical implementation against current interfaces and independently validate it in the next authorized environment before claiming execution support.
