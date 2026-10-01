# BP74 public module export handoff — nextcore-efi

## Current Status

The generated export commit `61a7797fdb7488843e26f4f35ac7d253ed1bf392` is an independent root commit with no parents. Its source refers to public parent revision `93e4a9ebc1a05e2cbec78125a0186ca1b71d98d6`. The current module prior handoff main `6b9d5d4e2f8b0fad0d787422aa4e494a4403e27b` retains its active API, dependency pins and build selection. The older snapshot is unfinished historical public work.

## Target State

Preserve the export commit identity and its original tree in this module's own main ancestry using an ordinary merge that explicitly allows unrelated histories. Retain all 10 older variants differing from the current source plus the original license here with exact bytes and [manifest.json](manifest.json). No export path is absent from the current module source. Future implementation choices require review in the next authorized development environment.

## Source and metadata scope

Rust/C source, tests, build consumers and other authored source match the original public parent tree. Generated export metadata, workflows and README files describe the historical publication snapshot. Authored shader, linker and plist fixtures already equal current published source blobs. Historical attribute and ignore files use inert archive names so they cannot normalize or hide the retained variants; their original paths and blobs remain in the preserved export commit and manifest.

## Verification and license

Hashes and Git object identities establish source preservation only. This handoff reports no compiler, runtime, operating-system boot, Metal or device acceptance result. Remote publication must be independently verified. The original [LICENSE.txt](LICENSE.txt) is retained byte-for-byte alongside the unchanged current module [LICENSE.txt](../../../LICENSE.txt).
