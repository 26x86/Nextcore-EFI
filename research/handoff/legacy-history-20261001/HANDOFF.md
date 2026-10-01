# Historical public history handoff — nextcore-efi

## Current Status

The authoritative main at `252d9ccbd1c2920c232cff998cf0d1fba941e010` is the active module API. The older local public main `76964c0f779dbd7f0716c2db2f5aaabd3d5a9cca` and frozen source HEAD `ed9ba25598a52fdf1ba55badfee0d953afdbc20e` contain 23 commit identities absent from that initial main ancestry. Ordinary local merge commits preserve those identities without replacing the current API or dependency pins. Publication must be verified separately.

## Target State

Keep the current module implementation active. Retain the distinct older conflict variants below as historical research source with their exact bytes, original paths, Git blob identifiers and SHA-256 hashes in [manifest.json](manifest.json). The preserved variants are unfinished historical work; their presence makes no compiler, runtime, operating-system boot, Metal or device acceptance claim.

## Conflict disposition

Current feature declarations, dependency revisions, workflows, build source selection, ABI consumers and probe readers are retained. Older build and trace paths are the M0-only/deep-trace variants. Current source retains those paths and adds selected input ownership/seals, mapped trace routing, framebuffer handling/readback, protection observation, FP/SIMD source selection and expanded unaligned MMU cases. The older reader hardcoded 108 cases; the current reader derives its expanded expected count. All distinct older conflicting blobs and source license are preserved here, including variants from the frozen detached HEAD where different.

## License

Each recorded source revision includes its original `LICENSE.txt` in the manifest. The current module [LICENSE.txt](../../../LICENSE.txt) also remains unchanged.
