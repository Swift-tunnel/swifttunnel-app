This directory is populated by the release workflow with the pinned
`nvidiaProfileInspector.exe` 2.4.0.31 release from upstream NVIDIA Profile
Inspector.

The binary is intentionally not committed to the repository. Tauri bundles this
directory when release builds run, and `build.rs` fails Windows release builds if
the helper was not staged or its SHA-256 does not match the pinned artifact.
