# App bug hunt log

Running log of bugs and fragile code found during automated review of the
desktop app (swifttunnel-core, swifttunnel-desktop). Each entry lists the
file and line, why it matters, and whether it was fixed.

Environment notes: swifttunnel-core depends on the `windows` crate
unconditionally, so `cargo test -p swifttunnel-core` does not build on Linux.
Rust changes were compile-checked with
`cargo check --target x86_64-pc-windows-gnu` (MinGW) where possible;
Windows-only tests still need CI.

## Pass 1

### 1. Resolver answers for Jakarta and Tel Aviv were discarded

- File: `swifttunnel-core/src/geolocation.rs` (`roblox_region_from_id`,
  `roblox_region_from_swifttunnel_region_id`, around line 251).
- Why it matters: `best_swifttunnel_region` maps Jakarta to `jakarta` and
  Tel Aviv to `israel`, but the reverse lookups had no arms for those ids.
  A resolver answer of `jakarta` or `israel` became "no region", which is
  cached for hours, so those game servers were never routed to their relays.
- Status: fixed. Added the missing mappings and a round-trip test over
  `all_regions()`. Compile-checked for Windows; test run pending (Windows CI).
