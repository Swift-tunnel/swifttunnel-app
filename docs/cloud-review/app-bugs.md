# App bug hunt log

Running log of bugs and fragile code found during automated review of the
desktop app (swifttunnel-core, swifttunnel-desktop). Each entry lists the
file and line, why it matters, and whether it was fixed.

Environment notes: swifttunnel-core depends on the `windows` crate
unconditionally, so `cargo test -p swifttunnel-core` does not build on Linux.
Rust changes were compile-checked with
`cargo check --target x86_64-pc-windows-gnu` (MinGW) where possible;
Windows-only tests still need CI.

There is no `AGENTS.md` in the repository (checked in pass 2), so these
passes follow the repository's existing conventions: rustfmt, small
commits, tests next to each fix.

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

## Pass 2

### 2. Driver Store lookup failed on non-English Windows and missed duplicates

- File: `swifttunnel-core/src/vpn/winpkfilter.rs`
  (`parse_enum_drivers_output`, `remove_installed_driver_package`).
- Why it matters: the parser matched the English labels `Published Name`
  and `Original Name` in `pnputil /enum-drivers` output. pnputil translates
  those labels, so on German, French, Japanese, ... Windows the WinpkFilter
  package was never found. Driver repair then skipped removing the stale
  package, install verification reported the package missing after a good
  install, and `driver_install_evidence` lost one of its signals. Separately,
  only the first matching package was removed, so a store holding two stale
  `ndisrd_lwf.inf` copies kept one (the old TODO in
  `commands/system.rs`).
- Status: fixed. The parser now keys on the values (`oemNN.inf` and the INF
  name, which pnputil does not translate) and returns every match; removal
  deletes each copy and reports the first failure. Tests cover German and
  Japanese output, duplicates and truncated records. Compile-checked for
  Windows; the parser tests were also run on Linux from an extracted copy.
