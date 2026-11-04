# App bug hunt log

Running log of bugs and fragile code found during automated review of the
desktop app (swifttunnel-core, swifttunnel-desktop). Each entry lists the
file and line, why it matters, and whether it was fixed.

Environment notes: swifttunnel-core depends on the `windows` crate
unconditionally, so `cargo test -p swifttunnel-core` does not build on Linux.
Rust changes were compile-checked with
`cargo check --target x86_64-pc-windows-gnu` (MinGW) where possible;
Windows-only tests still need CI.

From pass 2, Windows tests also run locally under Wine: install
`gcc-mingw-w64-x86-64` and `wine64`, build with
`cargo test -p swifttunnel-core --lib --target x86_64-pc-windows-gnu --no-run`
and run the printed `.exe` with `/usr/lib/wine/wine64`. Wine is not Windows
(no WFP, no NDIS driver), so failures there still need checking on CI.

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

### 3. Service state read from translated `sc query` text

- Files: `swifttunnel-core/src/optimizations.rs` (`read_service_running`),
  `swifttunnel-desktop/src-tauri/src/commands/system.rs`
  (`query_firewall_service`).
- Why it matters: both parsed the `STATE` line of `sc query`. sc translates
  that label (`STATUS` in German, `ÉTAT` in French), so on non-English
  Windows every service-disable optimization failed with "Couldn't read the
  original service state", and the Windows Firewall repair reported the
  firewall services as `unknown` and always tried to start them.
- Status: fixed. Added `utils::query_service_state`, which reads
  `dwCurrentState` from the service control manager, and
  `service_state_name`. Both callers use it; the text parsers are gone.
  Tests run under Wine (see environment notes).

### 4. Core parking tweak read its original value from translated powercfg text

- File: `swifttunnel-core/src/optimizations.rs` (`read_power_ac`).
- Why it matters: the snapshot looked for the English line
  `Current AC Power Setting Index:` in `powercfg /query` output. powercfg
  translates it, so on non-English Windows the "Disable core parking" tweak
  always failed with "Couldn't read the original power setting".
- Status: fixed. The value is read with `PowerReadACValueIndex`; the two
  powercfg aliases the tweak uses map to their GUIDs in `power_guid`. Added
  the `Win32_System_Power` feature of the `windows` crate. A test checks
  that every `PowerAc` action's aliases resolve. Tests run under Wine.

### 5. Translated "Access is denied" was not treated as a permission problem

- Files: `swifttunnel-core/src/vpn/error_messages.rs`
  (`user_friendly_error`, new `is_access_denied`),
  `swifttunnel-desktop/src/stores/vpnStore.ts` (`isPermissionMessage`).
- Why it matters: both matched only the English OS text. On non-English
  Windows an access-denied split-tunnel setup error fell through to the
  generic "run a repair" message, and the store treated a raw access-denied
  driver error as driver-repairable and ran an automatic driver repair
  instead of reporting the permission problem.
- Status: fixed. Both also match `(os error 5)` and `0x80070005`, which
  Windows does not translate. Tests use German and French messages and
  check that `(os error 50)` / `(os error 53)` do not match.

### 6. SwiftTunnel power plan import treated a translated "already exists" as failure

- File: `swifttunnel-core/src/system_optimizer.rs`
  (`import_swifttunnel_power_plan`).
- Why it matters: when `powercfg /import` fails because the fixed-GUID plan
  is already installed, the code accepted that only if the output said
  "already exists" in English. On other languages, if `powercfg /list`
  could not see the plan beforehand (a race with another apply, or a list
  timeout), applying the SwiftTunnel power plan failed.
- Status: fixed. A failed import also counts as success when
  `powercfg /list` now shows the plan's GUID. No unit test: the branch only
  runs against a real powercfg; compile-checked for Windows.

### 7. Legacy IPv6 firewall-rule recovery checked English netsh text

- File: `swifttunnel-core/src/vpn/ipv6_recovery.rs`
  (`restore_firewall_rule_marker`, and the PowerShell in
  `Ipv6Marker::restore_command`).
- Why it matters: when `netsh ... delete rule` fails because the rule is
  already gone, removal is confirmed only by the English text
  `No rules match`. On other languages a leftover legacy marker is never
  cleared and recovery reports failure on every launch. Only markers from
  the old firewall-rule method are affected; current versions use
  WinpkFilter static filters.
- Status: fixed. After a failed delete, the rule counts as gone when the
  persistent firewall policy store
  (`...\SharedAccess\Parameters\FirewallPolicy\FirewallRules`) has no
  value whose `Name=` field is the rule name. The English text is kept only
  as a fallback when the store cannot be read. The PowerShell variant in
  `restore_command` is not on the live recovery path (firewall-rule markers
  go to `restore_firewall_rule_marker`) and was left as is. Tests run under
  Wine; the two `recorded_ipv6_legacy_binding_*` tests in this module fail
  under Wine before and after the change because Wine has no PowerShell.

### 8. `Instant::now() - interval` panics shortly after Windows boots

- Files: `swifttunnel-core/src/discord_rpc/manager.rs` (`rpc_thread_main`),
  `swifttunnel-core/src/vpn/connection.rs` (relay lease renewal task).
- Why it matters: on Windows, `Instant` counts from boot, and subtracting
  a `Duration` larger than the uptime panics ("overflow when subtracting
  duration from instant"). The Discord presence thread started with
  `Instant::now() - 30s`, so an autostart within 30 s of boot (fast SSD,
  auto sign-in, run-on-startup is on by default) killed the thread and
  Discord presence never worked that session. The relay renewal task did
  the same with 5 s.
- Status: fixed. Both keep `Option<Instant>` for "no attempt yet". The other
  `now - duration` uses are in tests. Test for the Discord helper runs
  under Wine.

### 9. Adapter GUID extraction panicked on names shorter than a GUID

- File: `swifttunnel-core/src/vpn/parallel_interceptor.rs`
  (`extract_guid_str_from_internal_name`).
- Why it matters: the braceless fallback looped over
  `0..=len.saturating_sub(36)` and sliced `bytes[start..start + 36]`. For a
  name under 36 bytes with no `{GUID}` (for example the NDIS 5 style
  `\DEVICE\NDISWANIP`, or any short adapter name a driver reports) the range
  is `0..=0` and the slice runs past the end, panicking inside physical
  adapter selection during connect. NDIS 6 usually names WAN miniports by
  GUID, which is likely why it has not shown up in the field.
- Status: fixed with `bytes.windows(36).position(..)`, which yields nothing
  for short names. Test covers empty, short, braced non-GUID and raw GUID
  names. Runs under Wine; the standalone pattern was confirmed to panic.

### 10. Run-on-startup for the full app may be blocked by Windows (open, needs Windows check)

- Files: `swifttunnel-core/src/autostart.rs` (`sync_run_on_startup`),
  `swifttunnel-desktop/src-tauri/build.rs` (manifest).
- Why it matters: the desktop exe's manifest is `requireAdministrator`, and
  run-on-startup (on by default) registers it under
  `HKCU\...\CurrentVersion\Run`. With UAC on, Windows does not elevate Run
  entries at sign-in and normally skips programs that need elevation, so
  the full app may never start with Windows. Lite runs as the user and is
  not affected.
- Status: not changed. Confirming needs a real Windows sign-in with UAC at
  its default level. If confirmed, the usual fix is an "at log on" scheduled
  task with "run with highest privileges", which also needs uninstall and
  `--cleanup` support, so it is larger than this bug hunt's scope.

### 11. Non-UTF-8 hosts files disabled the country-ban bypass

- File: `swifttunnel-core/src/roblox_proxy/hosts.rs`
  (`read_hosts_or_empty`, `remove_marker_block`, `write_overrides`,
  `has_overrides`).
- Why it matters: the hosts file was read with a UTF-8-only reader. Windows
  reads hosts in the ANSI code page, and files with a Windows-1252/1251
  comment (older Notepad, ad-block and "privacy" tools) are common on
  non-English PCs. Every read failed, so applying the bootstrap overrides
  failed (bypass unavailable), removing our stale block failed, and
  `has_overrides` reported none. Writes also rewrote CRLF files as LF.
- Status: fixed. The file is handled as bytes and edited line by line, so
  other lines and the file's line endings are kept exactly; added lines use
  the file's own line ending. UTF-16 files (BOM or NUL bytes) are refused
  with a clear message instead of being corrupted. Tests cover a
  Windows-1252 CRLF file round trip and UTF-16 refusal; run under Wine.
