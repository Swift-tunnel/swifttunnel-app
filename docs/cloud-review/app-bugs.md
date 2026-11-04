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
The desktop crate's tests also run under Wine after copying
`WebView2Loader.dll` (from the `webview2-com-sys` build output) next to the
test `.exe`. Tests that start `powershell` fail under Wine because it has
none; that accounts for every Wine failure seen so far.

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

### 12. Dead restore-point helpers with wrong behaviour; stale comment

- Files: `swifttunnel-core/src/system_optimizer.rs`
  (`create_restore_point`, `open_system_restore`),
  `swifttunnel-desktop/src/lib/utils.ts` (`countryFlag`),
  `swifttunnel-desktop/src-tauri/src/state.rs`.
- Why it matters: nothing calls these. `create_restore_point` hard-coded
  `C:\`, detected throttling by English text, and reported success when
  Windows silently skipped the restore point, so wiring it up later would
  have misled users. `countryFlag` produced invalid code points for
  non-letters. The `sync_roblox_window_settings` comment said it spawns
  icacls; it only clears a read-only attribute.
- Status: removed the dead code and corrected the comment. Windows check,
  `tsc` and the frontend suite pass.

### 13. Lite's Apply reset Roblox graphics level and window size

- File: `swifttunnel-lite/src/engine.rs` (`quality_of`, `level_of`,
  `apply_roblox`).
- Why it matters: Lite offers Auto, Low and Max, but read Roblox's saved
  level through `level_of`, which mapped every level except 1 and 10 to
  Automatic. Any Apply, even one that only changed the frame cap, then wrote
  Automatic over a level the player chose in Roblox's own menu (2 to 9).
  The same Apply built its config with `..RobloxSettingsConfig::default()`,
  so it also replaced Roblox's saved windowed size (`StartScreenSize`) with
  the default.
- Status: fixed. Levels 0 to 10 round-trip unchanged (no chip is selected
  for 2 to 9, which is accurate), and Apply writes back the window size
  Roblox already has, read after Roblox is closed. Tests cover both; the
  Lite suite (90 tests) passes under Wine.

### 14. Lite left Auto routing on when Bypass Country Bans was enabled

- File: `swifttunnel-lite/src/engine.rs` (`toggle`, new `toggle_country_ban`).
- Why it matters: the full app and Lite's own Route Assist switch turn Auto
  routing off when a TCP-relaying mode is enabled, but Lite's Bypass switch
  did not. The connect then chose an Auto region the user could not see was
  in effect, and on the next launch loading the settings turned Auto off
  silently (core already blocks mid-session relay switching for bypass, so
  the session itself was not split).
- Status: fixed to match the full app, with a test. Lite suite passes under
  Wine.

### 15. Lite's "Unlock FPS" switch could not be turned off

- File: `swifttunnel-lite/src/engine.rs` (`apply_roblox`, new
  `frame_cap_to_write`).
- Why it matters: Lite has no saved unlock setting; it shows the switch as
  on whenever Roblox's `FramerateCap` is above 60, and its toggle sets the
  draft to 60 "so the client stops running at the raised cap". But Apply
  passed `unlock_fps: false`, which core reads as "leave the cap alone". The
  raised cap stayed, and after Apply the re-read turned the switch back on.
- Status: fixed. Lite always sends `unlock_fps: true` with the cap to write:
  the typed value when on, 60 when off. The full app's meaning of
  `unlock_fps: false` (do not touch the cap) is unchanged. Test added; Lite
  suite passes under Wine.
- Related, not changed: the full app's session card shows "Default FPS cap
  60" when unlock is off, although Roblox may still be at a higher cap set
  in its own menu.

### 16. A full-app "uncapped" frame rate locked Lite's Apply

- File: `swifttunnel-lite/src/state.rs` (`RobloxDraft::fps`).
- Why it matters: the full app lets players pick caps up to 99999
  ("uncapped"); Lite accepts only 30 to 1000. Lite reads the cap from
  Roblox's file, so for such a player its draft was never `ready()`, and no
  Lite change (graphics, fullscreen, Ultraboost) could be applied until they
  retyped the cap to something lower.
- Status: fixed. The draft remembers the cap it was read with, and that
  untouched value is accepted; newly typed values keep Lite's 30 to 1000
  range. Test added; Lite suite (93 tests) passes under Wine.

### 17. Lite's auto-reconnect retried every 5 seconds forever

- File: `swifttunnel-lite/src/engine.rs` (`maybe_reconnect`, new
  `ReconnectBackoff`).
- Why it matters: with Auto-reconnect on (opt-in), a reconnect that failed
  left the state at Error with `was_connected` still set, so the next idle
  poll (5 s) started another full connect: token refresh, fleet refresh and
  split-tunnel driver setup, indefinitely, for as long as the network or
  relay stayed down.
- Status: fixed. Failed automatic reconnects back off 5, 10, 20, 40, 80 s,
  then every 120 s; a connected session resets the backoff. Manual connects
  are not affected. Test added; Lite suite (94 tests) passes under Wine.

### 18. Lite postponed automatic updates by six hours whenever it was busy

- File: `swifttunnel-lite/src/engine.rs` (`spawn_auto_update`, new
  `UpdatePass` / `update_retry_after`).
- Why it matters: the worker checks 45 s after launch, then sets its wait to
  six hours before doing anything. Every skip (tunnel connected, Roblox
  open, another update running) and every failure then waited the full six
  hours. For a client people open to play, the first check usually lands
  while connected or in game, so updates were in practice delayed by six
  hours per session.
- Status: fixed. Skips made before any network work retry after 60 s;
  updates interrupted by activity after 10 min; failed checks or downloads
  after 30 min; a completed check still waits six hours. Network calls still
  happen only while idle. Test added; Lite suite (95 tests) passes under
  Wine.

### 19. Shared presets could set Roblox's frame cap as low as 1 FPS

- File: `swifttunnel-desktop/src/lib/presets.ts` (`decodePreset`).
- Why it matters: imported presets clamp every field, but `target_fps` was
  clamped to 1..99999 while the FPS slider, Lite and the launcher import all
  use a 30 minimum. A shared preset (from another player) with
  `target_fps: 1` and unlock on would cap Roblox at 1 FPS, a value no
  control in the app can produce.
- Status: fixed. Imported caps are clamped to 30..99999. Test added (fails
  before, passes after); frontend suite passes.
