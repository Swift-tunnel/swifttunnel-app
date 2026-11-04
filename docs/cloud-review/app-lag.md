# App lag hunt

Running log of things in the desktop app that can make the app, the PC or Roblox
lag or stutter. Each entry: where it is, what it likely costs, and what was done.

Verification notes for this environment (Linux cloud container): the Rust crates
are Windows-only, so Rust changes are checked with
`cargo check --target x86_64-pc-windows-msvc` (clang-cl + stub headers for ring).
Rust unit tests cannot run here; tests added for Rust changes are compiled but run
in Windows CI. Frontend tests (`npm test`) run here.

## Pass 1

### 1. Packet reader lost wake-ups (fixed)
- `swifttunnel-core/src/vpn/parallel_interceptor.rs`, `run_packet_reader` (event wait and `ResetEvent`).
- The packet event is manual-reset and was cleared *after* each batch was processed and sent. A packet
  that arrived mid-batch set the event, and then that reset wiped it, so the packet sat in the driver
  queue until the next packet arrived or the 100ms wait timed out. The reader also read only 64 packets
  per wake, so anything left after a burst waited the same way.
- Cost: occasional 8-100ms extra latency on game packets (ping spikes / rubber-banding), worse on busy
  adapters (downloads, browser) since every adapter packet goes through this reader.
- Fix: reset the event right after the wait returns, before reading. After a full 64-packet batch, read
  again without waiting (an empty-queue error on that follow-up read is treated as benign, not counted
  against the rebind budget). Also wait 10ms instead of 100ms while cloud-game packets are held for an
  owner lookup, so they replay promptly. Test: `reader_wakes_quickly_only_while_cloud_packets_are_held`.

### 2. TCP owner-table lookup on the packet reader for every new HTTPS connection (fixed)
- `swifttunnel-core/src/vpn/parallel_interceptor.rs`, `tcp_api_bootstrap_owner` in
  `should_route_to_vpn_with_routing_flags_and_tcp_owner_process_lookup`.
- With API tunneling on, the first SYN of *any* process's connection to port 80/443 (browser, Discord,
  launchers) called `GetExtendedTcpTable` twice, scanned the whole table, and could `OpenProcess` the
  owner, all on the single reader thread. The code's own estimate is about 500us per lookup, so a page
  load with 20+ connections stalled every queued packet, Roblox's included, for milliseconds.
- The owner only matters for Route Assist control hosts and Full Country Ban web traffic. For any other
  destination the SYN goes direct whoever owns it, so the lookup is now skipped there. Routing is
  unchanged; only the diagnostic owner field is missing in that case.
- Test: `test_route_assist_skips_owner_lookup_for_unrelated_https_syn`.

### 3. Closed TCP flows leaked in the reader's inline cache (fixed)
- `swifttunnel-core/src/vpn/parallel_interceptor.rs`, `InlineCacheEntry`, `prune_inline_cache_on_snapshot_refresh`
  and the FIN handling in the inline-cache phase.
- An entry was only evicted on RST, a second local FIN, or port reuse. A normal close sends one local
  FIN, so every gracefully closed relayed TCP flow stayed as `FinSeen` forever, and snapshot refreshes
  kept all TCP entries. Over a long Full Country Ban / Route Assist session the map grew until its
  10,000-entry cap. After that new flows were not cached: their SYN was relayed and later packets went
  direct, which breaks those connections midway. That is memory growth turning into a correctness bug.
- Fix: `FinSeen` now records when the FIN was seen, and the existing prune on snapshot refresh drops
  entries older than 60s. Test: `test_snapshot_refresh_drops_long_closed_tcp_inline_entries`.
- Not fixed: `Active` TCP entries for flows that die without FIN/RST (timeouts) still only leave on port
  reuse. They are rare; tracking a last-seen time per packet would add a clock read on the hot path.

### 4. Every Apply switched the PC to the Windows Balanced power plan (fixed; likely cause of "lower FPS after optimizing")
- `swifttunnel-core/src/system_optimizer.rs`, `apply_optimizations_checked` (`set_power_plan` call), default
  `power_plan: PowerPlan::Balanced` in `structs.rs`.
- `powercfg /setactive <Balanced>` ran on every apply, so any Apply (including a single network toggle,
  which applies the whole config) moved players off High Performance, Ultimate, AMD Ryzen or OEM gaming
  plans onto Balanced for as long as the app ran. Balanced allows core parking and a low minimum
  processor state, so clocks ramp more slowly: lower and less stable FPS in CPU-bound Roblox scenes.
- The UI only offers the SwiftTunnel plan toggle; Balanced is the "not using our plan" value. `restore()`
  runs before every apply and puts the user's original plan back, so the fix is to not switch when the
  config says Balanced. HighPerformance / Ultimate / SwiftTunnel still switch as before.
- Test: `default_balanced_plan_keeps_the_users_own_power_plan`.

### 5. CPU Sets pinned Roblox to the cores that happened to be unparked (fixed)
- `swifttunnel-core/src/vpn/process_performance.rs`, `select_cpu_set_ids`.
- The CPU Sets boost dropped every CPU set flagged "parked" before calling `SetProcessDefaultCpuSets`.
  Parking is a transient power hint; when Roblox starts on Balanced (or with the AMD X3D driver parking a
  CCD) many cores can be parked at that instant. Roblox was then restricted to that subset for the whole
  session, nothing re-evaluated it, and fewer cores means lower FPS.
- Fix: no longer filter on `parked`. Reserved-for-other-process, CPU0 unbinding and the P-core
  preference behave as before. Test updated in `cpu_selection_respects_allocations_groups_and_available_cores`.
- Not changed: "Prefer P-cores" still excludes E-cores and "Unbind CPU0" still removes CPU0. Both are
  explicit opt-ins named for exactly that behaviour.

### 6. "Is Roblox still running?" polls took a full system process snapshot (fixed)
- `swifttunnel-core/src/performance_monitor.rs`, `refresh_player`. Callers while Roblox runs: overlay
  `overlay_game_monitor` (1/s), game-join watcher (every 1.5s), window-size watcher (every 2s), plus
  metrics consumers.
- sysinfo 0.32 on Windows implements `ProcessesToUpdate::Some(&[pid])` with
  `NtQuerySystemInformation(SystemProcessInformation)` over the whole machine (512KiB+ buffer, every
  process and thread) and then filters. So each presence check was a full snapshot, about 1-3 per second
  during gameplay.
- Fix: once a player is confirmed, hold an `OpenProcess(SYNCHRONIZE)` handle. Presence-only polls are a
  `WaitForSingleObject(h, 0)`. The open handle also prevents PID reuse, so the check stays exact. Metrics
  samples and forced discovery still go through sysinfo unchanged.
- Test (Windows): `presence_polls_of_a_live_player_use_the_held_handle_not_a_snapshot`.

### 7. Packet threads ran at normal priority under a High-priority Roblox (fixed)
- `swifttunnel-core/src/vpn/parallel_interceptor.rs` (reader and V3 inbound receiver spawns,
  `raise_packet_thread_priority`), `swifttunnel-core/src/vpn/udp_relay.rs` (`udp-relay-sender`).
- The High Priority boost (in every preset) puts Roblox in `HIGH_PRIORITY_CLASS` (base 13). Roblox runs a
  worker thread per core, so in CPU-bound scenes any normal-priority thread (base 8), including our own
  packet reader, relay sender and inbound injector, waits for Windows' starvation boost (up to a few
  seconds) before running. Each delayed batch is extra ping exactly when the game is busiest.
- Fix: those three threads now run at `THREAD_PRIORITY_TIME_CRITICAL` (15, still below the realtime
  class). They block on the driver event or a socket and do microseconds of work per packet.
- Trade-off: during a saturating download the reader (which sees every adapter packet) now wins its core
  over Roblox. Its per-packet work is small and Roblox's threads spread over other cores; worth
  measuring on the testbench with a 1 Gbps download running alongside a game.
- Not changed: Roblox's own priority stays High as the boost promises. Lowering it to AboveNormal
  would be a behaviour change to a named feature; see open items.

### 8. Cache refresher opened every socket owner's process 10 times a second (fixed)
- `swifttunnel-core/src/vpn/parallel_interceptor.rs`, `run_cache_refresher` fast path and
  `collect_connection_pid_names_since`.
- With API tunneling on and Roblox running, the refresher runs every 100ms. On each tick it called
  `OpenProcess` + `K32GetProcessImageFileNameW` + `CloseHandle` (plus a 1KB buffer and a String) for every
  distinct PID that owns a TCP or UDP socket: typically 50-150 PIDs, so roughly 500-1500 process opens per
  second for the whole game session.
- Fix: carry a PID's name over from the previous sample when that PID still owns a socket it owned
  then. A persisting socket proves the owner did not exit, so the PID cannot have been reused by a
  different process. PIDs without one are looked up fresh, so the PID-reuse guarantee is unchanged. In
  steady state only new owners are opened.
- Test: `connection_name_refresh_reuses_names_only_for_persisting_sockets`.
- Follow-ups: the unchanged-snapshot republish is fixed in item 9, and the 5s full scan's exe lookups in
  item 10.

## Pass 2

### 9. Unchanged owner tables republished the process snapshot 10 times a second (fixed)
- `swifttunnel-core/src/vpn/process_cache.rs`, `update`, `update_with_tcp_ports`,
  `update_with_recent_tcp_ports` (new `snapshot_inputs_unchanged`).
- With API tunneling on and Roblox running, the cache refresher samples every 100ms. Each sample built a
  brand-new `ProcessSnapshot` (lowercased every process name, rebuilt the connection map clone, tunnel
  PID and port sets) and bumped `version`, even when the TCP/UDP owner tables were identical to the last
  sample, which is the usual case mid-match. On a version change the packet reader drops every UDP
  entry from its inline routing cache and `retain`s the rest, so it also re-derived the routing of the
  game's UDP flow from the snapshot ten times a second.
- Fix: before publishing, compare the inputs (connections, owner names, explicit UDP/TCP ports) with the
  live snapshot; if they match, keep it and its version. Everything else in a snapshot is derived from
  those inputs plus the fixed `tunnel_apps`, so routing is unchanged. Any real change (new socket, new
  owner, port retention expiring) still publishes immediately.
- Test: `identical_refresh_keeps_the_live_snapshot_and_version` (run on Linux by compiling
  `process_cache.rs` standalone; the module has no Windows dependencies).

### 10. The 5s full process scan read every process's exe path for nothing (fixed)
- `swifttunnel-core/src/vpn/parallel_interceptor.rs`, `run_cache_refresher`, full-scan branch.
- While in a game with API tunneling on, the refresher's full scan (every 5s) asked sysinfo for
  `with_exe(UpdateKind::Always)`. In sysinfo 0.32 that is a `GetModuleFileNameExW` on every process
  on the machine, which reads the target's PEB across process boundaries: a few hundred of those every
  5 seconds, competing with the game.
- The code only reads `process.name()`, which comes from the system process list sysinfo fetches
  anyway. The comment said `Always` protected against PID reuse leaving a stale name, but the exe flag
  never refreshes `name`; sysinfo handles PID reuse itself by comparing start times and rebuilding the
  entry. So the scan now uses `ProcessRefreshKind::new()`. Same names, same PID-reuse behaviour.

### 11. The overlay's once-a-second CPU/RAM sample snapshotted every process on the PC (fixed)
- `swifttunnel-core/src/performance_monitor.rs`, `update_metrics_at` (new `sample_held_player`,
  `PlayerHandle::usage`).
- Item 6 made presence checks use a held handle, but every *metrics* sample still went through sysinfo
  `ProcessesToUpdate::Some(&[pid])`, which on Windows is a full `SystemProcessInformation` snapshot of
  every process and thread. The overlay requests one each second (`boost_get_metrics`) for the whole
  match, as does the Boost page while it is open.
- Fix: the player handle is now opened with `PROCESS_QUERY_LIMITED_INFORMATION` as well (falling back to
  `SYNCHRONIZE` only if refused). A sample of the confirmed player reads `GetProcessTimes` and
  `K32GetProcessMemoryInfo` from it: CPU is the CPU-time delta over wall time across all cores (same
  0-100 scale as before), RAM is the working set, which is the figure sysinfo reported. Discovery,
  player changes and a handle without query rights still go through sysinfo as before.
- Tests: `held_player_cpu_is_a_share_of_the_whole_machine`, and on Windows
  `metric_samples_of_a_held_player_do_not_snapshot_the_system`.

### 12. In-game ping and Roblox stats re-rendered the hidden Connect tab every second (fixed)
- `swifttunnel-desktop/src/components/connect/ConnectTab.tsx` (`ping`), `SessionCards.tsx`
  (`RobloxCard` cpu/RAM/FPS, `SessionCards` session stats), `shell/TopBar.tsx` and `shell/Sidebar.tsx`
  (`ping`); new `useLiveStoreValue` / `liveSelector` in `lib/useLiveUpdates.ts`.
- While a game runs, the overlay driver refreshes ping and Roblox CPU/RAM/FPS every second, and each
  ping reading also updates the session statistics. `ConnectTab` subscribed to `ping` at the top of the
  tab and used it as a `useMemo` dependency of the region list, so every new reading re-rendered the
  whole tab and rebuilt every region row, all while the window was behind the game. WebView2 occlusion
  tracking is disabled on purpose (`apply_webview2_resource_tuning`), so those DOM changes were also
  painted. The other readouts did the same on a smaller scale.
- The app already pauses cosmetic updates while unfocused (`useLiveUpdates`, `idle_when_unfocused`),
  but these readouts were not using it. `useLiveStoreValue` subscribes normally while live; while paused
  its selector returns one constant, so store writes do not re-render the component at all, and the value
  catches up the moment the window is back in front. Only display values use it; routing, overlay and
  session bookkeeping still read the stores directly.
- Test: `src/lib/useLiveUpdates.test.ts`. Frontend suite, `tsc` and `vite build` pass.

### 13. "Optimizations for Windowed Games" switched off the player's VRR and Auto HDR (fixed)
- `swifttunnel-core/src/optimizations.rs`, tweak `windowed_games_optimizations_enable` (new
  `Action::RegStringEntry`), new `swifttunnel-core/src/semicolon_settings.rs`.
- Windows keeps several graphics settings in one string,
  `HKCU\Software\Microsoft\DirectX\UserGpuPreferences\DirectXUserGlobalSettings`, for example
  `VRROptimizeEnable=1;AutoHDREnable=1;SwapEffectUpgradeEnable=1;`. The tweak wrote the whole value as
  `SwapEffectUpgradeEnable=1;`, which silently turned off "Variable refresh rate" for windowed games
  (and Auto HDR) for anyone who had it on. Losing VRR on a G-Sync/FreeSync monitor shows up exactly as
  the stutter and tearing players blame on the "optimization".
- Fix: the tweak now sets only its own `SwapEffectUpgradeEnable` entry and keeps the rest. Undo uses
  the same snapshot format as before: it puts our entry back to its original value (or removes it),
  keeps changes the player made in the meantime, and adds back original entries that are now missing,
  so reverting on a machine where an older build wiped the string restores VRR/Auto HDR too.
- Tests: `semicolon_settings` unit tests (run on Linux in a scratch crate).

### 14. "Disable Core Parking" lowered FPS on dual-CCD Ryzen X3D processors (fixed)
- `swifttunnel-core/src/optimizations.rs`, `apply` (`core_parking_disable`, new
  `cpu_steers_games_with_core_parking`).
- The tweak sets the active plan's `CPMINCORES` (AC) to 100%. On the Ryzen 9 X3D parts (7900X3D,
  7950X3D, 9900X3D, 9950X3D) AMD's driver keeps games on the CCD with 3D V-Cache by parking the other
  CCD while a game runs. With parking disabled Roblox's threads spread over both CCDs, which is a
  well-known FPS loss on these chips, and the tweak advertises the opposite ("avoiding stutter").
- Fix: on a Ryzen 9 X3D (read from the registry `ProcessorNameString`) applying this tweak is refused
  with an explanation; nothing is changed. Single-CCD X3D parts and every other CPU behave as before,
  and revert still works for anyone who already applied it. The catalog description says so.
- Test: `core_parking_stays_on_for_dual_ccd_x3d_processors` (Windows CI).

### 15. The Roblox log tailer ran three full regex scans on every log line (fixed)
- `swifttunnel-core/src/roblox_watcher.rs`, `parse_join` and the server-IP pattern loop in `watch_logs`.
- Every new line of the Roblox log went through `parse_join`'s regex and then the "joining" and "UDMUX"
  regexes. `regex-lite` has no literal prefilter, so each call scans the whole line: about 12us per line
  for the three, measured on a typical 160-character line. The tailer catches up on up to 256 KB per
  poll, so attaching to a long log or a burst of logging on a teleport cost tens of milliseconds of CPU
  per second.
- Fix: each regex needs a fixed piece of text (`! Joining game '`, `UDMUX Address = `), so check for
  it with `contains` first (about 15ns for both). Matches are unchanged; existing watcher tests cover
  the parsing.
