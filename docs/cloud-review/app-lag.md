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
