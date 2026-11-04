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
