# Local usage measurement prototype

Population measurement now uses the [automatic session-peak design](../../docs/AUTOMATIC-PLAYER-USAGE-20261031.md). The standalone desktop sampler below remains local diagnostics, not a volunteer deployment plan. The relay counter collector remains relevant to measuring account bandwidth without destinations. Do not deploy either path without approval.

This is opt-in research tooling, not an app feature or an enforcement rollout. Normal desktop builds, routing, update packaging and process selection are untouched. Nothing uploads automatically. The relay addition is excluded unless explicitly built with the `usage-observation` Cargo feature. No production deployment or telemetry collection has been authorised.

## What it measures

- A separate Windows process counts actual `RobloxPlayerBeta.exe` and `RobloxPlayer.exe` processes, including the standard/VNG binaries with those names. It keeps Studio and launcher/installer/strapper counts separate. It also reports how many Players own a UDP binding. A binding is not proof of a live game, and a Player can be on the home screen.
- Counts contain no PIDs, process paths, command lines, windows, game IDs, job IDs, account names, hardware IDs, destinations or URLs. Studio ancestry is checked locally, up to eight ancestors. Missing/exited parents mean this is only a lower bound on Studio-launched test clients.
- A relay reader takes five-second snapshots of existing account offered-packet/byte counters and existing successful client-return send counters. New process/run and account-lifetime markers distinguish restarts, pruning and recreation even if a recreated counter is higher than its predecessor.
- Account and session identifiers are HMAC-pseudonymised on the relay before SSH export. One campaign key provides account deduplication across relays. The desktop receives only its participant tokens, never that key or a relay credential. The tools do not contact the website or Supabase and need no migration.
- The offline report counts sampled clients with multiple Players and time over a proposed one-Player allowance with 90 seconds of handover. It compares 5, 10 and 20 Mbps budgets with a 256 MiB burst and counts complete non-overlapping 60-second windows over each rate. These are proposed scenarios, not new limits.
- Traffic across all sampled relays is combined per account before applying a model. A missing node, busy counter, truncated response, baseline reset, clock jump or sampling gap is reported as incomplete. It is not silently replaced with zero.

One account's aggregate traffic while multiple Players were observed is measurable. How much was *caused* by the extra Players is not established by correlation. The report deliberately leaves `extra_instances_cost` and `actual_provider_invoice_cost` null.

`successful_return_ipv4_bytes` uses existing successful tunnel-frame send counters plus 28 bytes of IPv4/UDP overhead per datagram. The send atomics are sampled independently, so even this is an estimate at the sampling boundaries. It covers the client-return leg, not server-facing upload, retransmissions, provider transfer pools, credits or the invoice. Offered inner-IP bytes are reported separately and can include attempted traffic that was not sent successfully.

## Safety and overhead

No packet-path increment, packet parsing, classification decision, queue, wait, network probe or process enforcement was added. The optional relay account epoch is assigned only when an account state is created. The research endpoint copies a few existing values with `try_lock`; if busy it skips the row. It formats JSON after releasing the lock. Successful-return data comes from existing atomics, with a non-waiting map lookup. Responses are capped at 4,096 accounts and 4,096 sessions. The endpoint uses the existing stats authentication; it is 404 in a normal build.

The desktop sampler uses native process snapshots and UDP-owner tables in a separate process at BelowNormal priority. It does not attach to Roblox, scan memory, start ETW, capture packets, change a driver/firewall/adapter, start a game or send pings. When no Player exists it skips UDP-table enumeration. No sampler starts with SwiftTunnel.

Local idle measurements on 2026-10-31, after the idle shortcut:

| Measurement | Result |
| --- | ---: |
| Cadence and duration | Five seconds, 60 seconds total |
| Samples | 12 |
| Native count median / maximum wall time | 9.446 / 15.940 ms |
| Separate PowerShell process CPU during the run | 562.5 ms |
| Mean CPU relative to one core | 0.937% |

This short run includes PowerShell/JSON warm-up after Add-Type, but excludes initial C# compilation and PowerShell startup. It was an **idle** check with no Roblox Player present. It does not prove active-game overhead, ping, FPS or Linux packet-forwarding latency. Normal builds incur none of this collection work. Before any public pilot, test active multi-Player/Studio/VNG cases and perform controlled gameplay A/B checks, including a busy relay with the observer enabled. Do not advertise zero overhead based on source inspection or these idle results.

## Preparing a local campaign

Requires Node 24 with built-in SQLite (tested with 24.16), Windows PowerShell 5.1 or PowerShell 7 for desktop sampling, and Python 3/OpenSSH on a relay chosen for a later approved pilot. Run from `C:/Users/supre/swift/swifttunnel-app`. Keep keys, participant files, observations and reports under the local audit directory, outside OneDrive and source control.

```powershell
node tools/usage-observation/campaign.mjs init C:/Users/supre/swift/audit-followup/usage-campaign
```

The operator puts the intended account's ID in a private text file, then issues one participant file **per device**, reusing that file on subsequent runs from that same device:

```powershell
node tools/usage-observation/campaign.mjs participant C:/Users/supre/swift/audit-followup/usage-campaign C:/Users/supre/swift/audit-followup/account-id.local C:/Users/supre/swift/audit-followup/participant.json
```

Keep the account-ID file and campaign key private. The participant file contains only campaign/account/device tokens. Token possession is not a security attestation of account ownership, and modified clients can falsify their counts. This prototype is for controlled/volunteer measurement, not enforcement or a claim of population-wide prevalence. Cross-device time correlations require synchronised UTC clocks; the tooling detects jumps, not a constant offset. Report population coverage and missing clients explicitly.

Run the local-only Windows sampler, writing a new file:

```powershell
& tools/usage-observation/observe-desktop.ps1 -Config C:/Users/supre/swift/audit-followup/participant.json -OutFile C:/Users/supre/swift/audit-followup/desktop-observation.jsonl -DurationSeconds 600
```

It is bounded to at most 24 hours and a 32 MiB file by default, supports a 5-60 second cadence, and refuses to overwrite a file. Ctrl+C stops the standalone tool. Its records have a validity flag and include collection duration/error codes. A missing UDP table is unknown rather than zero Players. The process count can still be valid when UDP counts are unknown.

## Relay pilot preparation, do not deploy yet

The separate relay repo contains the local feature. Its build command for a later approved pilot would be `cargo build --release --features usage-observation`. This guide does not authorise running or deploying that build. Existing relays return 404 for the new endpoint, which the reader treats as unknown. There is deliberately no fallback to the older counters that cannot distinguish account-lifetime resets.

Inventory format, held privately outside the repo:

```json
[
  { "id": "approved-relay-id", "host": "approved-relay-host", "user": "ubuntu", "key_file": "C:/Users/supre/.ssh/swifttunnel" }
]
```

Only after approval to operate the collector against the chosen nodes:

```powershell
node tools/usage-observation/collect-relays.mjs C:/Users/supre/swift/audit-followup/usage-campaign C:/Users/supre/swift/audit-followup/approved-relays.json C:/Users/supre/swift/audit-followup/relay-observation.jsonl --run --seconds 600
```

The `--run` acknowledgement is mandatory. The script runs a temporary Python reader through SSH stdin; it installs nothing remotely and never changes relay env, routing or enforcement. It keeps one bounded-duration SSH connection per node instead of reconnecting every sample. Stats tokens stay on the relay. Responses have a four-MiB bound and output has a 256 MiB bound. Failures stop or mark collection incomplete. The reader exits when its duration ends or the SSH pipe closes. No daemon or scheduled task is created.

Choose the full relevant fleet as the inventory. The analyser requires the same inventory across combined files. Combining a subset while calling it account-wide would hide traffic on other relays. Restarting daily files is supported with the same campaign tokens and inventory. Rotate campaign keys between research periods and delete raw data under the agreed retention period; the tooling does not silently delete evidence.

## Offline report

```powershell
node tools/usage-observation/analyze.mjs C:/Users/supre/swift/audit-followup/usage-report C:/Users/supre/swift/audit-followup/desktop-observation.jsonl C:/Users/supre/swift/audit-followup/relay-observation.jsonl
```

An optional `--price-per-gb N` models an explicitly supplied marginal price. No price is assumed. It reports offered-traffic and successful-return-leg scenarios separately, not an invoice or the incremental cost of extra instances.

The output directory must be fresh. The report and local SQLite database contain pseudonymised samples, not destinations. Input processing is streamed and indexed on disk, with bounds on lines, file size and one-account working sets. Identical repeated samples are deduplicated; conflicting duplicates or unsupported/private fields are rejected. Oversized account histories are counted as unanalysed rather than silently omitted. The report includes incomplete coverage and independent model restarts across gaps.

Times between adjacent samples are modelled using the previous desktop state and uniform byte rates. Models cannot reproduce sub-sample packet bursts or exact packet drops. Cross-device sums and over-90-second durations are labelled modelled. `max_observed_players` and the basic multi-Player account count use actual **single-device** samples, not tunnel sessions, flow counts, helper counts or fabricated population estimates. Studio-present impact is broken out for review before any exemption/limit decision.

## Verification

```powershell
node --test tools/usage-observation/observation.test.mjs
wsl.exe -e python3 /mnt/c/Users/supre/swift/swifttunnel-app/tools/usage-observation/test-reader.py
```

The fixture cases cover account counter recreation with higher values, missing samples, clocks, duplicate collectors, multi-relay aggregation, burst budgets, privacy/schema rejection, unknown costs and idempotent ingestion. Relay checks cover non-waiting observation of a busy account, distinct epochs, and authenticated availability only in the feature build. They are local checks, with no external relay or production keys.

The next approval is for a limited measurement pilot and an active-game overhead check, not enforcement. Nothing is dropped until representative measured results and each proposed rule's expected impact have been reviewed separately.

For incremental bandwidth cost, a later approved test should compare one, two and four Players in matched workloads, keeping cold downloads separate from steady gameplay. Compare the account counters and host transmit deltas against an idle baseline, then reconcile the relevant provider transfer pool and marginal price. A representative period, suggested seven days including update days and peak hours, is needed before estimating prevalence. The prototype does not infer either incremental cost or population prevalence from its local synthetic fixtures or idle overhead samples.
