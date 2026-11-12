# Automatic sampled Player peaks, local handoff

Prepared 2026-10-31. Local changes only. No push, tag, release, deployment, production SQL or new production collection. This replaces the volunteer campaign as the proposed prevalence-measurement approach. The separate Windows/volunteer tools remain local diagnostics, are not bundled with the desktop app, and are not needed by players.

## What is implemented

The shared desktop/Lite core counts `RobloxPlayerBeta.exe` and `RobloxPlayer.exe` on the PC every five seconds during a hosted SwiftTunnel connection. A low-priority worker uses a fresh native process snapshot. It does not trust the routing cache's retained ETW hints, examine sockets or destinations, or run on a UI/packet thread. Studio, installers and strappers are excluded as executables. Actual Player processes started by Studio are included; the measurement is not evidence of abuse.

Only a connection-lifetime sampled maximum and quality counters are kept in memory. No time series, process IDs, paths, other application names, Roblox usernames, place IDs, job IDs or visited destinations are sent. The wire report is:

```json
{"schema":1,"session_id":"0123456789abcdef","peak_players":2,"samples":24,"failures":0}
```

The session ID already exists for relay authentication. Account identity comes from authenticated API context, not a client-supplied account ID. `samples:0, peak_players:null` means unknown. A successful zero count is `samples:1, peak_players:0`. Failures never become zero samples. The peak survives automatic relay switches and resets on a genuinely new connection. A reconnect cannot inherit the previous connection's counter.

The report is attached only to existing relay ticket/renewal and disconnect calls in `X-SwiftTunnel-Roblox-Usage`. No new network request, reporting timer, gameplay packet field, encryption change or traffic limit is introduced. The five-second census does have a small cost; this is not advertised as zero overhead. One worker per connection sleeps between samples, and a global non-waiting census guard prevents stacked enumerations during reconnects. Census errors affect measurement only.

The backend sends `player_usage_enabled` in successful signed ticket responses. It is true only with `ROBLOX_USAGE_REPORTING_ENABLED=1`. Both ends default off. An older API response leaves a new client disabled. An enabled client stops sampling/reporting when a later ticket turns the flag off. The inactive worker does no census. Custom relays without a hosted session do not start the worker.

On the website, telemetry is parsed with a 256-character bound and an exact field allowlist. Invalid/missing reports are ignored without changing a ticket or disconnect response. A ticket report must match its existing authenticated session request. Saves run in Next.js `after`, after the response, with at most 32 in flight, a 1.5-second storage timeout and no retry queue. Unchanged peaks are coalesced in bounded memory for five minutes; a new peak, first valid sample or final disconnect report is eligible immediately. Storage failure does not populate the success cache.

The draft database table stores account/session IDs, first/last report times, sampled peak, sample/failure counts and app version. RLS and grants deny direct client access. The service-only RPC upserts monotonically, so retries and stale reports cannot lower or double-count a peak. It uses non-waiting account admission and caps **new measurement rows**, not connections, at 512 per account per 24 hours to bound storage abuse. A storage/admission skip means incomplete data, never a player rejection or evidence of no multi-instance activity.

## What must ship, in order

1. **Backend migration and receiver:** apply `swifttunnel-web/supabase/migrations/20261031_roblox_usage_measurement.sql` only after approval; deploy the API changes with reporting disabled. No existing production SQL has been run.
2. **Retention:** copy `scripts/prune-roblox-usage.mjs` to the control plane's ops directory and install the supplied service/timer only after approval. The hourly job removes reports older than 30 days in bounded batches. Monitor failures/backlogs so the draft public maximum of 31 days remains true. Account deletion cascades to usage rows. Exported raw/pseudonymised datasets and future byte archives must have the same retention policy; the SQL timer alone does not delete files or backups.
3. **Privacy and release notice:** approve and publish the local privacy draft before the client is authorised to send measurements. Confirm the legal basis and objection process, and set the actual publication date. Do not rely on installation/updating as blanket consent. Include a short notice in the normal update notes, linking the privacy page.
4. **Updated Desktop and Lite:** release the new shared-core code with the normal version bump and packaging. No executable, release-file or `--cleanup` names change. No new NVIDIA/driver/helper package is required. Do not raise the minimum client version just to improve a measurement denominator.
5. **Enable measurement deliberately:** set `ROBLOX_USAGE_REPORTING_ENABLED=1` after approval of the above. Updated clients then report automatically; no volunteer script or separate player installation is needed. Old, offline, modified, failed and unreported clients remain unknown. Check storage/coalescing/admission health and actual reporting coverage.
6. **Bandwidth evidence:** promote the previously prepared relay observation feature and off-packet-path counter collector to an approved, durable whole-fleet collection job. Its local relay commit is `d14136a`; it uses existing counters, not destination histories. Deployment, output rotation, retention and clock/restart coverage still need operational review before activation. The existing short-lived live counters alone cannot retrospectively supply a week's account bandwidth. Peak reporting can ship independently, but **do not say the app-only change measures bandwidth cost**.

Local rollout flag: leave `ROBLOX_USAGE_REPORTING_ENABLED` absent or `0` until approval. This flag controls measurement only. None of the destination, bandwidth, account/device or multi-instance enforcement settings is changed.

Suggested update note: "SwiftTunnel can now report a sampled count of open Roblox Players and limited connection-use statistics to help us plan capacity and evaluate fair-use rules. See our privacy policy. No new instance restrictions are included."

## What the data will and will not answer

- Among upgraded clients with accepted samples, how many accounts reported at least two open Players on the measured PC during a connection. This reduces volunteer-selection bias. It does not prove the prevalence among clients who do not report, verify modified clients, or identify Roblox accounts.
- It counts open Player processes, including the home screen and Studio-launched Player clients. It does not prove that all were playing or all generated tunnel traffic. Other Windows users on a shared PC can also have Player processes; this is a PC-wide process count, not process ownership attribution.
- Missing samples and brief overlaps between polls are not observed. A crash can lose the final peak; previous renewal reports remain. Final disconnect is best effort, not a durable delivery guarantee. An ongoing connection's maximum can reflect activity before an analysis window.
- Never add per-session/device maxima to claim a simultaneous account total. A peak alone cannot tell whether an overlap lasted a second or an hour. The proposed 90-second overlap rule cannot be evaluated from this dataset.
- With complete, retained account counters, compare **total account/session transfer among cohorts that reported different peaks**. That is not bandwidth causally attributable to extra instances. Keep cold downloads, country-ban web traffic and legitimate Studio use in mind. Do not multiply session bytes by a peak to claim extra-instance cost.
- Byte totals are not invoices. Reconcile actual host egress, provider pools/allowances/credits, encapsulation, failed sends and resets before giving dollar figures. The existing relay feature distinguishes offered counters from successful client-return send counters; the latter still does not measure the complete server-facing upload leg or provider billing.

`swifttunnel-web/scripts/roblox-usage-cohorts.sql` is a prepared **read-only** reporting query, not a production command to run without approval. It separates sampled, unknown, zero and multi-Player reports and keeps the separate quota-activity denominator labelled. Do not divide a seven-day numerator by a one-day denominator. Publish app-version uptake and reporting coverage with any prevalence estimate. Self-reported peaks are not an admission, enforcement or ban signal.

## Privacy wording

The existing live-line policy says it does not collect bandwidth usage or any record of connected activity. Those statements cannot accompany account-linked session/transfer measurements. The local privacy-page change removes those absolute claims and adds the data fields, purpose, account linkage, recipients, retention, rights contact and measurement limits. It does not alter the redesign worktree.

Suggested core disclosure:

> Updated SwiftTunnel apps can report the highest sampled number of Roblox Player processes open during a connection, together with sampling-quality counts. We link these reports to your SwiftTunnel account, connection session, app version and report times. Our relays also measure bytes and packets transferred. We use these limited measurements to understand resource use, plan capacity and evaluate fair-use rules. They do not contain process IDs, executable paths, other application names, Roblox usernames, game identifiers, visited destinations or packet contents. These are account-linked measurements, not anonymous data. Session reports are kept in the live measurement store for up to 31 days after the last report and removed when account deletion completes. We do not sell them or use them for advertising. Contact support@swifttunnel.net for access or to raise an objection.

The local draft proposes legitimate interests in maintaining a reliable shared service. **That basis is proposed, not a compliance finding.** Confirm applicability in the relevant jurisdictions and document purpose, necessity, reasonable expectations and balancing, including younger users. The alternatives considered are biased volunteer sampling and unlinked aggregate counts that cannot deduplicate accounts or reconcile transfer cohorts. Minimise data, keep retention short, and do not turn a measurement into an automatic accusation. Confirm the privacy contact, rights/objection handling, infrastructure transfers and backup/export retention before publishing the draft or enabling collection. No new user opt-in or setting was invented; if consent is the appropriate basis, the proposed automatic flow needs changing first.

Primary guidance reviewed: [ICO privacy information](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/what-privacy-information-should-we-provide/) and [ICO legitimate interests](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/lawful-basis/a-guide-to-lawful-basis/legitimate-interests/). These inform the draft; they do not establish which jurisdictions/basis apply to SwiftTunnel. [Next.js `after`](https://nextjs.org/docs/app/api-reference/functions/after) documents execution after the response, which is why measurement writes are not awaited by ticket handling.

## Local verification and remaining uncertainty

The core unit checks cover default-off reporting, unknown versus zero, failure counts, preserved peaks across rebinding and a fresh counter on a new connection. The wire-header check verifies the exact five fields and the disable switch. Local PostgreSQL-compatible PGlite checks exercise the actual migration: monotonic/idempotent upserts, zero/unknown, retention, account deletion, storage admission and client privilege denial. They do not simulate multi-process PostgreSQL lock contention. API unit checks cover post-response saves, bounded work, coalescing, final reports and swallowed storage failures.

A local native census timing check made 25 snapshots: median **5.197 ms**, p96 **5.420 ms**, maximum **5.478 ms**. This is a wall-time microbenchmark of the actual native count, not a CPU or in-game ping benchmark. At a five-second cadence the median wall-work ratio is about 0.104% of one core, but wall time must not be relabelled measured CPU usage. No game was launched, no desktop build was started and no production endpoint was contacted for this check. An active gameplay latency comparison is still unverified; do not claim zero ping impact. Normal packet handling and routing are unchanged.
