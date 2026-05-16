# SwiftTunnel App

Windows desktop VPN client built with Tauri v2 and `swifttunnel-core`.

## VPN Lifecycle Invariants

- A normal, non-custom relay connection is successful only when the driver is opened/configured, the relay context is installed, and the relay accepted a fresh ticket for the active `session_id`.
- `Connected` must never be set because the driver attached or a relay socket exists if relay-ticket acquisition or relay auth ack failed.
- Relay auth ack status `7` means replayed/stale ticket. Treat it as a structured auth failure for the current attempt; do not collapse it into generic `bad_format` text matching and do not reuse the ticket/session as success.
- Every failed connect after driver open must close the split-tunnel driver before returning to the UI.
- Auto Route relay swaps must be gated by the lookup session epoch and live `Connected` state immediately before applying a relay switch. Disconnect/reset wins the race.
- App exit must disconnect if either VPN state is not `Disconnected` or a split-tunnel handle still exists.
- Startup boost and FFlag reapply must remain skipped for banned accounts; banned cleanup owns VPN disconnect and boost restore.

## Failure-Mode Testing

For VPN, driver, relay auth, Auto Route, tray/exit, or banned-state recovery changes:

- Add a positive test for the repair or rollback path.
- Add at least one negative test for a superficially similar non-repairable signal.
- Use structured markers such as enum variants, auth error codes, state variants, and lookup epochs. Do not add new broad substring recovery triggers.
- Bound retry or repair loops and test that stale sessions/generations cannot keep applying changes forever.
