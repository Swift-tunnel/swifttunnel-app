# Windows Split Tunnel Testbench

This folder is now a source-backed testbench for the current `ndisapi` / `NDISRD`
split tunnel stack.

The previous precompiled binaries were tied to the removed
`MullvadSplitTunnel` interface and are no longer valid for release gating.
Build the maintained testbench binaries from `swifttunnel-core` instead.

## Binaries

`cargo build -p swifttunnel-core --release --bin split_tunnel_test`

`cargo build -p swifttunnel-core --release --bin split_tunnel_integration_test`

`cargo build -p swifttunnel-core --release --bin ip_checker`

## Quick Start

PowerShell:

```powershell
cd <repo-root>

.\\Windows-testbench\\run_split_tunnel_test.ps1
.\\Windows-testbench\\run_split_tunnel_integration_test.ps1 `
  -Email $env:SWIFTTUNNEL_TEST_EMAIL `
  -Password $env:SWIFTTUNNEL_TEST_PASSWORD
```

If a valid SwiftTunnel auth session already exists on the machine, the
integration test can reuse it and does not need explicit credentials.

## Environment Variables

- `SWIFTTUNNEL_TEST_ACCESS_TOKEN`
- `SWIFTTUNNEL_TEST_EMAIL`
- `SWIFTTUNNEL_TEST_PASSWORD`
- `SWIFTTUNNEL_TEST_REGION`
- `SWIFTTUNNEL_TEST_ADAPTER_GUID`

## What The Tests Validate

`split_tunnel_test`

- WinpkFilter / `NDISRD` driver is available
- mandatory adapter binding preflight returns `ok`

`split_tunnel_integration_test`

- binding preflight returns `ok`
- the test process stays on the original public IP after connect
- a selected helper process (`ip_checker.exe`) generates tunneled UDP packets
- split tunnel diagnostics show tunneled packet counters increasing

This matches the current V3 architecture more closely than the retired
full-tunnel / Wintun-era harness.
