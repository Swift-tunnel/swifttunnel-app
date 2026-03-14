# Windows Testbench

This folder contains source-backed Windows testbench entrypoints for both the
desktop app harness and the current `ndisapi` / `NDISRD` split tunnel stack.

The previous precompiled binaries were tied to the removed
`MullvadSplitTunnel` interface and are no longer valid for release gating.
Build the maintained testbench binaries from source instead.

The PowerShell wrappers also repair the WinpkFilter (`nt_ndisrd`) binding on
the active/default-route adapter before running. This matters on some VMs where
the driver service is installed but the filter is disabled on the real NIC,
which otherwise makes preflight fall back to WAN pseudo-adapters that capture no
traffic. The app now performs the same validation during split-tunnel startup,
so a disabled binding no longer yields a silent "connected but 0 packets" run.

## Binaries

`cargo build -p swifttunnel-desktop --release --bin desktop_testbench_harness`

`cargo build -p swifttunnel-core --release --bin split_tunnel_test`

`cargo build -p swifttunnel-core --release --bin split_tunnel_integration_test`

`cargo build -p swifttunnel-core --release --bin ip_checker`

## Quick Start

PowerShell:

```powershell
cd <repo-root>

.\\Windows-testbench\\run_desktop_testbench_harness.ps1 `
  -ReportPath "$env:TEMP\\swifttunnel-desktop-harness.json"
.\\Windows-testbench\\run_split_tunnel_test.ps1
.\\Windows-testbench\\run_split_tunnel_integration_test.ps1 `
  -CustomRelay "45.32.115.254:51821" `
  -Email $env:SWIFTTUNNEL_TEST_EMAIL `
  -Password $env:SWIFTTUNNEL_TEST_PASSWORD
```

To include a full connect / disconnect pass in the desktop harness:

```powershell
.\\Windows-testbench\\run_desktop_testbench_harness.ps1 `
  -Connect `
  -CustomRelay "45.32.115.254:51821" `
  -GamePreset roblox `
  -Email $env:SWIFTTUNNEL_TEST_EMAIL `
  -Password $env:SWIFTTUNNEL_TEST_PASSWORD `
  -ReportPath "$env:TEMP\\swifttunnel-desktop-harness-connect.json"
```

If a valid SwiftTunnel auth session already exists on the machine, the
desktop harness and the integration test can reuse it and do not need explicit
credentials.

## Environment Variables

- `SWIFTTUNNEL_TEST_ACCESS_TOKEN`
- `SWIFTTUNNEL_TEST_EMAIL`
- `SWIFTTUNNEL_TEST_PASSWORD`
- `SWIFTTUNNEL_TEST_REGION`
- `SWIFTTUNNEL_TEST_ADAPTER_GUID`
- `SWIFTTUNNEL_TEST_CUSTOM_RELAY`
- `SWIFTTUNNEL_TEST_ENABLE_API_TUNNELING`

## What The Tests Validate

`desktop_testbench_harness`

- desktop startup bootstrap can initialize on the Windows VM
- crash-recovery startup steps can run without the GUI launcher path
- server list loading, auth refresh, driver check, and adapter binding preflight
  can be exercised from the desktop crate
- an optional connect / disconnect smoke pass can be driven with the same
  auth/session inputs used by the existing testbench flow
- a structured report file can be written for unattended runs
- the wrapper returns the harness exit code so it can gate CI-like scripts

`split_tunnel_test`

- WinpkFilter / `NDISRD` driver is available
- wrapper ensures `nt_ndisrd` is enabled on the active adapter before the test
- mandatory adapter binding preflight returns `ok`

`split_tunnel_integration_test`

- wrapper ensures `nt_ndisrd` is enabled on the active adapter before connect
- binding preflight returns `ok`
- optional `--custom-relay` / `SWIFTTUNNEL_TEST_CUSTOM_RELAY` targets a specific relay
- the test process stays on the original public IP after connect
- a selected helper process (`ip_checker.exe`) generates tunneled UDP packets
- split tunnel diagnostics show tunneled packet counters increasing

This matches the current V3 architecture more closely than the retired
full-tunnel / Wintun-era harness.
