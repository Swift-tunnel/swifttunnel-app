param(
    [string]$Region,
    [string]$Token,
    [string]$Email,
    [string]$Password,
    [string]$AdapterGuid,
    [string]$CustomRelay,
    [switch]$EnableApiTunneling,
    [string[]]$GamePreset,
    [string]$ReportPath,
    [int]$ConnectWaitMs,
    [switch]$Connect
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
. (Join-Path $PSScriptRoot "TestbenchHelpers.ps1")

Ensure-WinpkFilterBinding -AdapterGuid $AdapterGuid | Out-Null

cargo build -p swifttunnel-desktop --release --bin desktop_testbench_harness

$argsList = @()
if ($Region) { $argsList += @("--region", $Region) }
if ($Token) { $argsList += @("--token", $Token) }
if ($Email) { $argsList += @("--email", $Email) }
if ($Password) { $argsList += @("--password", $Password) }
if ($AdapterGuid) { $argsList += @("--adapter-guid", $AdapterGuid) }
if ($CustomRelay) { $argsList += @("--custom-relay", $CustomRelay) }
if ($EnableApiTunneling) { $argsList += "--enable-api-tunneling" }
if ($GamePreset) {
  foreach ($preset in $GamePreset) {
    $argsList += @("--game-preset", $preset)
  }
}
if ($ReportPath) { $argsList += @("--report", $ReportPath) }
if ($ConnectWaitMs) { $argsList += @("--connect-wait-ms", $ConnectWaitMs) }
if ($Connect) { $argsList += "--connect" }

& ".\target\release\desktop_testbench_harness.exe" @argsList
exit $LASTEXITCODE
