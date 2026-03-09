param(
    [string]$Region,
    [string]$Token,
    [string]$Email,
    [string]$Password,
    [string]$AdapterGuid,
    [string]$UdpTarget,
    [int]$UdpCount
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

cargo build -p swifttunnel-core --release --bin split_tunnel_integration_test --bin ip_checker

$argsList = @()
if ($Region) { $argsList += @("--region", $Region) }
if ($Token) { $argsList += @("--token", $Token) }
if ($Email) { $argsList += @("--email", $Email) }
if ($Password) { $argsList += @("--password", $Password) }
if ($AdapterGuid) { $argsList += @("--adapter-guid", $AdapterGuid) }
if ($UdpTarget) { $argsList += @("--udp-target", $UdpTarget) }
if ($UdpCount) { $argsList += @("--udp-count", $UdpCount) }

& ".\target\release\split_tunnel_integration_test.exe" @argsList
exit $LASTEXITCODE
