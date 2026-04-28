param(
    [string]$Region,
    [string]$Token,
    [string]$Email,
    [string]$Password,
    [string]$AdapterGuid,
    [string]$CustomRelay,
    [switch]$EnableApiTunneling,
    [switch]$UdpExpectResponses,
    [string]$UdpTarget,
    [int]$UdpCount,
    [int]$UdpPayloadBytes,
    [string]$TcpTarget,
    [int]$TcpCount
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
. (Join-Path $PSScriptRoot "TestbenchHelpers.ps1")

Ensure-WinpkFilterBinding -AdapterGuid $AdapterGuid | Out-Null

cargo build -p swifttunnel-core --release --bin split_tunnel_integration_test --bin ip_checker

$argsList = @()
if ($Region) { $argsList += @("--region", $Region) }
if ($Token) { $argsList += @("--token", $Token) }
if ($Email) { $argsList += @("--email", $Email) }
if ($Password) { $argsList += @("--password", $Password) }
if ($AdapterGuid) { $argsList += @("--adapter-guid", $AdapterGuid) }
if ($CustomRelay) { $argsList += @("--custom-relay", $CustomRelay) }
if ($EnableApiTunneling) { $argsList += "--enable-api-tunneling" }
if ($UdpExpectResponses) { $argsList += "--udp-expect-responses" }
if ($UdpTarget) { $argsList += @("--udp-target", $UdpTarget) }
if ($UdpCount) { $argsList += @("--udp-count", $UdpCount) }
if ($UdpPayloadBytes) { $argsList += @("--udp-payload-bytes", $UdpPayloadBytes) }
if ($TcpTarget) { $argsList += @("--tcp-target", $TcpTarget) }
if ($TcpCount) { $argsList += @("--tcp-count", $TcpCount) }

& ".\target\release\split_tunnel_integration_test.exe" @argsList
exit $LASTEXITCODE
