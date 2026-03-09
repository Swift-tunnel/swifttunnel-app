$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

cargo build -p swifttunnel-core --release --bin split_tunnel_test

& ".\target\release\split_tunnel_test.exe" @args
exit $LASTEXITCODE
