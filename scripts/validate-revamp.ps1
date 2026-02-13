param(
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Run-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    $global:LASTEXITCODE = 0
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "Step failed with exit code ${LASTEXITCODE}: $Name"
    }
    Write-Host "OK: $Name" -ForegroundColor Green
}

Push-Location $WorkspaceRoot
try {
    Run-Step -Name "Format Check" -Action {
        cargo fmt --all -- --check
    }

    Run-Step -Name "Core Region Resolver Tests" -Action {
        cargo test -p swifttunnel-core test_resolve_relay_server -- --nocapture
    }

    Run-Step -Name "Updater Channel/Security Tests" -Action {
        cargo test -p swifttunnel-desktop updater::tests:: -- --nocapture
    }

    Run-Step -Name "Frontend Build" -Action {
        Push-Location (Join-Path $WorkspaceRoot "swifttunnel-desktop")
        try {
            npm run build
        }
        finally {
            Pop-Location
        }
    }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Validation completed successfully." -ForegroundColor Green
