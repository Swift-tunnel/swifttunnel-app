# Velopack build & packaging script for SwiftTunnel
# Usage: .\build-velopack.ps1 -Version 1.0.16
#
# Prerequisites:
#   - .NET SDK 8+: winget install Microsoft.DotNet.SDK.8
#   - vpk CLI:     dotnet tool install -g vpk
#   - Rust:        https://rustup.rs
#   - VS Build Tools 2019+

param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ProjectRoot

$Target = "x86_64-pc-windows-msvc"
$ReleaseDir = "target\$Target\release"
$StagingDir = "$ProjectRoot\_velopack_staging"
$OutputDir = "$ProjectRoot\releases"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SwiftTunnel Velopack Build  v$Version" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Check prerequisites ──────────────────────────────────────────────

Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

# Cargo
$cargoPath = Join-Path $env:USERPROFILE ".cargo\bin"
if ($env:Path -notlike "*$cargoPath*") {
    $env:Path = "$cargoPath;$env:Path"
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found. Install Rust from https://rustup.rs" -ForegroundColor Red
    exit 1
}
Write-Host "  cargo  : $(cargo --version)" -ForegroundColor Gray

# vpk
if (-not (Get-Command vpk -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: vpk not found." -ForegroundColor Red
    Write-Host "  Install .NET SDK 8: winget install Microsoft.DotNet.SDK.8" -ForegroundColor Yellow
    Write-Host "  Then install vpk:   dotnet tool install -g vpk" -ForegroundColor Yellow
    exit 1
}
Write-Host "  vpk    : found" -ForegroundColor Gray

# Visual Studio Build Tools
$vsSearchPaths = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
)

$vcvarsall = $null
foreach ($path in $vsSearchPaths) {
    if (Test-Path $path) {
        $vcvarsall = $path
        break
    }
}

if (-not $vcvarsall) {
    Write-Host "ERROR: Visual Studio Build Tools not found." -ForegroundColor Red
    Write-Host "  Install VS 2019 or 2022 Build Tools with C++ workload." -ForegroundColor Yellow
    exit 1
}
Write-Host "  VS     : $vcvarsall" -ForegroundColor Gray

# Icon file
$iconPath = "$ProjectRoot\dist\swifttunnel.ico"
if (-not (Test-Path $iconPath)) {
    Write-Host "ERROR: Icon not found at dist\swifttunnel.ico" -ForegroundColor Red
    exit 1
}
Write-Host "  icon   : dist\swifttunnel.ico" -ForegroundColor Gray

Write-Host "  All prerequisites OK" -ForegroundColor Green

# ── Step 2: Set up VS environment ────────────────────────────────────────────

Write-Host ""
Write-Host "[2/6] Setting up Visual Studio environment..." -ForegroundColor Yellow

# Ensure vswhere.exe is in PATH (vcvarsall.bat needs it)
$vsInstallerDir = "C:\Program Files (x86)\Microsoft Visual Studio\Installer"
if ((Test-Path $vsInstallerDir) -and ($env:Path -notlike "*$vsInstallerDir*")) {
    $env:Path = "$vsInstallerDir;$env:Path"
}

$envOutput = cmd /c "`"$vcvarsall`" x64 && set" 2>&1
foreach ($line in $envOutput) {
    if ($line -match "^([^=]+)=(.*)$") {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}
Write-Host "  VS environment loaded" -ForegroundColor Green

# ── Step 3: Build release ────────────────────────────────────────────────────

Write-Host ""
Write-Host "[3/6] Building release (target: $Target)..." -ForegroundColor Yellow
Write-Host "  This may take a few minutes..." -ForegroundColor Gray

cargo build --release --target $Target

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: cargo build failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}
Write-Host "  Build succeeded" -ForegroundColor Green

# ── Step 4: Verify build outputs ─────────────────────────────────────────────

Write-Host ""
Write-Host "[4/6] Verifying build outputs..." -ForegroundColor Yellow

$mainExe = "$ReleaseDir\swifttunnel-fps-booster.exe"
if (-not (Test-Path $mainExe)) {
    Write-Host "ERROR: swifttunnel-fps-booster.exe not found in $ReleaseDir" -ForegroundColor Red
    exit 1
}
$mainExeSize = (Get-Item $mainExe).Length / 1MB
Write-Host ("  swifttunnel-fps-booster.exe  ({0:N2} MB)" -f $mainExeSize) -ForegroundColor Gray

$driverExe = "$ReleaseDir\driver-installer.exe"
if (Test-Path $driverExe) {
    $driverExeSize = (Get-Item $driverExe).Length / 1MB
    Write-Host ("  driver-installer.exe         ({0:N2} MB)" -f $driverExeSize) -ForegroundColor Gray
} else {
    Write-Host "  driver-installer.exe         (not found - skipping)" -ForegroundColor DarkYellow
}

# ── Step 5: Create staging directory ─────────────────────────────────────────

Write-Host ""
Write-Host "[5/6] Creating staging directory..." -ForegroundColor Yellow

if (Test-Path $StagingDir) {
    Remove-Item $StagingDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StagingDir | Out-Null
New-Item -ItemType Directory -Path "$StagingDir\drivers" | Out-Null

# Copy main exe
Copy-Item $mainExe "$StagingDir\" -Force
Write-Host "  Staged: swifttunnel-fps-booster.exe" -ForegroundColor Gray

# Copy driver-installer if it exists
if (Test-Path $driverExe) {
    Copy-Item $driverExe "$StagingDir\" -Force
    Write-Host "  Staged: driver-installer.exe" -ForegroundColor Gray
}

# Copy wintun.dll from dist/
$wintunSrc = "$ProjectRoot\dist\wintun.dll"
if (-not (Test-Path $wintunSrc)) {
    Write-Host "ERROR: wintun.dll not found at dist\wintun.dll" -ForegroundColor Red
    Write-Host "  Download from https://www.wintun.net/builds/wintun-0.14.1.zip" -ForegroundColor Yellow
    Write-Host "  Extract wintun\bin\amd64\wintun.dll to dist\wintun.dll" -ForegroundColor Yellow
    exit 1
}
Copy-Item $wintunSrc "$StagingDir\" -Force
Write-Host "  Staged: wintun.dll" -ForegroundColor Gray

# Copy or download WinpkFilter driver MSI
$driverMsiSrc = "$ProjectRoot\dist\drivers\WinpkFilter-x64.msi"
if (-not (Test-Path $driverMsiSrc)) {
    Write-Host "  Downloading WinpkFilter driver MSI..." -ForegroundColor Cyan
    $driverUrl = "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/WinpkFilter-x64.msi"
    New-Item -ItemType Directory -Path "$ProjectRoot\dist\drivers" -Force | Out-Null
    try {
        Invoke-WebRequest -Uri $driverUrl -OutFile $driverMsiSrc -UseBasicParsing
        $dlSize = (Get-Item $driverMsiSrc).Length
        if ($dlSize -lt 1000000) {
            Write-Host "ERROR: Downloaded driver MSI is too small ($dlSize bytes) - download may have failed" -ForegroundColor Red
            exit 1
        }
        Write-Host ("  Downloaded WinpkFilter-x64.msi ({0:N2} MB)" -f ($dlSize / 1MB)) -ForegroundColor Gray
    } catch {
        Write-Host "ERROR: Failed to download WinpkFilter driver: $_" -ForegroundColor Red
        Write-Host "  Manually download from: https://github.com/wiresock/ndisapi/releases" -ForegroundColor Yellow
        exit 1
    }
}
Copy-Item $driverMsiSrc "$StagingDir\drivers\" -Force
Write-Host "  Staged: drivers\WinpkFilter-x64.msi" -ForegroundColor Gray

# Summary of staging
$stagedFiles = Get-ChildItem $StagingDir -Recurse -File
$totalSize = ($stagedFiles | Measure-Object -Property Length -Sum).Sum / 1MB
Write-Host ("  Staging complete: {0} files, {1:N2} MB total" -f $stagedFiles.Count, $totalSize) -ForegroundColor Green

# ── Step 6: Run vpk pack ─────────────────────────────────────────────────────

Write-Host ""
Write-Host "[6/6] Packaging with Velopack..." -ForegroundColor Yellow

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

vpk pack `
    -u SwiftTunnel `
    -v $Version `
    -p $StagingDir `
    -e swifttunnel-fps-booster.exe `
    --icon "$ProjectRoot\dist\swifttunnel.ico" `
    -o $OutputDir

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: vpk pack failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

# ── Done ─────────────────────────────────────────────────────────────────────

# Clean up staging directory
Remove-Item $StagingDir -Recurse -Force

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Velopack packaging complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output directory: releases\" -ForegroundColor Cyan

if (Test-Path $OutputDir) {
    $outputFiles = Get-ChildItem $OutputDir -File
    foreach ($file in $outputFiles) {
        $size = $file.Length / 1MB
        Write-Host ("  {0}  ({1:N2} MB)" -f $file.Name, $size) -ForegroundColor White
    }
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Create a GitHub release for v$Version" -ForegroundColor Gray
Write-Host "  2. Upload all files from releases\ as release assets" -ForegroundColor Gray
Write-Host "  3. The app's auto-updater will find releases.win.json automatically" -ForegroundColor Gray
Write-Host ""
