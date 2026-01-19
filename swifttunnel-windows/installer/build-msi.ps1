# SwiftTunnel MSI Builder
# Requires WiX Toolset v3.11+ to be installed

param(
    [string]$WixPath = "C:\Program Files (x86)\WiX Toolset v3.14\bin"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistDir = Join-Path (Split-Path -Parent $ScriptDir) "dist"
$OutputDir = Join-Path $ScriptDir "output"

Write-Host "SwiftTunnel MSI Builder" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan

# Check WiX installation
if (-not (Test-Path (Join-Path $WixPath "candle.exe"))) {
    Write-Host "WiX Toolset not found at: $WixPath" -ForegroundColor Red
    Write-Host "Please install WiX Toolset v3.11+ from https://wixtoolset.org/" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Or download portable WiX:" -ForegroundColor Yellow
    Write-Host "  winget install WixToolset.WixToolset --version 3.14.0.6526" -ForegroundColor White
    exit 1
}

# Check source files
if (-not (Test-Path (Join-Path $DistDir "swifttunnel-fps-booster.exe"))) {
    Write-Host "Source files not found in dist folder. Please build first." -ForegroundColor Red
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

Write-Host "Compiling WiX source..." -ForegroundColor Yellow
$candleExe = Join-Path $WixPath "candle.exe"
$lightExe = Join-Path $WixPath "light.exe"
$wxsFile = Join-Path $ScriptDir "SwiftTunnel.wxs"
$wixobjFile = Join-Path $OutputDir "SwiftTunnel.wixobj"
$msiFile = Join-Path $OutputDir "SwiftTunnel-Setup.msi"

# Run candle (compiler)
& $candleExe -arch x64 -dSourceDir="$DistDir" -out $wixobjFile $wxsFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "WiX compilation failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Linking MSI package..." -ForegroundColor Yellow
# Run light (linker) with WixUIExtension for install dialog
& $lightExe -ext WixUIExtension -out $msiFile $wixobjFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "WiX linking failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "MSI package created successfully!" -ForegroundColor Green
Write-Host "Output: $msiFile" -ForegroundColor White
$msiSize = (Get-Item $msiFile).Length / 1MB
Write-Host "Size: $([math]::Round($msiSize, 2)) MB" -ForegroundColor White
