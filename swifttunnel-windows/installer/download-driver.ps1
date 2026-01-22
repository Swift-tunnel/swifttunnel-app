# Download Windows Packet Filter driver for bundling
# This script downloads the WinPkFilter MSI from GitHub releases

$ErrorActionPreference = "Stop"

# Create drivers directory if it doesn't exist
$driversDir = "..\dist\drivers"
if (!(Test-Path $driversDir)) {
    New-Item -ItemType Directory -Path $driversDir -Force | Out-Null
}

$driverMsi = "$driversDir\WinpkFilter-x64.msi"

# Check if already downloaded
if (Test-Path $driverMsi) {
    Write-Host "WinPkFilter driver already exists at $driverMsi"
    exit 0
}

# Download from GitHub releases
$downloadUrl = "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/WinpkFilter-x64.msi"
Write-Host "Downloading WinPkFilter driver from $downloadUrl..."

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $driverMsi -UseBasicParsing
    Write-Host "Downloaded successfully to $driverMsi"

    # Verify file size (should be several MB)
    $fileSize = (Get-Item $driverMsi).Length
    Write-Host "File size: $([math]::Round($fileSize / 1MB, 2)) MB"

    if ($fileSize -lt 1000000) {
        Write-Host "WARNING: File seems too small, download may have failed"
        exit 1
    }
}
catch {
    Write-Host "ERROR: Failed to download driver: $_"
    exit 1
}

Write-Host "Done!"
