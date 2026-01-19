# Build script for SwiftTunnel FPS Booster
# This script sets up the Visual Studio environment and builds the project

# Find and run vcvarsall.bat to set up the environment
$vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if (Test-Path $vsPath) {
    Write-Host "Setting up Visual Studio environment..." -ForegroundColor Cyan

    # Run vcvars64.bat and capture the environment
    $output = cmd /c "`"$vsPath`" && set"

    foreach ($line in $output) {
        if ($line -match "^([^=]+)=(.*)$") {
            $name = $matches[1]
            $value = $matches[2]
            [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }

    Write-Host "Environment set up successfully!" -ForegroundColor Green
} else {
    Write-Host "Visual Studio Build Tools not found at expected path." -ForegroundColor Red
    Write-Host "Attempting to find alternative..." -ForegroundColor Yellow

    # Try to find vcvarsall.bat in common locations
    $possiblePaths = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    )

    $found = $false
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            Write-Host "Found: $path" -ForegroundColor Green
            $output = cmd /c "`"$path`" && set"
            foreach ($line in $output) {
                if ($line -match "^([^=]+)=(.*)$") {
                    [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
                }
            }
            $found = $true
            break
        }
    }

    if (-not $found) {
        Write-Host "Could not find Visual Studio. Please install Visual Studio Build Tools." -ForegroundColor Red
        exit 1
    }
}

# Add Cargo to path if not already there
$cargoPath = Join-Path $env:USERPROFILE ".cargo\bin"
if ($env:Path -notlike "*$cargoPath*") {
    $env:Path += ";$cargoPath"
}

# Clean previous build artifacts if they exist
Write-Host "`nCleaning previous build..." -ForegroundColor Cyan
cargo clean 2>$null

# Build the project
Write-Host "`nBuilding SwiftTunnel FPS Booster..." -ForegroundColor Cyan
cargo build --release

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Build successful!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green

    # Download and copy wintun.dll if not present
    $wintunDll = "target\release\wintun.dll"
    $wintunZip = "target\release\wintun.zip"
    $wintunDir = "target\release\wintun"

    if (-not (Test-Path $wintunDll)) {
        Write-Host "`nDownloading Wintun..." -ForegroundColor Cyan

        # Download wintun from official source
        $wintunUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip"

        try {
            Invoke-WebRequest -Uri $wintunUrl -OutFile $wintunZip
            Expand-Archive -Path $wintunZip -DestinationPath "target\release" -Force

            # Copy correct architecture DLL
            $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }
            Copy-Item "$wintunDir\bin\$arch\wintun.dll" $wintunDll -Force

            Write-Host "Wintun DLL installed successfully!" -ForegroundColor Green
        } catch {
            Write-Host "Failed to download Wintun: $_" -ForegroundColor Red
            Write-Host "Please manually download from https://www.wintun.net/" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Wintun DLL already present." -ForegroundColor Gray
    }

    # Download split tunnel driver if not present
    $driverDir = "drivers"
    $driverFile = "$driverDir\mullvad-split-tunnel.sys"

    if (-not (Test-Path $driverFile)) {
        Write-Host "`nDownloading Mullvad Split Tunnel driver..." -ForegroundColor Cyan

        # Note: The driver needs to be downloaded from Mullvad VPN releases
        # and requires code signing. For development, we'll note this.
        Write-Host "NOTE: Split tunnel driver requires manual download." -ForegroundColor Yellow
        Write-Host "Download from: https://github.com/mullvad/mullvadvpn-app/releases" -ForegroundColor Yellow
        Write-Host "Extract: windows/x64/mullvad-split-tunnel.sys" -ForegroundColor Yellow

        if (-not (Test-Path $driverDir)) {
            New-Item -ItemType Directory -Path $driverDir | Out-Null
        }
    } else {
        Write-Host "Split tunnel driver present." -ForegroundColor Gray
    }

    # Create distribution folder
    $distDir = "dist"
    Write-Host "`nCreating distribution package..." -ForegroundColor Cyan

    if (Test-Path $distDir) {
        Remove-Item $distDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $distDir | Out-Null
    New-Item -ItemType Directory -Path "$distDir\drivers" | Out-Null

    # Copy required files
    Copy-Item "target\release\swifttunnel-fps-booster.exe" "$distDir\" -Force
    Copy-Item "target\release\wintun.dll" "$distDir\" -Force

    # Copy driver if present
    if (Test-Path $driverFile) {
        Copy-Item $driverFile "$distDir\drivers\" -Force
        Write-Host "  - drivers\mullvad-split-tunnel.sys" -ForegroundColor White
    }

    # Get file sizes
    $exeSize = (Get-Item "$distDir\swifttunnel-fps-booster.exe").Length / 1MB
    $dllSize = (Get-Item "$distDir\wintun.dll").Length / 1MB
    $totalSize = $exeSize + $dllSize

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Distribution package created in: dist\" -ForegroundColor Green
    Write-Host "Contents:" -ForegroundColor Cyan
    Write-Host "  - swifttunnel-fps-booster.exe ({0:N2} MB)" -f $exeSize -ForegroundColor White
    Write-Host "  - wintun.dll ({0:N2} MB)" -f $dllSize -ForegroundColor White
    Write-Host "  Total size: {0:N2} MB" -f $totalSize -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host "`nBuild failed with exit code $LASTEXITCODE" -ForegroundColor Red
}
