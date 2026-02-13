# Refresh environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Add cargo to current session
$cargoPath = Join-Path $env:USERPROFILE ".cargo\bin"
$env:Path += ";$cargoPath"

# Verify installation
cargo --version
rustc --version

Write-Host "`nRust is now ready! You can now run: cargo build --release" -ForegroundColor Green
