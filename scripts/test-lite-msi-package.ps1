param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [Parameter(Mandatory = $true)][string]$WixDir,
    [Parameter(Mandatory = $true)][string]$MsiActionsPath,
    [ValidateSet('x64', 'arm64')][string]$Architecture = 'x64'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$WorkDir = [IO.Path]::GetFullPath($WorkDir)
$WixDir = [IO.Path]::GetFullPath($WixDir)
$MsiActionsPath = (Resolve-Path -LiteralPath $MsiActionsPath).Path
$pe = [IO.File]::ReadAllBytes($MsiActionsPath)
$machine = [BitConverter]::ToUInt16($pe, [BitConverter]::ToInt32($pe, 0x3c) + 4)
$expected = if ($Architecture -eq "arm64") { 0xaa64 } else { 0x8664 }
if ($machine -ne $expected) { throw "Action DLL architecture mismatch" }
if ($WorkDir.StartsWith($repo.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture output must be outside the repository'
}
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
# Inert payloads and an unconditional launch failure prevent accidental install.
foreach ($name in @('lite.exe', 'ndisrd_lwf.inf', 'ndisrd.sys', 'ndisrd.cat')) {
    [IO.File]::WriteAllText((Join-Path $WorkDir $name), 'Non-installable MSI packaging fixture')
}
$source = Get-Content -LiteralPath "$repo/swifttunnel-lite/wix/product.wxs" -Raw
$source = $source.Replace('<Media Id="1"', '<Condition Message="Packaging fixture cannot be installed">0</Condition><Media Id="1"')
[IO.File]::WriteAllText((Join-Path $WorkDir 'product.wxs'), $source)
Push-Location $WorkDir
try {
    & "$WixDir/candle.exe" -nologo -arch $Architecture "-dVersion=3.1.5" `
        "-dMsiActionsPath=$MsiActionsPath" "-dLitePath=$WorkDir/lite.exe" "-dDriverDir=$WorkDir" "-dDriverArch=$Architecture" `
        "-dIconPath=$repo/swifttunnel-lite/resources/icon.ico" product.wxs "$repo/installer/SwiftSetupUI.wxs"
    if ($LASTEXITCODE -ne 0) { throw 'Lite MSI compile failed' }
    & "$WixDir/light.exe" -nologo -wx -ice:ICE20 -ice:ICE31 -ice:ICE44 -ice:ICE63 -ext WixUIExtension -out lite-fixture.msi product.wixobj SwiftSetupUI.wixobj
    if ($LASTEXITCODE -ne 0) { throw 'Lite MSI link failed' }
    & "$PSScriptRoot/check-installer-ui.ps1" -Msi lite-fixture.msi
    & "$PSScriptRoot/check-desktop-msi-sequence.ps1" -Msi lite-fixture.msi -Product Lite
} finally { Pop-Location }

