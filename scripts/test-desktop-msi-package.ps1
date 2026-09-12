param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
    [string]$Target = 'x86_64-pc-windows-msvc'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$WorkDir = [IO.Path]::GetFullPath($WorkDir)
if ($WorkDir.StartsWith($repo.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture output must be outside the repository'
}
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$archive = Join-Path $WorkDir 'wix314-binaries.zip'
$wix = Join-Path $WorkDir 'wix'
# Same official portable toolset and digest pinned by Tauri CLI v2.10.0.
$digest = '6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31'
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip' -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $digest) { throw 'WiX archive digest mismatch' }
Expand-Archive -LiteralPath $archive -DestinationPath $wix -Force
Push-Location $repo
try {
    $output = cargo build -p swifttunnel-msi-actions --release --target $Target --message-format=json-render-diagnostics
    if ($LASTEXITCODE -ne 0) { throw 'MSI action DLL build failed' }
    $dlls = @($output | ForEach-Object {
        $message = $_ | ConvertFrom-Json
        if ($message.reason -eq 'compiler-artifact' -and $message.target.name -eq 'swifttunnel_msi_actions') {
            $message.filenames | Where-Object { $_.EndsWith('.dll') }
        }
    })
    if ($dlls.Count -ne 1) { throw 'Expected exactly one freshly built action DLL' }
    $dll = $dlls[0]
    $pe = [IO.File]::ReadAllBytes($dll)
    $offset = [BitConverter]::ToInt32($pe, 0x3c)
    $machine = [BitConverter]::ToUInt16($pe, $offset + 4)
    $expected = if ($Target.StartsWith('aarch64')) { 0xaa64 } else { 0x8664 }
    if ($machine -ne $expected) { throw 'Action DLL architecture does not match the MSI target' }
    cargo run -p swifttunnel-msi-actions --example render_sequence_fixture -- $WorkDir
    if ($LASTEXITCODE -ne 0) { throw 'Desktop template render failed' }
} finally { Pop-Location }
$previousDll = $env:SWIFTTUNNEL_MSI_ACTIONS_DLL
$env:SWIFTTUNNEL_MSI_ACTIONS_DLL = $dll
$arch = if ($Target.StartsWith('aarch64')) { 'arm64' } else { 'x64' }
Push-Location $WorkDir
try {
    & "$wix/candle.exe" -nologo -arch $arch -ext WixUtilExtension main.wxs `
        "$repo/swifttunnel-desktop/src-tauri/wix/nsis-migration.wxs" "$repo/swifttunnel-desktop/src-tauri/wix/lite.wxs"
    if ($LASTEXITCODE -ne 0) { throw 'WiX fixture compile failed' }
    & "$wix/light.exe" -nologo -wx -ice:ICE63 -ext WixUIExtension -ext WixUtilExtension `
        -cultures:en-us -loc fixture.wxl -out desktop-sequence-fixture.msi main.wixobj nsis-migration.wixobj lite.wixobj
    if ($LASTEXITCODE -ne 0) { throw 'WiX upgrade sequencing validation failed' }
    & "$PSScriptRoot/check-desktop-msi-sequence.ps1" -Msi desktop-sequence-fixture.msi
    $fixtureInstaller = New-Object -ComObject WindowsInstaller.Installer
    $fixtureDb = $fixtureInstaller.OpenDatabase((Join-Path $WorkDir 'desktop-sequence-fixture.msi'), 0)
    $guard = $fixtureDb.OpenView('SELECT `Condition` FROM `LaunchCondition`')
    $guard.Execute()
    $guardFound = $false
    while ($row = $guard.Fetch()) { if ($row.StringData(1) -eq '0') { $guardFound = $true } }
    if (-not $guardFound) { throw 'Fixture must refuse actual installation' }
} finally {
    Pop-Location
    $env:SWIFTTUNNEL_MSI_ACTIONS_DLL = $previousDll
}
