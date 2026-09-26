param([Parameter(Mandatory = $true)][string[]]$Binary)
$ErrorActionPreference = 'Stop'

# Inspect the final PE imports, including delay-load imports. Build flags alone
# do not prove a native dependency did not reintroduce the redistributable.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$dumpbin = & $vswhere -latest -products '*' -find 'VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe' |
    Select-Object -First 1
if (-not $dumpbin) { throw 'dumpbin was not found in the Visual Studio C++ tools' }
foreach ($path in $Binary) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Binary missing: $path" }
    $imports = & $dumpbin /nologo /dependents $path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect PE dependencies: $path" }
    $externalRuntime = $imports | Select-String -Pattern '\b(?:vcruntime|msvcp|concrt)\d[^\s]*\.dll\b'
    if ($externalRuntime) {
        throw "$path requires an unbundled Visual C++ runtime: $($externalRuntime.Line.Trim() -join ', ')"
    }
    Write-Host "VC runtime check passed: $path"
}
