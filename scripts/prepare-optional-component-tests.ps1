$ErrorActionPreference = 'Stop'
# Download test inputs without installing or executing the optional tools.
# Pin the same upstream archive as release.yml, then let the Rust tests verify
# each file against the client manifest. Do not write into the source checkout.
if (-not $env:RUNNER_TEMP) { throw 'RUNNER_TEMP must point to CI scratch storage' }
$scratch = Join-Path $env:RUNNER_TEMP ('component-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$archive = Join-Path $scratch 'goodbyedpi-0.2.2.zip'
Invoke-WebRequest 'https://github.com/ValdikSS/GoodbyeDPI/releases/download/0.2.2/goodbyedpi-0.2.2.zip' -OutFile $archive
$expected = '00a2f8b99cd817f8c7fc4c449033015f039d18af213de78cb66bf202277c0628'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'Optional component archive did not match the pinned SHA-256'
}
Expand-Archive -LiteralPath $archive -DestinationPath $scratch
$env:SWIFTTUNNEL_TEST_COMPONENT_DIR = Join-Path $scratch 'goodbyedpi-0.2.2'
if (-not (Test-Path -LiteralPath $env:SWIFTTUNNEL_TEST_COMPONENT_DIR -PathType Container)) {
    throw 'Optional component archive is missing its expected directory'
}
