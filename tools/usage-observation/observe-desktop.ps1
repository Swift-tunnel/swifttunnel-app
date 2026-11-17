[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Config,
    [Parameter(Mandatory=$true)][string]$OutFile,
    [ValidateRange(1,86400)][int]$DurationSeconds=600,
    [ValidateRange(5,60)][int]$IntervalSeconds=5,
    [ValidateRange(1,256)][int]$MaxFileMiB=32
)
$ErrorActionPreference='Stop'
$participant=Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
if ($participant.schema -ne 1 -or $participant.campaign -notmatch '^[0-9a-f]{32}$' -or
    $participant.account -notmatch '^[0-9a-f]{64}$' -or $participant.device -notmatch '^[0-9a-f]{64}$') {
    throw 'Invalid measurement participant file.'
}
$absolute=[IO.Path]::GetFullPath($OutFile)
if ($absolute -match '(?i)[\\/]OneDrive([\\/]|$)') { throw 'Use the local swift audit folder, outside OneDrive.' }
if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($absolute))) { throw 'Create the output directory first.' }
Add-Type -Path (Join-Path $PSScriptRoot 'WindowsCounts.cs')
$observer=[Diagnostics.Process]::GetCurrentProcess()
try { $observer.PriorityClass=[Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}
$stream=[IO.File]::Open($absolute,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$writer=New-Object IO.StreamWriter($stream,(New-Object Text.UTF8Encoding($false)),65536)
$clock=[Diagnostics.Stopwatch]::StartNew()
$cpuStart=$observer.TotalProcessorTime.TotalMilliseconds
$session=[Guid]::NewGuid().ToString('N')
$next=0L
$lastFlush=0L
$samples=0
$writtenBytes=0L
try {
    while ($clock.Elapsed.TotalSeconds -lt $DurationSeconds) {
        $timer=[Diagnostics.Stopwatch]::StartNew()
        $counts=[SwiftTunnel.UsageObservation.WindowsCounts]::Capture()
        $timer.Stop()
        $record=[ordered]@{
            schema=1;kind='desktop';campaign=$participant.campaign;account=$participant.account;device=$participant.device
            session=$session;unix_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();mono_ms=$clock.ElapsedMilliseconds;interval_ms=$IntervalSeconds*1000
            valid=$counts.Valid;players=$null;players_with_udp=$null;studio=$null;helpers=$null;studio_descendant_players=$null
            process_error=$counts.ProcessError;udp4_error=$counts.Udp4Error;udp6_error=$counts.Udp6Error
            sample_wall_ms=[Math]::Round($timer.Elapsed.TotalMilliseconds,3)
        }
        if ($counts.Valid) {
            $record.players=$counts.Players;$record.players_with_udp=$counts.PlayersWithUdp
            $record.studio=$counts.Studio;$record.helpers=$counts.Helpers;$record.studio_descendant_players=$counts.StudioDescendantPlayers
        }
        $line=$record | ConvertTo-Json -Compress
        $lineBytes=[Text.Encoding]::UTF8.GetByteCount($line)+[Text.Encoding]::UTF8.GetByteCount($writer.NewLine)
        if ($writtenBytes+$lineBytes+4096 -ge $MaxFileMiB*1MB) { break }
        $writer.WriteLine($line)
        $writtenBytes+=$lineBytes
        $samples++
        if ($clock.ElapsedMilliseconds-$lastFlush -ge 60000) { $writer.Flush();$lastFlush=$clock.ElapsedMilliseconds }
        $next += $IntervalSeconds*1000
        $remaining=[Math]::Min($next-$clock.ElapsedMilliseconds,$DurationSeconds*1000-$clock.ElapsedMilliseconds)
        if ($remaining -gt 0) { [Threading.Thread]::Sleep([int]$remaining) }
        else { $next=$clock.ElapsedMilliseconds }
    }
} finally {
    $summary=[ordered]@{schema=1;kind='observer_summary';campaign=$participant.campaign;session=$session;samples=$samples
        wall_ms=$clock.ElapsedMilliseconds;cpu_ms=$observer.TotalProcessorTime.TotalMilliseconds-$cpuStart}
    $writer.WriteLine(($summary | ConvertTo-Json -Compress))
    $writer.Dispose()
    $stream.Dispose()
}
Write-Output ('Local measurement saved: '+$absolute)
