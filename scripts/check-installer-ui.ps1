param([Parameter(Mandatory = $true)][string]$Msi)
$ErrorActionPreference = 'Stop'
# Inspect the compiled database, without opening UI or installing the fixture.
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.OpenDatabase((Resolve-Path -LiteralPath $Msi).Path, 0)
function Rows([string]$query, [int]$fields) {
    $view = $db.OpenView($query)
    $null = $view.Execute()
    while ($row = $view.Fetch()) {
        $values = @()
        for ($i = 1; $i -le $fields; $i++) { $values += $row.StringData($i) }
        ,$values
    }
    $null = $view.Close()
}
$dialogs = @{}
foreach ($row in (Rows 'SELECT `Dialog`, `Width`, `Height` FROM `Dialog`' 3)) { $dialogs[$row[0]] = $row }
foreach ($name in @('SwiftWelcome', 'SwiftMaintenance', 'SwiftProgress', 'SwiftFinish', 'ErrorDlg', 'FatalError', 'UserExit', 'FilesInUse', 'MsiRMFilesInUse')) {
    if (-not $dialogs.ContainsKey($name)) { throw "Missing installer dialog: $name" }
}
foreach ($row in (Rows 'SELECT `Dialog_`, `Control`, `X`, `Y`, `Width`, `Height` FROM `Control`' 6)) {
    if (-not $row[0].StartsWith('Swift')) { continue }
    $dialog = $dialogs[$row[0]]
    if ([int]$row[2] -lt 0 -or [int]$row[3] -lt 0 -or
        ([int]$row[2] + [int]$row[4]) -gt [int]$dialog[1] -or
        ([int]$row[3] + [int]$row[5]) -gt [int]$dialog[2]) { throw "Control is outside dialog: $($row[0]).$($row[1])" }
}
$events = @(Rows 'SELECT `Dialog_`, `Control_`, `Event`, `Argument`, `Condition`, `Ordering` FROM `ControlEvent`' 6)
function RequireEvent($dialog, $control, $event, $argument) {
    $match = @($events | Where-Object { $_[0] -eq $dialog -and $_[1] -eq $control -and $_[2] -eq $event -and $_[3] -eq $argument })
    if ($match.Count -ne 1) { throw "Missing or ambiguous event: $dialog.$control $event $argument" }
    return ,$match[0]
}
$install = RequireEvent SwiftWelcome Install EndDialog Return
if ($install[4] -ne 'OutOfDiskSpace <> 1') { throw 'Install must check disk space' }
$null = RequireEvent SwiftWelcome Install SpawnWaitDialog WaitForCostingDlg
$null = RequireEvent SwiftWelcome Cancel EndDialog Exit
$null = RequireEvent SwiftProgress Cancel SpawnDialog CancelDlg
$repairMode = RequireEvent SwiftMaintenance Repair ReinstallMode amus
$repair = RequireEvent SwiftMaintenance Repair Reinstall All
$repairEnd = RequireEvent SwiftMaintenance Repair EndDialog Return
if ([int]$repairMode[5] -ge [int]$repair[5] -or [int]$repair[5] -ge [int]$repairEnd[5]) {
    throw 'Repair must select complete file replacement before reinstalling and dismissing'
}
$null = RequireEvent SwiftMaintenance Remove NewDialog VerifyReadyDlg
$null = RequireEvent VerifyReadyDlg Back NewDialog SwiftMaintenance
$finish = RequireEvent SwiftFinish Finish EndDialog Return
foreach ($launch in @($events | Where-Object { $_[0] -eq 'SwiftFinish' -and $_[2] -eq 'DoAction' })) {
    if ([int]$launch[5] -ge [int]$finish[5]) { throw 'Launch must precede dialog dismissal' }
}
$sequence = @{}
foreach ($row in (Rows 'SELECT `Action`, `Sequence` FROM `InstallUISequence`' 2)) { $sequence[$row[0]] = [int]$row[1] }
if ($sequence['SwiftFinish'] -ne -1 -or $sequence['SwiftWelcome'] -le $sequence['CostFinalize'] -or
    $sequence['SwiftProgress'] -le $sequence['SwiftWelcome'] -or $sequence['ExecuteAction'] -le $sequence['SwiftProgress']) {
    throw 'UI must cost before confirmation, execute after progress, and finish only on success'
}
Write-Output 'Compiled installer UI, navigation and control bounds verified. No installation or visual test was run.'

