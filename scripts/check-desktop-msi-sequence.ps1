param([Parameter(Mandatory = $true)][string]$Msi)
$ErrorActionPreference = 'Stop'
# Database inspection only. Do not use Win32_Product or invoke msiexec here.
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase((Resolve-Path -LiteralPath $Msi).Path, 0)
$view = $database.OpenView('SELECT `Action`, `Sequence` FROM `InstallExecuteSequence`')
$view.Execute()
$sequence = @{}
while ($record = $view.Fetch()) { $sequence[$record.StringData(1)] = $record.IntegerData(2) }
$ordered = @('InstallInitialize', 'PrepareDesktopRecovery', 'RepairDesktopOrphans',
    'InstallExecute', 'RefreshDesktopUpgradeList', 'InstallExecuteAgain',
    'RemoveExistingProducts', 'ProcessComponents', 'RemoveFiles', 'InstallFiles', 'InstallFinalize')
$previous = -1
foreach ($action in $ordered) {
    if (-not $sequence.ContainsKey($action) -or $sequence[$action] -le $previous) {
        throw "Unsafe Desktop upgrade sequence at $action"
    }
    $previous = $sequence[$action]
}
# No later-added action may schedule file/registry changes in the early flushes.
$allowed = @('PrepareDesktopRecovery', 'RepairDesktopOrphans', 'InstallExecute',
    'RefreshDesktopUpgradeList', 'InstallExecuteAgain', 'SilentNsisUninstall')
foreach ($action in $sequence.Keys) {
    if ($sequence[$action] -gt $sequence['InstallInitialize'] -and
        $sequence[$action] -lt $sequence['RemoveExistingProducts'] -and $action -notin $allowed) {
        throw "Unexpected action before old-product removal: $action"
    }
}
$types = @{}
$view = $database.OpenView('SELECT `Action`, `Type` FROM `CustomAction`')
$view.Execute()
while ($record = $view.Fetch()) { $types[$record.StringData(1)] = $record.IntegerData(2) }
if ($types['RepairDesktopOrphans'] -ne 3073) { throw 'Recovery must be a checked deferred, non-impersonating DLL action' }
foreach ($action in @('PrepareDesktopRecovery', 'RefreshDesktopUpgradeList')) {
    if ($types[$action] -ne 1) { throw "$action must be an immediate checked DLL action" }
}
foreach ($action in $ordered) { Write-Output "$action $($sequence[$action])" }
Write-Output 'Desktop MSI recovery sequencing verified. Installation was not executed.'
