param([Parameter(Mandatory = $true)][string]$Msi, [ValidateSet("Desktop", "Lite")][string]$Product = "Desktop")
$ErrorActionPreference = 'Stop'
# Database inspection only. Do not use Win32_Product or invoke msiexec here.
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase((Resolve-Path -LiteralPath $Msi).Path, 0)
$view = $database.OpenView('SELECT `Action`, `Sequence`, `Condition` FROM `InstallExecuteSequence`')
$view.Execute()
$sequence = @{}
$conditions = @{}
while ($record = $view.Fetch()) {
    $sequence[$record.StringData(1)] = $record.IntegerData(2)
    $conditions[$record.StringData(1)] = $record.StringData(3).Trim()
}
$view.Close()
$ordered = @('InstallInitialize', "Prepare${Product}Recovery", "Repair${Product}Orphans",
    'InstallExecute', "Refresh${Product}UpgradeList", 'InstallExecuteAgain',
    'RemoveExistingProducts', 'ProcessComponents', 'RemoveFiles', 'InstallFiles', 'InstallFinalize')
$previous = -1
foreach ($action in $ordered) {
    if (-not $sequence.ContainsKey($action) -or $sequence[$action] -le $previous) {
        throw "Unsafe $Product upgrade sequence at $action"
    }
    $previous = $sequence[$action]
}
# No later-added action may schedule file/registry changes in the early flushes.
$allowed = @("Prepare${Product}Recovery", "Repair${Product}Orphans", 'InstallExecute',
    "Refresh${Product}UpgradeList", 'InstallExecuteAgain', 'SilentNsisUninstall')
foreach ($action in $sequence.Keys) {
    if ($sequence[$action] -gt $sequence['InstallInitialize'] -and
        $sequence[$action] -lt $sequence['RemoveExistingProducts'] -and $action -notin $allowed) {
        throw "Unexpected action before old-product removal: $action"
    }
}
$types = @{}
$sources = @{}
$targets = @{}
$view = $database.OpenView('SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`')
$view.Execute()
while ($record = $view.Fetch()) {
    $types[$record.StringData(1)] = $record.IntegerData(2)
    $sources[$record.StringData(1)] = $record.StringData(3)
    $targets[$record.StringData(1)] = $record.StringData(4)
}
$view.Close()
if ($types["Repair${Product}Orphans"] -ne 3073) { throw 'Recovery must be a checked deferred, non-impersonating DLL action' }
foreach ($action in @("Prepare${Product}Recovery", "Refresh${Product}UpgradeList")) {
    if ($types[$action] -ne 1) { throw "$action must be an immediate checked DLL action" }
}
if ($Product -eq 'Desktop') {
    # Check compiled tables, not just the WiX text: a display-name-based path
    # previously pointed both helpers at an executable absent from the MSI.
    $view = $database.OpenView('SELECT `FileName` FROM `File` WHERE `File` = ''Path''')
    $view.Execute()
    $file = $view.Fetch()
    if (-not $file -or -not $file.StringData(1).EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Desktop MSI must contain its main executable as File Path'
    }
    $view.Close()
    foreach ($helper in @(
        @{ Action = 'RunCleanupOnUninstall'; Argument = '--cleanup'; Condition = 'Installed AND REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE' },
        @{ Action = 'RunInstallDriverAfterInstall'; Argument = '--install-driver'; Condition = 'NOT REMOVE' }
    )) {
        $action = $helper.Action
        # 18: installed executable, 1024: deferred, 2048: elevated, 64: best effort.
        if ($types[$action] -ne 3154 -or $sources[$action] -ne 'Path' -or $targets[$action] -ne $helper.Argument) {
            throw "$action must reference the packaged main executable with $($helper.Argument)"
        }
        if (-not $sequence.ContainsKey($action) -or $conditions[$action] -ne $helper.Condition) {
            throw "$action has an unsafe install/uninstall condition"
        }
    }
    if ($sequence['RunCleanupOnUninstall'] -le $sequence['RemoveExistingProducts'] -or
        $sequence['RunCleanupOnUninstall'] -ge $sequence['RemoveFiles']) {
        throw 'Cleanup must run before its executable is removed, after upgrade recovery'
    }
    if ($sequence['RunInstallDriverAfterInstall'] -le $sequence['InstallFiles'] -or
        $sequence['RunInstallDriverAfterInstall'] -ge $sequence['InstallFinalize']) {
        throw 'Driver installation must run after its executable is installed'
    }
    Write-Output 'Desktop cleanup and driver actions reference the packaged executable with safe sequencing.'
}
foreach ($action in $ordered) { Write-Output "$action $($sequence[$action])" }
Write-Output "$Product MSI recovery sequencing verified. Installation was not executed."
