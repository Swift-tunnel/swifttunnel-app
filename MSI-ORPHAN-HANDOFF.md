# MSI orphaned-registration failure: what was tried and why each route failed

Written for a second pair of eyes. The goal is to fix this **inside the MSI**,
so the website can keep serving a bare `.msi`. Everything below was tested on a
real Windows machine, not reasoned about.

## The failure

A machine that installed SwiftTunnel through the in-app updater has its install
source recorded as `%TEMP%\<random>\SwiftTunnel-<version>-installer.msi` (Tauri
writes the download there). Windows wipes `%TEMP%`. The cached copy under
`C:\Windows\Installer` is also lost on machines running PC cleanup tools.

The registration is now orphaned. Nothing breaks until the next upgrade, which
dies at `RemoveExistingProducts` with:

> The feature you are trying to use is on a network resource that is unavailable

The user then cannot upgrade **and** cannot uninstall. Reproduce with:

```powershell
# as admin, with SwiftTunnel installed
$p = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products" |
     ForEach-Object { Get-ItemProperty (Join-Path $_.PSPath InstallProperties) -EA SilentlyContinue } |
     Where-Object { $_.DisplayName -like "*SwiftTunnel*" }
Remove-Item $p.LocalPackage -Force        # this is the break
```

Then install a newer MSI **unelevated**, with no other SwiftTunnel MSI anywhere
on disk. Both conditions matter; see "test traps" below.

## The fix that works, and why it is outside the MSI

`swifttunnel-setup` (in this repo): a small Rust launcher with a
`requireAdministrator` manifest. It embeds the MSI, clears the orphaned
registration via `swifttunnel-msi-repair`, then runs `msiexec /i`. Verified
end to end against the broken state, unelevated launch, exit 0, full payload
intact.

The question for a reviewer is whether the same thing can be done from within
the MSI. Four routes were tried:

### 1. Immediate custom action (shipped in v3.0.5, does not work)

`Execute="immediate"`, Type 66, scheduled before `InstallValidate`.

Immediate actions impersonate the invoking user. A user double-clicking an MSI
is **not** elevated; Windows only elevates when the service executes the script.
The repair binary cannot write `HKLM` and exits 3. `Return="ignore"` swallows it:

```
CustomAction ClearOrphanedSwiftTunnelRegistration returned actual error code 3
  but will be translated to success due to continue marking
```

This shipped because the test ran `msiexec` from an Administrator prompt, which
inherits elevation no real user has.

### 2. Deferred, non-impersonating, before RemoveExistingProducts

`Execute="deferred" Impersonate="no"` (Type 3138) runs as SYSTEM and **does**
get the privileges:

```
MSI_LUA : Custom Action 'ClearOrphanedSwiftTunnelRegistration' is running with
sufficient privileges.
Action ended: ClearOrphanedSwiftTunnelRegistration. Return value 1.
```

But the install then fails:

```
DEBUG: Error 2613: RemoveExistingProducts action sequenced incorrectly.
```

MSI permits **no action between `RemoveExistingProducts` and its anchor**. WiX
warns about this as ICE63 and it is not advisory. Tauri pins
`<MajorUpgrade Schedule="afterInstallInitialize">`, so the removal sits at 1501
with `InstallInitialize` at 1500 and there is no integer between them.

### 3. Move the removal later (`afterInstallExecute`), via a WiX template override

Sequencing becomes legal and the broken upgrade succeeds. But a **healthy**
upgrade then comes out with `resources\drivers` and `resources\tools` missing:
the old product's uninstall runs after `InstallFiles` and deletes files the new
install just placed, because Tauri emits fresh component GUIDs per build so
refcounting does not protect them. This breaks the driver and the optimiser for
every upgrading user, which is worse than the original bug. Rejected.

`afterInstallFinalize` is the same hazard in a separate transaction.

### 4. Override the removal schedule from a fragment

```
error LGHT0170 : The InstallExecuteSequence table contains an action
'RemoveExistingProducts' that is declared in two different locations.
```

`Overridable='yes'` would have to be set on Tauri's own `MajorUpgrade` element,
which a fragment cannot reach. Needs a full `wix.template` override.

## Ideas considered and discarded without testing

- **`RemoveRegistry` table entries for known past product codes.** Component
  registry operations run at `RemoveRegistryValues`/`WriteRegistryValues`,
  both far after `RemoveExistingProducts`. Too late.
- **Repointing the old product's `SourceList`.** Needs `HKLM` writes, so it has
  the same elevation problem as route 1.
- **Dropping `MajorUpgrade` entirely.** No removal means no failure, but leaves
  two entries in Add/Remove Programs and the orphan forever.
- **Script custom actions.** Strictly worse: same impersonation rules, and AV
  treats MSI script actions far more harshly than a native binary.

## Test traps that produced two false passes

1. **Launching `msiexec` from an elevated shell.** The immediate action inherits
   that elevation. Launch unelevated.
2. **Leaving any SwiftTunnel MSI on disk.** Windows resolves the "missing"
   package from it and the install succeeds for the wrong reason. Watch for
   `SOURCEDIR ==> ...` in the verbose log. Downloads and `%TEMP%` must be clear.
3. **Installing the same version over itself.** Same ProductCode makes it a
   reinstall, not an upgrade, so `WIX_UPGRADE_DETECTED` is never set and the
   action does not run. Install an older version first.

## Constraints on any proposed fix

- Must work when the MSI is double-clicked by a non-elevated user.
- Must not change behaviour for a healthy upgrade, in particular must not
  disturb `resources\drivers` or `resources\tools`.
- Tauri v2.10.3 generates `main.wxs`; fragments are added through
  `bundle.windows.wix.fragmentPaths` + `componentGroupRefs`. A `wix.template`
  override is possible but pins a copy of Tauri's template.
- Installers are currently unsigned, so adding executables that msiexec unpacks
  into `%TEMP%` and runs has a real Defender cost.
