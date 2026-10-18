# Installs, upgrades, and uninstalls Hivemend silently, the way winget,
# Chocolatey, and a user upgrading by hand do, and checks each step:
#
#   installer\test-installer.ps1 -Old <setup.exe> -OldVersion 0.1.0 `
#                                -New <setup.exe> -NewVersion 0.1.1
#
# Run it on a Windows machine you can install software on, from an
# administrator prompt (the all-users steps need it). Old and New may be the
# same file to check a reinstall.
param(
  [Parameter(Mandatory)] [string] $Old,
  [Parameter(Mandatory)] [string] $OldVersion,
  [Parameter(Mandatory)] [string] $New,
  [Parameter(Mandatory)] [string] $NewVersion
)
$ErrorActionPreference = 'Stop'

# The Add/Remove Programs key Inno Setup writes for the installer's AppId.
$keyName = '{6F1C2A4E-8B3D-4E7A-9C51-2D8E0B7F4A93}_is1'
$roots = [ordered]@{
  user    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
  machine = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
}
$silent = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-')

# The machine theme default the installer's /Theme switch seeds.
$themeKey = 'HKLM:\SOFTWARE\TUIGSE\Hivemend'
function Theme-Default {
  (Get-ItemProperty -Path $themeKey -Name Theme -ErrorAction SilentlyContinue).Theme
}

function Install([string] $setup, [string[]] $scope) {
  $process = Start-Process $setup -ArgumentList ($silent + $scope) -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    throw "$(Split-Path $setup -Leaf) $scope exited with $($process.ExitCode)"
  }
}

function Installs {
  foreach ($scope in $roots.Keys) {
    $path = Join-Path $roots[$scope] $keyName
    if (Test-Path $path) {
      [pscustomobject]@{ Scope = $scope; Entry = Get-ItemProperty $path }
    }
  }
}

function Expect-Installed([string] $scope, [string] $version) {
  $found = @(Installs)
  if ($found.Count -ne 1) {
    throw "expected one install, found $($found.Count) ($($found.Scope -join ', '))"
  }
  if ($found[0].Scope -ne $scope) { throw "expected a $scope install, found $($found[0].Scope)" }
  $shown = $found[0].Entry.DisplayVersion
  if ($shown -ne $version) { throw "expected version $version, found $shown" }
  $exe = Join-Path $found[0].Entry.InstallLocation 'Hivemend.exe'
  if (-not (Test-Path $exe)) { throw "$exe is missing" }
  Write-Host "ok: $scope install, version $version, $exe"
  $exe
}

function Uninstall-All {
  foreach ($install in @(Installs)) {
    $uninstaller = $install.Entry.UninstallString.Trim('"')
    $exe = Join-Path $install.Entry.InstallLocation 'Hivemend.exe'
    Start-Process $uninstaller -ArgumentList $silent -Wait
    # The uninstaller hands over to a copy of itself and returns at once.
    $deadline = (Get-Date).AddMinutes(2)
    while (((Test-Path $exe) -or @(Installs).Count -gt 0) -and (Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 1
    }
    if (Test-Path $exe) { throw "uninstalling left $exe behind" }
  }
  if (@(Installs).Count -gt 0) { throw 'uninstalling left an Add/Remove Programs entry' }
  Write-Host 'ok: uninstalled'
}

# Starts Hivemend and returns its process, or $null where no window can be
# shown (such as a service session).
function Start-Hivemend([string] $exe) {
  $process = Start-Process $exe -PassThru
  Start-Sleep -Seconds 3
  if ($process.HasExited) {
    Write-Warning "Hivemend did not stay open here (exit $($process.ExitCode)); skipping the running-app check"
    return $null
  }
  $process
}

function Expect-Closed($process) {
  if ($null -eq $process) { return }
  if (-not $process.HasExited) { throw 'the upgrade did not close the running Hivemend' }
  $again = @(Get-Process Hivemend -ErrorAction SilentlyContinue)
  if ($again.Count -gt 0) { throw 'the upgrade restarted Hivemend; it must not come back elevated' }
  Write-Host 'ok: the running Hivemend was closed and not restarted'
}

# Data Hivemend keeps outside its install folder must survive an uninstall.
$data = Join-Path $env:LOCALAPPDATA 'HiveMend'
$marker = Join-Path $data 'installer-test-marker.txt'
New-Item -ItemType Directory -Force $data | Out-Null
Set-Content $marker 'backups and settings stay'

Uninstall-All

Write-Host '== Per-user install, then an upgrade with no scope switch (as a user double-clicking the new setup)'
Install $Old @('/CURRENTUSER')
$exe = Expect-Installed user $OldVersion
$running = Start-Hivemend $exe
Install $New @()
Expect-Installed user $NewVersion | Out-Null
Expect-Closed $running

Write-Host '== Reinstalling the same version per user (winget scope user)'
Install $New @('/CURRENTUSER')
Expect-Installed user $NewVersion | Out-Null
Uninstall-All

Write-Host '== All-users install and upgrade (Chocolatey, winget scope machine)'
Install $Old @('/ALLUSERS')
$exe = Expect-Installed machine $OldVersion
$running = Start-Hivemend $exe
# The fixture is cleared BEFORE the no-switch upgrade below, so the
# absence assertion after it observes the installer, not the cleanup.
Remove-ItemProperty -Path $themeKey -Name Theme -ErrorAction SilentlyContinue
Install $New @('/ALLUSERS')
Expect-Installed machine $NewVersion | Out-Null
Expect-Closed $running
if ($null -ne (Theme-Default)) { throw "a switchless install wrote a theme default: '$(Theme-Default)'" }
Write-Host 'ok: a switchless install wrote no machine default'

Write-Host '== /Theme seeds the machine default, upgrades preserve it, bad values change nothing'
# Runs the validation script straight from the repo (bypassing the
# installer's extraction) so a refusal can be diagnosed: if this says
# ABSENT/PROTECTED while Setup refuses, the failure is in the
# installer's script handling, not the store.
function Show-Validation {
  $dir = Join-Path ([IO.Path]::GetTempPath()) 'theme-validate-diag'
  New-Item -ItemType Directory -Force $dir | Out-Null
  $out = Join-Path $dir 'verdict.txt'
  $err = Join-Path $dir 'stderr.txt'
  Remove-Item $out -ErrorAction SilentlyContinue
  Remove-Item $err -ErrorAction SilentlyContinue
  $script = Join-Path $PSScriptRoot 'validate-theme-store.ps1'
  # Same engine order as the installer: pwsh first (some hosts cannot
  # load the Security module under 5.1), powershell as fallback.
  $proc = $null
  foreach ($engine in @('pwsh.exe', 'powershell.exe')) {
    try {
      $proc = Start-Process $engine -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $script, '-OutFile', $out) -Wait -PassThru -ErrorAction Stop `
        -RedirectStandardError $err -RedirectStandardOutput (Join-Path $dir 'stdout.txt')
      break
    } catch {
      Write-Host "validation engine $engine unavailable ($($_.Exception.Message))"
    }
  }
  if ($null -eq $proc) {
    Write-Host 'direct validation: no engine launched'
    return
  }
  $verdict = '(no verdict file)'
  if (Test-Path $out) { $verdict = (Get-Content $out -Raw).Trim() }
  Write-Host "direct validation: exit $($proc.ExitCode), $verdict"
  if (Test-Path $err) {
    $text = (Get-Content $err -Raw).Trim()
    if ($text -ne '') { Write-Host "validation stderr: $text" }
  }
}
$seed = Start-Process $New -ArgumentList ($silent + @('/ALLUSERS', '/Theme=Dark')) -Wait -PassThru
if ($seed.ExitCode -ne 0) {
  Show-Validation
  throw "expected /Theme=Dark to seed the machine default, setup exited with $($seed.ExitCode)"
}
Expect-Installed machine $NewVersion | Out-Null
if ((Theme-Default) -ne 'dark') { throw "expected machine theme default 'dark', found '$(Theme-Default)'" }
Write-Host 'ok: /Theme=Dark wrote the machine default'
# The seeded store must be protected: a trusted-system owner and no
# store-changing grant to any principal but SYSTEM/Administrators.
# This mirrors the runtime all-trustee policy (STORE_WRITE_MASK in
# src/settings.rs), including its inherit-only exception: an ACE that
# applies to subkeys only does not grant access to the key itself.
# Numeric rights (not enum names) so FullControl and generic mappings
# cannot hide a write bit.
$acl = Get-Acl -Path 'HKLM:\SOFTWARE\TUIGSE\Hivemend'
if (@('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') -notcontains $acl.Owner) {
  throw "machine theme store owned by '$($acl.Owner)', expected Administrators or SYSTEM"
}
$storeWrite = 0x2 -bor 0x4 -bor 0x20 -bor 0x10000 -bor 0x40000 -bor 0x80000
$systemWriters = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
$inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
# CREATOR OWNER empowers the owner, verified trusted just above, same
# coupling as the runtime and installer policies.
$exposed = @($acl.Access | Where-Object {
  $_.AccessControlType -eq 'Allow' `
  -and ($_.RegistryRights.value__ -band $storeWrite) -ne 0 `
  -and ($_.PropagationFlags -band $inheritOnly) -eq 0 `
  -and $systemWriters -notcontains $_.IdentityReference.Value `
  -and 'CREATOR OWNER' -ne $_.IdentityReference.Value
})
if ($exposed.Count -ne 0) {
  throw "machine theme store grants store-changing rights to untrusted identities: $($exposed.IdentityReference.Value -join ', ')"
}
Write-Host 'ok: /Theme=Dark established a protected store (owner and DACL)'
$exe = Expect-Installed machine $NewVersion
$accepted = & $exe machine-theme
if ($accepted -ne 'dark') {
  throw "an elevated app lookup refused the seeded store (got '$accepted'); the installer must seed stores the app accepts"
}
Write-Host 'ok: an elevated app lookup accepts the seeded store'
Install $New @('/ALLUSERS')
Expect-Installed machine $NewVersion | Out-Null
if ((Theme-Default) -ne 'dark') { throw 'an upgrade without /Theme overwrote the machine default' }
Write-Host 'ok: an upgrade without /Theme preserved the machine default'
# A rejected switch must change nothing. Exit codes cannot prove that: a
# late silent abort can still report 0, so the probes use the OLD version,
# where a mistaken success would visibly downgrade or add an install. The
# codes are logged for diagnosis, never asserted. The sleeps give a
# mistaken install time to show itself; a refusal is instant.
# Both halves of the failure contract are asserted: a nonzero status and
# unchanged installation state. The sleeps give a mistaken install time to
# show itself; a refusal is instant.
$bad = Start-Process $Old -ArgumentList ($silent + @('/ALLUSERS', '/Theme=Neon')) -Wait -PassThru
if ($bad.ExitCode -eq 0) { throw '/Theme=Neon reported success; a refusal must fail' }
Write-Host "ok: /Theme=Neon exited $($bad.ExitCode)"
Start-Sleep -Seconds 30
$still = @(Installs)
if ($still.Count -ne 1 -or $still[0].Scope -ne 'machine' -or $still[0].Entry.DisplayVersion -ne $NewVersion) {
  throw 'a rejected /Theme=Neon changed the install (downgraded or duplicated)'
}
if ((Theme-Default) -ne 'dark') { throw 'a rejected install damaged the machine default' }
Write-Host 'ok: /Theme=Neon changed nothing (no downgrade, default intact)'
$empty = Start-Process $Old -ArgumentList ($silent + @('/ALLUSERS', '/Theme=')) -Wait -PassThru
if ($empty.ExitCode -eq 0) { throw 'an empty /Theme= reported success; only absence preserves the default' }
Write-Host "ok: empty /Theme= exited $($empty.ExitCode)"
Start-Sleep -Seconds 30
$still = @(Installs)
if ($still.Count -ne 1 -or $still[0].Entry.DisplayVersion -ne $NewVersion) {
  throw 'an empty /Theme= changed the install'
}
if ((Theme-Default) -ne 'dark') { throw 'an empty /Theme= damaged the machine default' }
Write-Host 'ok: empty /Theme= changed nothing (no downgrade, default intact)'
$sentinel = Start-Process $Old -ArgumentList ($silent + @('/ALLUSERS', '/Theme=__ABSENT__')) -Wait -PassThru
if ($sentinel.ExitCode -eq 0) { throw 'the former absence marker as /Theme= reported success; every supplied value is validated' }
Write-Host "ok: former sentinel exited $($sentinel.ExitCode)"
Start-Sleep -Seconds 30
$still = @(Installs)
if ($still.Count -ne 1 -or $still[0].Entry.DisplayVersion -ne $NewVersion) {
  throw 'a rejected former sentinel changed the install (downgraded or duplicated)'
}
if ((Theme-Default) -ne 'dark') { throw 'a rejected former sentinel damaged the machine default' }
Write-Host 'ok: former sentinel changed nothing (no downgrade, default intact)'
$mortal = Start-Process $Old -ArgumentList ($silent + @('/CURRENTUSER', '/Theme=Dark')) -Wait -PassThru
if ($mortal.ExitCode -eq 0) { throw 'per-user /Theme=Dark reported success; it must fail instead' }
Write-Host "ok: per-user /Theme=Dark exited $($mortal.ExitCode)"
Start-Sleep -Seconds 30
if (@(Installs).Count -ne 1) { throw 'a rejected per-user /Theme added an install' }
if ((Theme-Default) -ne 'dark') { throw 'a rejected per-user install damaged the machine default' }
Write-Host 'ok: per-user /Theme=Dark changed nothing (no second install, default intact)'

Write-Host '== A hostile existing store refuses the whole install, changing neither value nor permissions'
# SDDL compare catches any permission mutation; the Theme value must
# stay exactly as the fixture left it. Each case starts from a light
# default with one hostile grant, and ends removed or repaired.
function Store-Sddl { (Get-Acl -Path $themeKey).Sddl }
function Assert-Refused([string]$case, [int]$exitCode, [string]$before) {
  if ($exitCode -eq 0) { throw "a /Theme install into a hostile store ($case) reported success; it must fail instead" }
  Write-Host "ok: hostile store ($case) exited $exitCode"
  Start-Sleep -Seconds 30
  $still = @(Installs)
  if ($still.Count -ne 1 -or $still[0].Entry.DisplayVersion -ne $NewVersion) {
    throw "a refused hostile install ($case) changed the install (downgraded or duplicated)"
  }
  if ((Theme-Default) -ne 'light') { throw "a refused hostile install ($case) changed the theme value" }
  if ((Store-Sddl) -ne $before) { throw "a refused hostile install ($case) changed the store permissions" }
  Write-Host "ok: hostile store ($case) refused, install/value/permissions untouched"
  $refused = & $exe machine-theme
  if ($null -ne $refused -and $refused -ne '') {
    throw "an elevated app lookup accepted a hostile store ($case, got '$refused')"
  }
  Write-Host "ok: an elevated app lookup refuses the hostile store ($case)"
}
function Add-StoreRule([string]$identity, [string]$rights) {
  $rule = New-Object System.Security.AccessControl.RegistryAccessRule($identity, $rights, 'Allow')
  $acl = Get-Acl -Path $themeKey
  $acl.AddAccessRule($rule)
  Set-Acl -Path $themeKey -AclObject $acl
  return $rule
}
function Remove-StoreRule($rule) {
  $acl = Get-Acl -Path $themeKey
  [void]$acl.RemoveAccessRule($rule)
  Set-Acl -Path $themeKey -AclObject $acl
}
Set-ItemProperty -Path $themeKey -Name Theme -Value 'light'
$rule = Add-StoreRule 'BUILTIN\Users' 'SetValue'
$before = Store-Sddl
$run = Start-Process $New -ArgumentList ($silent + @('/ALLUSERS', '/Theme=Dark')) -Wait -PassThru
Assert-Refused 'direct standard-user write' $run.ExitCode $before
Remove-StoreRule $rule
$grule = Add-StoreRule 'BUILTIN\Guests' 'SetValue, CreateSubKey'
$before = Store-Sddl
$run = Start-Process $New -ArgumentList ($silent + @('/ALLUSERS', '/Theme=Dark')) -Wait -PassThru
Assert-Refused 'custom-group write' $run.ExitCode $before
Remove-StoreRule $grule
# Untrusted ownership: giving the store away must refuse the install.
# Restoring needs the same privilege, so both directions are attempted
# and a blocked attempt is reported loudly instead of asserted.
$ownerFixture = $false
try {
  $acl = Get-Acl -Path $themeKey
  $acl.SetOwner([System.Security.Principal.NTAccount]'BUILTIN\Users')
  Set-Acl -Path $themeKey -AclObject $acl
  $ownerFixture = ((Get-Acl -Path $themeKey).Owner -eq 'BUILTIN\Users')
} catch {
  Write-Host "NOTE: this host cannot transfer store ownership ($($_.Exception.Message)); skipping the owner fixture"
}
if ($ownerFixture) {
  $before = Store-Sddl
  $run = Start-Process $New -ArgumentList ($silent + @('/ALLUSERS', '/Theme=Dark')) -Wait -PassThru
  Assert-Refused 'untrusted ownership' $run.ExitCode $before
  try {
    $acl = Get-Acl -Path $themeKey
    $acl.SetOwner([System.Security.Principal.NTAccount]'BUILTIN\Administrators')
    Set-Acl -Path $themeKey -AclObject $acl
  } catch {
    throw "could not restore store ownership after the fixture ($($_.Exception.Message))"
  }
}
# A redirected leaf: the store path itself is a link. The validation
# probe finds the marker without following, so resolution never
# matters. Removal uses the parent's delete-by-name, which addresses
# the link object, not its target.
$linkFixture = $false
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FixtureLink {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegCreateKeyEx(UIntPtr hKey, string subKey, IntPtr reserved,
        string cls, int options, int sam, IntPtr sec, out UIntPtr result, out int disp);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegSetValueEx(UIntPtr hKey, string name, IntPtr reserved,
        int type, byte[] data, int size);
    [DllImport("advapi32.dll")]
    public static extern int RegCloseKey(UIntPtr hKey);
}
'@ | Out-Null
  Remove-Item -Path $themeKey -Recurse -Force
  $link = [UIntPtr]::Zero
  $disp = 0
  $createLink = 2
  $volatile = 1
  $rc = [FixtureLink]::RegCreateKeyEx([UIntPtr]::new([uint64]2147483650), 'SOFTWARE\TUIGSE\Hivemend', [IntPtr]::Zero, $null,
    ($createLink -bor $volatile), 0x22, [IntPtr]::Zero, [ref]$link, [ref]$disp)
  if ($rc -ne 0) { throw "link creation failed ($rc)" }
  # MS-RRP: length-delimited target without a terminator.
  $units = [System.Text.Encoding]::Unicode.GetBytes('\REGISTRY\MACHINE\SOFTWARE')
  $rc = [FixtureLink]::RegSetValueEx($link, 'SymbolicLinkValue', 0, 6, $units, $units.Length)
  [void][FixtureLink]::RegCloseKey($link)
  if ($rc -ne 0) { throw "link target setup failed ($rc)" }
  $linkFixture = $true
} catch {
  Write-Host "NOTE: this host cannot stage a link fixture ($($_.Exception.Message)); skipping the redirected-leaf case"
}
if ($linkFixture) {
  $run = Start-Process $New -ArgumentList ($silent + @('/ALLUSERS', '/Theme=Dark')) -Wait -PassThru
  if ($run.ExitCode -eq 0) { throw 'a /Theme install into a redirected store reported success; it must fail instead' }
  Write-Host "ok: redirected store exited $($run.ExitCode)"
  Start-Sleep -Seconds 30
  $still = @(Installs)
  if ($still.Count -ne 1 -or $still[0].Entry.DisplayVersion -ne $NewVersion) {
    throw 'a refused redirected install changed the install (downgraded or duplicated)'
  }
  Write-Host 'ok: redirected store refused, install untouched'
  $parent = Get-Item 'HKLM:\SOFTWARE\TUIGSE'
  $parent.DeleteSubKey('Hivemend')
  if (Test-Path $themeKey) { throw 'the link fixture survived cleanup' }
  Write-Host 'ok: link fixture removed without touching its target'
  New-Item -Path $themeKey -Force | Out-Null
}
Set-ItemProperty -Path $themeKey -Name Theme -Value 'dark'
Write-Host 'ok: hostile fixtures repaired, seeded default restored'
Install $New @('/ALLUSERS')
Expect-Installed machine $NewVersion | Out-Null
Uninstall-All

if (-not (Test-Path $marker)) { throw "uninstalling removed $data" }
Remove-Item $marker
Write-Host 'ok: data in %LOCALAPPDATA%\HiveMend kept'
if ((Theme-Default) -ne 'dark') { throw 'uninstalling removed the machine theme default; it stays, like the per-user data' }
Write-Host 'ok: uninstalling kept the machine theme default'
# The suite cleans up after itself so a rerun starts clean.
Remove-ItemProperty -Path $themeKey -Name Theme -ErrorAction SilentlyContinue
Write-Host 'All installer checks passed.'
