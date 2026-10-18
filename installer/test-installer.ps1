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
Install $New @('/ALLUSERS', '/Theme=Dark')
if ((Theme-Default) -ne 'dark') { throw "expected machine theme default 'dark', found '$(Theme-Default)'" }
Write-Host 'ok: /Theme=Dark wrote the machine default'
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
