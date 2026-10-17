# Creates (or, with -Remove, deletes) the stale App Paths entries the UI
# tests look for. Each points at a program under C:\HivemendCI that does not
# exist. Run from an administrator prompt on a machine you can test on, or
# with -UserOnly as the standard account the tests use.
param([switch] $Remove, [switch] $UserOnly)
$ErrorActionPreference = 'Stop'
$base = 'Software\Microsoft\Windows\CurrentVersion\App Paths'
$entries = @(
  # Your own part of the registry: an administrator window leaves it to a
  # normal window.
  @{ Key = "HKCU:\$base\hivemend-ci-user.exe"; Target = 'C:\HivemendCI\user\tool.exe'; Lock = $false },
  # Machine-wide with Windows' default permissions for App Paths.
  @{ Key = "HKLM:\$base\hivemend-ci-default.exe"; Target = 'C:\HivemendCI\default\tool.exe'; Lock = $false },
  # Locked to administrators, but inside App Paths, which is not: removing it
  # could not be undone from an administrator window, so it is left alone.
  @{ Key = "HKLM:\$base\hivemend-ci-fixable.exe"; Target = 'C:\HivemendCI\fixable\tool.exe'; Lock = $true }
)
foreach ($entry in $entries) {
  # -UserOnly: just the per-user entry, for a standard account to seed its
  # own part of the registry.
  if ($UserOnly -and -not $entry.Key.StartsWith('HKCU:')) { continue }
  if (Test-Path $entry.Key) { Remove-Item $entry.Key -Recurse -Force }
  if ($Remove) { continue }
  New-Item $entry.Key -Force | Out-Null
  Set-ItemProperty $entry.Key '(default)' $entry.Target
  if ($entry.Lock) {
    $acl = Get-Acl $entry.Key
    $acl.SetAccessRuleProtection($true, $false)
    $admins = New-Object Security.Principal.NTAccount 'BUILTIN\Administrators'
    $acl.SetOwner($admins)
    foreach ($who in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {
      $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($who, 'FullControl', 'ContainerInherit', 'None', 'Allow')))
    }
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule('BUILTIN\Users', 'ReadKey', 'ContainerInherit', 'None', 'Allow')))
    Set-Acl $entry.Key $acl
  }
  Write-Host "seeded $($entry.Key) -> $($entry.Target)"
}
if (-not $UserOnly -and (Test-Path 'C:\HivemendCI')) { Remove-Item 'C:\HivemendCI' -Recurse -Force }
