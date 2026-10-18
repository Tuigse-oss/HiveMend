# Tests the Chocolatey install script's /Theme: parameter without
# installing anything: Get-PackageParameters and Install-ChocolateyPackage
# are stubbed, the real chocolateyinstall.ps1 runs against the stubs, and
# the silent arguments it would pass to Inno Setup are asserted here.
#
#   installer\test-choco-params.ps1
#
# Run on any Windows machine with PowerShell; CI runs it on every pull
# request, so a broken parameter fails before publishing, not during it.
#
# The shared state is $global: on purpose. A $script: variable inside a
# stub function resolves against whichever script is running when the stub
# is called (the install script, not this harness), which reads back $null
# and fails every check with "cannot call a method on a null-valued
# expression". Globals are unambiguous from every scope.
param(
  [Parameter(Mandatory)] [string] $Script
)
$ErrorActionPreference = 'Stop'

$global:__choco_params = @{}
$global:__choco_captured = $null

function Get-PackageParameters {
  if ($null -eq $global:__choco_params) { return @{} }
  return $global:__choco_params
}

function Install-ChocolateyPackage {
  param(
    $packageName, $fileType, $url64bit, $checksum64, $checksumType64,
    $softwareName, $silentArgs, $validExitCodes
  )
  $global:__choco_captured = $silentArgs
}

function Expect-Forwarded([string] $given, [string] $switch) {
  $global:__choco_params = @{ Theme = $given }
  $global:__choco_captured = $null
  & $Script
  if ($global:__choco_captured -notlike "*$switch*") {
    throw "/Theme:$given was not forwarded (silent args: '$global:__choco_captured')"
  }
  Write-Host "ok: /Theme:$given forwards $switch"
}

function Expect-Rejected($given) {
  $global:__choco_params = @{ Theme = $given }
  try {
    & $Script
  } catch {
    if ($_.Exception.Message -notlike 'Invalid /Theme*') { throw }
    Write-Host "ok: /Theme:$given rejected loudly"
    return
  }
  throw "/Theme:$given was accepted; it must fail instead"
}

$global:__choco_params = @{}
$global:__choco_captured = $null
& $Script
if ($global:__choco_captured -like '*/Theme=*') {
  throw "no parameter forwarded a switch (silent args: '$global:__choco_captured')"
}
if ($global:__choco_captured -notlike '*/ALLUSERS*') {
  throw "silent args lost /ALLUSERS (silent args: '$global:__choco_captured')"
}
Write-Host 'ok: no parameter forwards no switch and keeps /ALLUSERS'

Expect-Forwarded 'Dark' '/Theme=Dark'
Expect-Forwarded 'SYSTEM' '/Theme=SYSTEM'
Expect-Forwarded 'light' '/Theme=light'

Expect-Rejected 'Neon'
Expect-Rejected ''
Expect-Rejected '   '
Expect-Rejected 'darkmode'
Expect-Rejected 'Dark; Remove-Item C:\'

Remove-Variable -Name __choco_params, __choco_captured -Scope Global -ErrorAction SilentlyContinue
Write-Host 'All Chocolatey parameter checks passed.'
