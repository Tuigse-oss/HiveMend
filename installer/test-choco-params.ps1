# Tests the Chocolatey install script's /Theme: parameter without
# installing anything: Get-PackageParameters and Install-ChocolateyPackage
# are stubbed, the real chocolateyinstall.ps1 runs against the stubs, and
# the silent arguments it would pass to Inno Setup are asserted here.
#
#   installer\test-choco-params.ps1
#
# Run on any Windows machine with PowerShell; CI runs it on every pull
# request, so a broken parameter fails before publishing, not during it.
param(
  [Parameter(Mandatory)] [string] $Script
)
$ErrorActionPreference = 'Stop'

$script:captured = $null
$script:params = @{}

function Get-PackageParameters { return $script:params }

function Install-ChocolateyPackage {
  param(
    $packageName, $fileType, $url64bit, $checksum64, $checksumType64,
    $softwareName, $silentArgs, $validExitCodes
  )
  $script:captured = $silentArgs
}

function Expect-Forwarded([string] $given, [string] $switch) {
  $script:params = @{ Theme = $given }
  $script:captured = $null
  & $Script
  if ($script:captured -notlike "*$switch*") {
    throw "/Theme:$given was not forwarded (silent args: '$script:captured')"
  }
  Write-Host "ok: /Theme:$given forwards $switch"
}

function Expect-Rejected($given) {
  $script:params = @{ Theme = $given }
  try {
    & $Script
  } catch {
    if ($_.Exception.Message -notlike 'Invalid /Theme*') { throw }
    Write-Host "ok: /Theme:$given rejected loudly"
    return
  }
  throw "/Theme:$given was accepted; it must fail instead"
}

$script:params = @{}
$script:captured = $null
& $Script
if ($script:captured -like '*/Theme=*') {
  throw "no parameter forwarded a switch (silent args: '$script:captured')"
}
if ($script:captured -notlike '*/ALLUSERS*') {
  throw "silent args lost /ALLUSERS (silent args: '$script:captured')"
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

Write-Host 'All Chocolatey parameter checks passed.'
