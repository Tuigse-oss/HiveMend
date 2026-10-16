$ErrorActionPreference = 'Stop'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'exe'
  url64bit       = '{{SETUP_URL}}'
  checksum64     = '{{SETUP_SHA256}}'
  checksumType64 = 'sha256'
  softwareName   = 'Hivemend*'
  silentArgs     = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /ALLUSERS'
  validExitCodes = @(0)
}

Install-ChocolateyPackage @packageArgs
