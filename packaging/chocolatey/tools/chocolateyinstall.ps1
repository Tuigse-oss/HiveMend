$ErrorActionPreference = 'Stop'

# Optional package parameters (case-insensitive):
#   choco install hivemend --params "/Theme:Dark"
# Light, System, or Dark seeds the machine theme default Hivemend starts
# from. Anything else fails the install rather than being silently
# ignored. With no parameter the installer writes nothing, so an upgrade
# keeps the previous machine default; an in-app Appearance pick always
# wins over the default.
$theme = $null
$params = Get-PackageParameters
if ($params.ContainsKey('Theme')) {
  $theme = $params['Theme']
}

$silentArgs = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /ALLUSERS'
if ($null -ne $theme) {
  if ([string]::IsNullOrWhiteSpace($theme) -or ($theme -notmatch '^(?i)(Light|System|Dark)$')) {
    throw "Invalid /Theme:$theme. Use /Theme:Light, /Theme:System, or /Theme:Dark."
  }
  $silentArgs += " /Theme=$theme"
}

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'exe'
  url64bit       = '{{SETUP_URL}}'
  checksum64     = '{{SETUP_SHA256}}'
  checksumType64 = 'sha256'
  softwareName   = 'Hivemend*'
  silentArgs     = $silentArgs
  validExitCodes = @(0)
}

Install-ChocolateyPackage @packageArgs
