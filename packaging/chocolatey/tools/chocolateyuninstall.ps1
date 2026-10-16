$ErrorActionPreference = 'Stop'

# Only the all-users install this package made; a per-user install someone
# made themselves is theirs to remove.
[array]$keys = Get-UninstallRegistryKey -SoftwareName 'Hivemend*' |
  Where-Object { $_.PSPath -match 'HKEY_LOCAL_MACHINE' }

foreach ($key in $keys) {
  Uninstall-ChocolateyPackage -PackageName $env:ChocolateyPackageName `
    -FileType 'exe' `
    -SilentArgs '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' `
    -File ($key.UninstallString -replace '"', '')
}
