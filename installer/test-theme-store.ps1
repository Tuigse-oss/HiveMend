# Run elevated on Windows. Uses a unique disposable key, never the app store.
$ErrorActionPreference = 'Stop'
$source = Get-Content (Join-Path $PSScriptRoot 'validate-theme-store.ps1') -Raw
$definition = [regex]::Match($source, "(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
Add-Type -TypeDefinition $definition
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ThemeFixture {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    public static extern int RegCreateKeyEx(IntPtr root, string name, int reserved, string cls,
        int options, int access, IntPtr security, out IntPtr key, out int disposition);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    public static extern int RegOpenKeyEx(IntPtr root, string name, int options, int access, out IntPtr key);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    public static extern int RegSetValueEx(IntPtr key, string name, int reserved, int type, byte[] bytes, int size);
    [DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr key);
    [DllImport("ntdll.dll")] public static extern int NtDeleteKey(IntPtr key);
}
'@
$links = @()
$root = [IntPtr]::new(-2147483646)
$path = 'SOFTWARE\HivemendInstallerTest' + [Guid]::NewGuid().ToString('N')
$providerPath = "HKLM:\$path"
function Restore-Acl([string]$key, [string]$sddl) {
    $acl = [Security.AccessControl.RegistrySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl $key $acl
}
function Expect-Refusal([string]$case) {
    $before = (Get-Acl "$providerPath\Leaf").Sddl
    $value = (Get-ItemProperty "$providerPath\Leaf").Theme
    $refused = $false
    try { [void][ThemeStore]::Run($root, "$path\Leaf", 'dark') } catch { $refused = $true }
    if (!$refused) { throw "$case accepted" }
    if ((Get-Acl "$providerPath\Leaf").Sddl -ne $before) { throw "$case changed permissions" }
    if ((Get-ItemProperty "$providerPath\Leaf").Theme -ne $value) { throw "$case changed value" }
    Write-Host "ok: $case refused without value/permission changes"
}
try {
    if (![ThemeStore]::Run($root, "$path\Leaf", '').StartsWith('ABSENT|')) { throw 'expected absent' }
    if (Test-Path $providerPath) { throw 'validation created a key' }
    [void][ThemeStore]::Run($root, "$path\Leaf", 'light')
    if (![ThemeStore]::Run($root, "$path\Leaf", '').StartsWith('PROTECTED|')) { throw 'new store unprotected' }
    [void][ThemeStore]::Run($root, "$path\Leaf", 'dark')
    if ((Get-ItemProperty "$providerPath\Leaf").Theme -ne 'dark') { throw 'protected write failed' }
    Write-Host 'ok: clean creation and protected existing write'
    $clean = (Get-Acl "$providerPath\Leaf").Sddl
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-21-12345-23456-34567-45678')) {
        try {
            $acl = Get-Acl "$providerPath\Leaf"
            $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'SetValue', 'Allow'))
            Set-Acl "$providerPath\Leaf" $acl
            Expect-Refusal "ordinary trustee $sid"
        } finally { Restore-Acl "$providerPath\Leaf" $clean }
    }
    try {
        $acl = Get-Acl "$providerPath\Leaf"
        $acl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
        Set-Acl "$providerPath\Leaf" $acl
        Expect-Refusal 'individual owner'
    } finally { Restore-Acl "$providerPath\Leaf" $clean }
    $parentClean = (Get-Acl $providerPath).Sddl
    try {
        [void][ThemeStore]::Run($root, "$path\Leaf", '')
        $acl = Get-Acl $providerPath
        $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'CreateSubKey', 'Allow'))
        Set-Acl $providerPath $acl
        Expect-Refusal 'ancestor changed after preflight'
    } finally { Restore-Acl $providerPath $parentClean }
    foreach ($case in @(
        @('LeafLink', "$path\Leaf", ''),
        @('AncestorLink', $path, '\Leaf')
    )) {
        $linkPath = "$path\$($case[0])"
        $links += $linkPath
        $key = [IntPtr]::Zero
        $disposition = 0
        $rc = [ThemeFixture]::RegCreateKeyEx($root, $linkPath, 0, $null, 3, 0x10023,
            [IntPtr]::Zero, [ref]$key, [ref]$disposition)
        if ($rc -ne 0) { throw "link fixture creation failed: $rc" }
        try {
            $bytes = [Text.Encoding]::Unicode.GetBytes("\REGISTRY\MACHINE\$($case[1])")
            if ([ThemeFixture]::RegSetValueEx($key, 'SymbolicLinkValue', 0, 6, $bytes, $bytes.Length) -ne 0) {
                throw 'link target write failed'
            }
        } finally { [void][ThemeFixture]::RegCloseKey($key) }
        $lookup = $linkPath + $case[2]
        $ordinary = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($lookup)
        if ($null -eq $ordinary) { throw 'ordinary link resolution required for qualification' }
        try { if ($ordinary.GetValue('Theme') -ne 'dark') { throw 'link resolves to wrong fixture' } }
        finally { $ordinary.Dispose() }
        $before = (Get-Acl "$providerPath\Leaf").Sddl
        $refused = $false
        try { [void][ThemeStore]::Run($root, $lookup, 'light') } catch { $refused = $true }
        if (!$refused) { throw "linked write accepted: $lookup" }
        if ((Get-ItemProperty "$providerPath\Leaf").Theme -ne 'dark' -or
            (Get-Acl "$providerPath\Leaf").Sddl -ne $before) { throw 'link refusal changed target' }
        Write-Host "ok: valid $($case[0]) resolves ordinarily and refuses installer write"
    }
} finally {
    foreach ($linkPath in $links) {
        $key = [IntPtr]::Zero
        $rc = [ThemeFixture]::RegOpenKeyEx($root, $linkPath, 8, 0x10001, [ref]$key)
        if ($rc -eq 0) {
            try { if ([ThemeFixture]::NtDeleteKey($key) -lt 0) { throw "cannot delete link $linkPath" } }
            finally { [void][ThemeFixture]::RegCloseKey($key) }
        } elseif ($rc -ne 2) { throw "cannot verify link cleanup: $rc" }
    }
    if (Test-Path $providerPath) { Remove-Item $providerPath -Recurse -Force }
    if (Test-Path $providerPath) { throw 'fixture survived cleanup' }
}
Write-Host 'All disposable theme-store checks passed.'
