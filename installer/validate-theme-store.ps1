# Validates the machine theme store BEFORE the installer mutates
# anything: every path component is checked without following links,
# then owner and every write-capable trustee are checked against the
# same policy the elevated app enforces at runtime. Prints one verdict
# line "VERDICT|detail" to -OutFile and exits 0 (absent or protected),
# 1 (hostile: refuse the install), or 2 (uncheckable: refuse as well).
# A hostile or unknown store must never be written: Inno's Permissions
# only grant rights, they cannot scrub an existing hostile grant, so
# validation has to happen before any permissions/value mutation.
param([Parameter(Mandatory = $true)][string]$OutFile)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RegLinkProbe {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegOpenKeyEx(
        UIntPtr hKey, string subKey, int options, int sam, out UIntPtr result);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegQueryValueEx(
        UIntPtr hKey, string value, IntPtr reserved, out int type,
        byte[] data, ref int size);
    [DllImport("advapi32.dll")]
    public static extern int RegCloseKey(UIntPtr hKey);
}
'@


# 0x80000002 written decimal: PowerShell parses the hex literal as a
# negative Int32 and refuses the UIntPtr cast.
$HKEY_LOCAL_MACHINE = [UIntPtr]2147483650
$OPEN_LINK = 8
$QUERY = 1
$NOT_FOUND = 2

function Test-LinkComponent([UIntPtr]$parent, [string]$name) {
    # Returns 'link', 'plain', 'missing', or 'unknown'. No-follow open;
    # the kernel flags would be ideal, but RegOpenKeyEx with OPEN_LINK
    # plus the marker is what a script can do. A marker on a normal key
    # is treated as hostile below (fail closed), never as trusted.
    $child = [UIntPtr]::Zero
    $rc = [RegLinkProbe]::RegOpenKeyEx($parent, $name, $OPEN_LINK, $QUERY, [ref]$child)
    if ($rc -ne 0) {
        if ($rc -eq $NOT_FOUND) { return 'missing' }
        return 'unknown'
    }
    try {
        # A real buffer: with a null buffer the API may report
        # MORE_DATA instead of success, which would refuse clean
        # installs. Any other non-success (besides missing) refuses.
        $kind = 0
        $probe = New-Object byte[] 4096
        $size = $probe.Length
        $qr = [RegLinkProbe]::RegQueryValueEx($child, 'SymbolicLinkValue', [IntPtr]::Zero, [ref]$kind, $probe, [ref]$size)
        if ($qr -eq 0) { return 'link' }
        if ($qr -eq $NOT_FOUND) { return 'plain' }
        return 'unknown'
    } finally {
        [void][RegLinkProbe]::RegCloseKey($child)
    }
}

# Rights that let an untrusted principal change or replace the store.
# Must match STORE_WRITE_MASK in src/settings.rs.
$storeWrite = 0x2 -bor 0x4 -bor 0x20 -bor 0x10000 -bor 0x40000 -bor 0x80000
$trustedOwners = @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')
$trustedWriters = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')

function Open-NoFollow([UIntPtr]$parent, [string]$name) {
    $child = [UIntPtr]::Zero
    $rc = [RegLinkProbe]::RegOpenKeyEx($parent, $name, $OPEN_LINK, $QUERY, [ref]$child)
    if ($rc -ne 0 -or $child -eq [UIntPtr]::Zero) { return $null }
    return $child
}

function Test-StoreObject([string]$path) {
    # $path like 'HKLM:\SOFTWARE\TUIGSE'. Returns $null when clean, or a
    # reason string. Every component is probed no-follow relative to its
    # retained validated parent handle, and each present component faces
    # the owner plus all-trustee DACL check. A missing component ends the
    # walk as clean-so-far (the caller knows whether the leaf exists).
    # Get-Acl reads by path, which follows links, but every component on
    # the chain was just proven link-free through its validated parent;
    # only an administrator could plant a link between the probe and the
    # read, which is outside the threat model.
    $parts = $path.Substring(6).Split('\')
    $parent = $HKEY_LOCAL_MACHINE
    $prefix = @()
    foreach ($part in $parts) {
        $probe = Test-LinkComponent $parent ([string]$part)
        if ($probe -eq 'link' -or $probe -eq 'unknown') {
            $here = (($prefix + @($part)) -join '\')
            if ($parent -ne $HKEY_LOCAL_MACHINE) { [void][RegLinkProbe]::RegCloseKey($parent) }
            return "link-or-unknown component $here ($probe)"
        }
        if ($probe -eq 'missing') {
            if ($parent -ne $HKEY_LOCAL_MACHINE) { [void][RegLinkProbe]::RegCloseKey($parent) }
            return $null
        }
        $prefix += $part
        $full = 'HKLM:\' + ($prefix -join '\')
        $acl = Get-Acl -Path $full
        if ($trustedOwners -notcontains $acl.Owner) {
            if ($parent -ne $HKEY_LOCAL_MACHINE) { [void][RegLinkProbe]::RegCloseKey($parent) }
            return "untrusted owner $($acl.Owner) on $full"
        }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if (($ace.RegistryRights.value__ -band $storeWrite) -eq 0) { continue }
            if ($trustedWriters -contains $ace.IdentityReference.Value) { continue }
            if ($parent -ne $HKEY_LOCAL_MACHINE) { [void][RegLinkProbe]::RegCloseKey($parent) }
            return "store-changing grant to $($ace.IdentityReference.Value) on $full"
        }
        $next = Open-NoFollow $parent ([string]$part)
        if ($parent -ne $HKEY_LOCAL_MACHINE) { [void][RegLinkProbe]::RegCloseKey($parent) }
        if ($null -eq $next) { return "cannot descend into $full" }
        $parent = $next
    }
    if ($parent -ne $HKEY_LOCAL_MACHINE) { [void][RegLinkProbe]::RegCloseKey($parent) }
    return $null
}

$verdict = 'UNKNOWN|validation did not run'
$code = 2
try {
    $leaf = 'HKLM:\SOFTWARE\TUIGSE\Hivemend'
    if (!(Test-Path $leaf)) {
        # No store yet: the ancestors alone decide. A hostile ancestor
        # could replace anything created under it.
        $reason = Test-StoreObject 'HKLM:\SOFTWARE\TUIGSE'
        if ($null -eq $reason) { $reason = Test-StoreObject 'HKLM:\SOFTWARE' }
        if ($null -eq $reason) { $verdict = 'ABSENT|no store, ancestry clean'; $code = 0 }
        else { $verdict = "HOSTILE|$reason"; $code = 1 }
    } else {
        $reason = Test-StoreObject $leaf
        if ($null -eq $reason) { $verdict = 'PROTECTED|existing store passes'; $code = 0 }
        else { $verdict = "HOSTILE|$reason"; $code = 1 }
    }
} catch {
    $verdict = "UNKNOWN|$($_.Exception.Message)"
    $code = 2
}
Set-Content -Path $OutFile -Value $verdict
exit $code
