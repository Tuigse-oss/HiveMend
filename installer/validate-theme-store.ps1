# Validate without mutation by default. -Theme performs a fresh handle-bound
# validate/create/write operation; no cached verdict authorizes a later write.
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [ValidateSet('', 'light', 'system', 'dark')][string]$Theme = ''
)
$ErrorActionPreference = 'Stop'
$code = 2
$verdict = 'UNKNOWN|validation did not run'
try {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

public static class ThemeStore {
    const int Read = 0x20001, View64 = 0x100, OpenLink = 8;
    const uint WriteMask = 0x000D0026U | 0x50000000U | 0x02000000U;
    [StructLayout(LayoutKind.Sequential)] struct UnicodeString {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
        public int Length;
        public IntPtr Root, Name;
        public uint Attributes;
        public IntPtr Security, Quality;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    static extern int RegOpenKeyEx(IntPtr root, string name, int options, int access, out IntPtr key);
    [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    static extern int RegSetValueEx(IntPtr key, string name, int reserved, int type, byte[] data, int size);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityInfo(IntPtr key, int type, uint info, out IntPtr owner,
        IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("ntdll.dll")]
    static extern int NtQueryKey(IntPtr key, int kind, [Out] uint[] info, int size, out int used);
    [DllImport("ntdll.dll")]
    static extern int NtCreateKey(out IntPtr key, int access, ref ObjectAttributes attributes,
        int title, IntPtr cls, int options, out int disposition);

    static bool Trusted(string sid) { return sid == "S-1-5-18" || sid == "S-1-5-32-544"; }
    static void Verify(IntPtr key) {
        uint[] flags = new uint[3]; int used;
        int status = NtQueryKey(key, 5, flags, 12, out used); // KeyFlagsInformation
        if (status < 0 || used < 8) throw new InvalidOperationException("cannot check key flags");
        if ((flags[1] & 2) != 0) throw new InvalidOperationException("registry link refused");
        IntPtr owner, dacl, sd;
        uint rc = GetSecurityInfo(key, 4, 5, out owner, IntPtr.Zero, out dacl, IntPtr.Zero, out sd);
        try {
            if (rc != 0 || sd == IntPtr.Zero || owner == IntPtr.Zero || dacl == IntPtr.Zero)
                throw new InvalidOperationException("cannot check owner/DACL");
            byte[] bytes = new byte[GetSecurityDescriptorLength(sd)];
            Marshal.Copy(sd, bytes, 0, bytes.Length);
            RawSecurityDescriptor security = new RawSecurityDescriptor(bytes, 0);
            if (!Trusted(security.Owner.Value)) throw new InvalidOperationException("untrusted owner");
            if (security.DiscretionaryAcl == null || security.DiscretionaryAcl.Count == 0)
                throw new InvalidOperationException("missing/empty DACL");
            foreach (GenericAce entry in security.DiscretionaryAcl) {
                if ((entry.AceFlags & AceFlags.InheritOnly) != 0) continue;
                QualifiedAce ace = entry as QualifiedAce;
                if (ace == null) throw new InvalidOperationException("unsupported ACE");
                if (ace.AceQualifier == AceQualifier.AccessDenied) continue;
                if (ace.AceQualifier != AceQualifier.AccessAllowed)
                    throw new InvalidOperationException("unsupported ACE qualifier");
                if (Trusted(ace.SecurityIdentifier.Value) || ace.SecurityIdentifier.Value == "S-1-3-0") continue;
                if (((uint)ace.AccessMask & WriteMask) != 0)
                    throw new InvalidOperationException("store-changing grant to " + ace.SecurityIdentifier.Value);
            }
        } finally { if (sd != IntPtr.Zero) LocalFree(sd); }
    }

    static IntPtr Create(IntPtr parent, string name, int access) {
        // OBJ_OPENLINK keeps even a racing existing link as the link object.
        // The returned object is verified before descent or a value write.
        byte[] bytes = new byte[new RawSecurityDescriptor(
            "O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)").BinaryLength];
        new RawSecurityDescriptor("O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)").GetBinaryForm(bytes, 0);
        IntPtr buffer = Marshal.StringToHGlobalUni(name);
        IntPtr unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
        GCHandle security = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try {
            UnicodeString text = new UnicodeString { Length = (ushort)(name.Length * 2),
                MaximumLength = (ushort)(name.Length * 2 + 2), Buffer = buffer };
            Marshal.StructureToPtr(text, unicode, false);
            ObjectAttributes attributes = new ObjectAttributes {
                Length = Marshal.SizeOf(typeof(ObjectAttributes)), Root = parent, Name = unicode,
                Attributes = 0x140, Security = security.AddrOfPinnedObject() };
            IntPtr key; int disposition;
            int status = NtCreateKey(out key, access, ref attributes, 0, IntPtr.Zero, 0, out disposition);
            if (status < 0) throw new InvalidOperationException("create failed: NTSTATUS " + status.ToString("X8"));
            return key;
        } finally { security.Free(); Marshal.FreeHGlobal(unicode); Marshal.FreeHGlobal(buffer); }
    }

    // Public only for disposable native fixtures. Production always uses HKLM,
    // SOFTWARE\TUIGSE\Hivemend. Every opened handle remains alive until return.
    public static string Run(IntPtr root, string path, string theme) {
        bool write = !String.IsNullOrEmpty(theme);
        if (write && theme != "light" && theme != "system" && theme != "dark")
            throw new ArgumentException("invalid theme");
        string[] names = path.Split('\\');
        List<IntPtr> held = new List<IntPtr>();
        IntPtr parent = root;
        try {
            for (int i = 0; i < names.Length; i++) {
                if (String.IsNullOrEmpty(names[i])) throw new ArgumentException("empty component");
                int access = Read | View64 | (write ? (i == names.Length - 1 ? 2 : 4) : 0);
                IntPtr child;
                int rc = RegOpenKeyEx(parent, names[i], OpenLink, access, out child);
                if (rc == 2) {
                    if (!write) return "ABSENT|validated parent, missing component";
                    // Parent was verified before reaching this component.
                    child = Create(parent, names[i], access);
                } else if (rc != 0) throw new Win32Exception(rc);
                held.Add(child);
                Verify(child);
                parent = child;
            }
            if (write) {
                byte[] data = System.Text.Encoding.Unicode.GetBytes(theme + "\0");
                int rc = RegSetValueEx(parent, "Theme", 0, 1, data, data.Length);
                if (rc != 0) throw new Win32Exception(rc);
                return "WRITTEN|validated handle";
            }
            return "PROTECTED|validated handle chain";
        } finally { for (int i = held.Count - 1; i >= 0; i--) RegCloseKey(held[i]); }
    }
}
'@
    # Sign-extend the predefined HKEY on 64-bit hosts; request the 64-bit view.
    $verdict = [ThemeStore]::Run([IntPtr]::new(-2147483646), 'SOFTWARE\TUIGSE\Hivemend', $Theme)
    $code = 0
} catch {
    $verdict = "REFUSED|$($_.Exception.Message)"
    $code = 1
}
# ASCII is readable by Inno on both Windows PowerShell 5.1 and pwsh.
Set-Content -LiteralPath $OutFile -Value $verdict -Encoding ASCII
exit $code
