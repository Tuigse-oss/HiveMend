# Run on an interactive elevated disposable Windows desktop.
# Exercises actual controls without scanning or repairing the machine.
param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string]$OutDir)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutDir | Out-Null
Start-Transcript (Join-Path $OutDir 'ui-transcript.txt') -Force
$process = $null
$result = [ordered]@{ Passed=$false; StartedUTC=[DateTime]::UtcNow.ToString('o'); Cases=@() }
try {
    Add-Type -AssemblyName System.Drawing
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ThemeUI {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left,Top,Right,Bottom; }
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr window,System.Text.StringBuilder text,int count);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern uint GetDoubleClickTime();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags,int dx,int dy,uint data,UIntPtr extra);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr window, IntPtr after,
        int x,int y,int width,int height,uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr window, int id);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr SendMessageTimeout(
        IntPtr window, uint msg, IntPtr wparam, IntPtr lparam, uint flags, uint timeout, out IntPtr result);
    [DllImport("user32.dll")] public static extern bool InvalidateRect(IntPtr window, IntPtr rect, bool erase);
}
'@
    [void][ThemeUI]::SetProcessDPIAware()
    $result.OS = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber)
    $result.HarnessSHA256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $result.BinarySHA256 = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $result.Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$result.Elevated) { throw 'This test requires elevation so appearance choices remain session-only.' }
    $process = Start-Process $Exe -PassThru
    $deadline = (Get-Date).AddSeconds(30)
    do { Start-Sleep -Milliseconds 250; $process.Refresh() } while ($process.MainWindowHandle -eq 0 -and !$process.HasExited -and (Get-Date) -lt $deadline)
    if ($process.MainWindowHandle -eq 0) { throw 'No interactive app window' }
    $window = $process.MainWindowHandle
    function Click-Control([IntPtr]$control) {
        $bounds = Rectangle $control
        if (![ThemeUI]::IsWindowVisible($control) -or $bounds.Right -le $bounds.Left -or $bounds.Bottom -le $bounds.Top) { throw 'Control has no visible rectangle' }
        [void][ThemeUI]::SetForegroundWindow($window)
        if (![ThemeUI]::SetCursorPos([int](($bounds.Left+$bounds.Right)/2),[int](($bounds.Top+$bounds.Bottom)/2))) { throw 'Cannot position pointer' }
        [ThemeUI]::mouse_event(2,0,0,0,[UIntPtr]::Zero)
        [ThemeUI]::mouse_event(4,0,0,0,[UIntPtr]::Zero)
        Start-Sleep -Milliseconds 300
    }
    function Press([string]$name) {
        # These named controls intentionally have zero-alpha regions. Locate
        # their real native rectangles, then click the drawn UI underneath.
        $labels = @()
        foreach ($id in 3000..3063) {
            $button = [ThemeUI]::GetDlgItem($window,$id)
            if ($button -eq [IntPtr]::Zero -or ![ThemeUI]::IsWindowVisible($button)) { continue }
            $label = [Text.StringBuilder]::new(256)
            [void][ThemeUI]::GetWindowText($button,$label,256)
            $labels += $label.ToString()
            if ($label.ToString() -eq $name) {
                Write-Host "click: $name, native id=$id"
                Click-Control $button
                return
            }
        }
        throw "Missing native button: $name; labels=$($labels -join ', ')"
    }
    function Message([IntPtr]$target, [uint32]$msg, [int]$wparam=0, [int]$lparam=0) {
        $reply = [IntPtr]::Zero
        if ([ThemeUI]::SendMessageTimeout($target,$msg,[IntPtr]::new($wparam),[IntPtr]::new($lparam),2,3000,[ref]$reply) -eq [IntPtr]::Zero) { throw "Native message timed out: $msg" }
        return $reply.ToInt64()
    }
    function Rectangle([IntPtr]$target) {
        $rect = [ThemeUI+Rect]::new()
        if (![ThemeUI]::GetWindowRect($target,[ref]$rect)) { throw 'Cannot read rectangle' }
        return $rect
    }
    function Shot([string]$name) {
        $rect = Rectangle $window
        $image = [Drawing.Bitmap]::new($rect.Right-$rect.Left,$rect.Bottom-$rect.Top)
        $graphics = [Drawing.Graphics]::FromImage($image)
        try {
            $graphics.CopyFromScreen($rect.Left,$rect.Top,0,0,$image.Size)
            $image.Save((Join-Path $OutDir "$name.png"),[Drawing.Imaging.ImageFormat]::Png)
        } finally { $graphics.Dispose(); $image.Dispose() }
    }
    $dpi = [ThemeUI]::GetDpiForWindow($window)
    $result.DPI = $dpi
    $minimumWidth = [int][Math]::Round(900*$dpi/96)
    $minimumHeight = [int][Math]::Round(660*$dpi/96)
    $caseIndex = 0
    foreach ($size in @(@(1000,720),@($minimumWidth,$minimumHeight))) {
        if (![ThemeUI]::SetWindowPos($window,[IntPtr]::Zero,10,10,$size[0],$size[1],4)) { throw 'Resize failed' }
        Start-Sleep -Milliseconds 350
        $actual = Rectangle $window
        if (($actual.Right-$actual.Left) -ne $size[0] -or ($actual.Bottom-$actual.Top) -ne $size[1]) {
            throw 'The native window did not reach the requested test size'
        }
        foreach ($mode in @('Light','Dark','System','Dark','Light')) {
            $caseIndex++
            Press 'Settings'
            Press $mode
            $list = [ThemeUI]::GetDlgItem($window,2003)
            $button = [ThemeUI]::GetDlgItem($window,1103)
            if (![ThemeUI]::IsWindowVisible($list) -or ![ThemeUI]::IsWindowVisible($button)) { throw 'Settings list/button hidden' }
            $listRect = Rectangle $list
            $buttonRect = Rectangle $button
            if ($listRect.Bottom -gt $buttonRect.Top -or $listRect.Bottom -le $listRect.Top) { throw 'Settings controls overlap or list has no rows' }
            $visibleChecks = @(1200..1211 | Where-Object {
                $check = [ThemeUI]::GetDlgItem($window,$_)
                $check -ne [IntPtr]::Zero -and [ThemeUI]::IsWindowVisible($check)
            })
            if ($visibleChecks.Count -ne 12) { throw 'Scanner checkboxes are not visible' }
            $checkboxHandle = [ThemeUI]::GetDlgItem($window,1200)
            $before = Message $checkboxHandle 0xF0 # BM_GETCHECK
            Click-Control $checkboxHandle
            if ((Message $checkboxHandle 0xF0) -eq $before) { throw 'Scanner checkbox did not toggle' }
            Start-Sleep -Milliseconds ([int][ThemeUI]::GetDoubleClickTime()+50)
            Click-Control $checkboxHandle
            if ((Message $checkboxHandle 0xF0) -ne $before) { throw 'Scanner checkbox did not restore' }
            Shot "$caseIndex-settings-$($size[0])-$mode"
            Press 'Scan'
            $list = [ThemeUI]::GetDlgItem($window,2000)
            $background = Message $list 0x1000 # LVM_GETBKCOLOR proves the theme click applied
            if (($mode -eq 'Light' -and $background -ne 0xFFFFFF) -or
                ($mode -eq 'Dark' -and $background -ne 0x1C201A)) {
                throw "Theme choice did not reach the native list: $mode, color=$background"
            }
            $header = [IntPtr]::new((Message $list 0x101F)) # LVM_GETHEADER
            if ($header -eq [IntPtr]::Zero) { throw 'Missing native list header' }
            $columns = Message $header 0x1200 # HDM_GETITEMCOUNT, dispatched to saved proc in dark
            if ($columns -ne 4) { throw "Header dispatch lost columns: $columns" }
            $font = Message $header 0x31 # WM_GETFONT, another non-paint dispatch
            if ((Message $list 0x101E 0 145) -eq 0) { throw 'Native column resizing failed' }
            [void][ThemeUI]::InvalidateRect($header,[IntPtr]::Zero,$true)
            [void](Message $header 0xF) # WM_PAINT
            if ($process.HasExited) { throw 'App exited during header dispatch' }
            Shot "$caseIndex-header-$($size[0])-$mode"
            $result.Cases += [ordered]@{ Mode=$mode; Width=$size[0]; Height=$size[1]; Columns=$columns; Font=$font; NativeBackground=$background; ListBottom=$listRect.Bottom; ButtonTop=$buttonRect.Top; Checkboxes=$visibleChecks.Count }
            Write-Host "ok: size=$($size -join 'x') mode=$mode, Settings interactions/layout, native header count/font/resize/paint"
        }
    }
    $result.Passed = $true
} catch {
    $result.Error = ($_ | Out-String)
    Write-Host $result.Error
} finally {
    if ($process -and !$process.HasExited) { $process.CloseMainWindow() | Out-Null; if (!$process.WaitForExit(5000)) { $process.Kill() } }
    $result.EndedUTC = [DateTime]::UtcNow.ToString('o')
    $result | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutDir 'ui-result.json') -Encoding UTF8
    Stop-Transcript
}
if (!$result.Passed) { exit 1 }
