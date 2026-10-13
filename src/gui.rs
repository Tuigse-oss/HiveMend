//! Window home screen: blue header, left navigation, three action cards,
//! and a status summary.
//!
//! Safety rules the window follows:
//! - Scanning never writes.
//! - Repair only touches ticked rows. Rows that cannot be backed up have no
//!   check box. Temp files (no backup) and machine-wide entries without
//!   administrator rights start unticked.
//! - Before anything is removed, the ticked rows are scanned again and only
//!   the ones still broken are repaired, after a backup is written.
//! - The window cannot be closed while a repair or restore is running.
#![allow(unsafe_op_in_unsafe_fn)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use registry_master::{
    BackupInfo, BackupSummary, CleanOutcome, Engine, Exclusions, Finding, HostFs, ItemOutcome,
    Preview, PrivacyItem, Repair, RepairOutcome, SUGGESTED, ScanOptions, ScanReport,
    ScannerId, ScmServiceStore, ServiceChange, ServiceInfo, ServiceOutcome, ServiceState,
    ServiceStore, Settings, StartType, WINDOWS_TOOLS, WindowsProcessList, WindowsRegistry,
    WindowsSystemTargets, apply_start_changes, backups_dir, build_items, clean_with_progress,
    custom_privacy_file, decode_text_owned, exclusions_file, expand_target, format_bytes,
    format_uptime, gather_snapshot, import_reg_file, list_backups, parse_custom, plan_profile,
    preview, read_backup, repair_with_progress, restore_files, scan_with_progress,
    settings_file, sort_services, start_services, still_reported, stop_services,
};
use windows_sys::Win32::Foundation::{
    FILETIME, HANDLE, HWND, LPARAM, LRESULT, POINT, RECT, SYSTEMTIME, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, ClientToScreen, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreatePen,
    CreateSolidBrush, DT_CALCRECT, DT_CENTER, DT_END_ELLIPSIS, DT_NOPREFIX, DT_RIGHT,
    DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, DeleteDC, DeleteObject, DrawTextW, EndPaint,
    FillRect, GRADIENT_FILL_RECT_H, GRADIENT_FILL_RECT_V, GradientFill, HALFTONE, HBITMAP,
    HBRUSH, HDC, HFONT, InvalidateRect, PAINTSTRUCT, RoundRect, SRCCOPY, SelectObject,
    SetBkColor, SetBkMode, SetBrushOrgEx, SetStretchBltMode, SetTextColor, StretchBlt,
    TRANSPARENT, TRIVERTEX,
};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ, RegSetKeyValueW};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows_sys::Win32::UI::Controls::{
    ICC_LISTVIEW_CLASSES, ICC_PROGRESS_CLASS, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX,
    InitCommonControlsEx, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_PARAM, LVIF_STATE, LVIF_TEXT,
    LVIS_STATEIMAGEMASK, LVITEMW, LVM_DELETEALLITEMS, LVM_GETITEMCOUNT, LVM_GETITEMRECT, LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTITEMW,
    LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMSTATE, LVM_SETITEMTEXTW,
    LVN_ITEMCHANGED, LVN_ITEMCHANGING, LVNI_SELECTED, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER,
    LVS_EX_FULLROWSELECT, LVS_EX_LABELTIP, LVS_NOSORTHEADER, LVS_REPORT, LVS_SHOWSELALWAYS,
    LVS_SINGLESEL, NM_DBLCLK, NMHDR, NMLISTVIEW, PBM_SETPOS, PBM_SETRANGE32, PROGRESS_CLASSW,
    SetWindowTheme, WC_LISTVIEWW,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows_sys::Win32::UI::Controls::WM_MOUSELEAVE;
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_PUSHBUTTON, CW_USEDEFAULT,
    CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GWLP_USERDATA, GetClientRect, GetCursorPos, GetMessageW,
    GetWindowLongPtrW, HMENU, HTCLIENT, IDC_ARROW, IDC_HAND, IDYES, IMAGE_BITMAP,
    IsDialogMessageW, LR_CREATEDIBSECTION, LR_LOADFROMFILE, LoadCursorW, LoadImageW, MB_DEFBUTTON2,
    MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MB_YESNO, MF_GRAYED,
    MF_SEPARATOR, MF_STRING, MINMAXINFO, MSG, MessageBoxW, MoveWindow, PostMessageW, PostQuitMessage,
    RegisterClassW, SW_HIDE, SW_SHOW, SW_SHOWNORMAL, SWP_NOACTIVATE, SWP_NOZORDER, SendMessageW,
    SetCursor, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE, WM_COMMAND,
    WM_CONTEXTMENU, WM_CREATE, WM_CTLCOLORBTN, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED,
    WM_ERASEBKGND, WM_GETMINMAXINFO, WM_LBUTTONUP, WM_MOUSEMOVE, WM_NOTIFY,
    WM_PAINT, WM_SETCURSOR, WM_SETFONT, WM_SETREDRAW, WM_SIZE, WNDCLASSW, WS_BORDER, WS_CHILD,
    WS_CLIPCHILDREN, WS_EX_CONTROLPARENT, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE,
    WS_VSCROLL,
};

const WM_JOB_PROGRESS: u32 = WM_APP + 1;
const WM_JOB_DONE: u32 = WM_APP + 2;

// Control ids. 1 and 2 are IDOK and IDCANCEL, which IsDialogMessage sends for
// Enter and Esc.
const ID_SCAN: u16 = 1001;
const ID_SELECT_ALL: u16 = 1002;
const ID_SELECT_NONE: u16 = 1003;
const ID_IGNORE: u16 = 1004;
const ID_REPAIR: u16 = 1005;
const ID_CANCEL_SCAN: u16 = 1006;
const ID_RESTORE: u16 = 1101;
const ID_OPEN_BACKUPS: u16 = 1102;
const ID_UNIGNORE: u16 = 1103;
const ID_SCANNER_BASE: u16 = 1200;
const ID_SVC_REFRESH: u16 = 1300;
const ID_SVC_ALL: u16 = 1301;
const ID_SVC_NONE: u16 = 1302;
const ID_SVC_APPLY: u16 = 1303;
const ID_SVC_START: u16 = 1304;
const ID_SVC_STOP: u16 = 1305;
const ID_PRIV_PREVIEW: u16 = 1400;
const ID_PRIV_ALL: u16 = 1401;
const ID_PRIV_NONE: u16 = 1402;
const ID_PRIV_CLEAN: u16 = 1403;
const ID_FINDINGS: u16 = 2000;
const ID_PROGRESS: u16 = 2001;
const ID_BACKUPS: u16 = 2002;
const ID_IGNORED: u16 = 2003;
const ID_SVC_LIST: u16 = 2004;
const ID_SVC_TUNE: u16 = 2005;
const ID_PRIV_LIST: u16 = 2006;
const IDCANCEL: u16 = 2;

const MENU_DETAILS: usize = 1;
const MENU_COPY: usize = 2;
const MENU_SHOW: usize = 3;
const MENU_IGNORE: usize = 4;
const MENU_SVC_START: usize = 11;
const MENU_SVC_STOP: usize = 12;
const MENU_SVC_AUTO: usize = 13;
const MENU_SVC_AUTO_DELAYED: usize = 14;
const MENU_SVC_MANUAL: usize = 15;
const MENU_SVC_DISABLED: usize = 16;

/// Layout is designed at 96 DPI and scaled.
const HEADER_H: i32 = 72;
const SIDEBAR_W: i32 = 172;
const CONTENT_X: i32 = 196;
const FOOTER_H: i32 = 8;
const TITLE_Y: i32 = HEADER_H + 14;
const SUBTITLE_Y: i32 = HEADER_H + 52;
/// Where page content starts, below the title and subtitle.
const BODY_Y: i32 = HEADER_H + 90;
const LIST_Y: i32 = BODY_Y + 22;
const SETTINGS_IGNORED_Y: i32 = BODY_Y + 34 + 6 * 30 + 18;

const BG: u32 = rgb(255, 255, 255);
const SIDEBAR_BG: u32 = rgb(232, 236, 242);
const INK: u32 = rgb(28, 28, 28);
const MUTED: u32 = rgb(92, 98, 108);
const LINK: u32 = rgb(16, 120, 52);
const BLUE_INK: u32 = rgb(24, 64, 140);
const ACCENT: u32 = rgb(196, 32, 32);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Status,
    Scan,
    Restore,
    Settings,
    Services,
    Privacy,
    Monitor,
    Tools,
    About,
}

const NAV: &[(&str, Page)] = &[
    ("Status", Page::Status),
    ("Start Scan", Page::Scan),
    ("Restore", Page::Restore),
    ("Settings", Page::Settings),
    ("Services", Page::Services),
    ("Privacy", Page::Privacy),
    ("Monitor", Page::Monitor),
    ("Tools", Page::Tools),
    ("About", Page::About),
];

/// Friendly names and what each scanner looks at, for Settings.
const SCANNERS: &[(ScannerId, &str)] = &[
    (ScannerId::SoftwareLocations, "Software locations and run history"),
    (ScannerId::StartupPrograms, "Startup programs"),
    (ScannerId::AddRemovePrograms, "Uninstall entries and firewall rules"),
    (ScannerId::CustomControls, "COM controls and shell extensions"),
    (ScannerId::FileExtensions, "File associations and Open With"),
    (ScannerId::SharedDlls, "Shared DLLs"),
    (ScannerId::WindowsFonts, "Fonts"),
    (ScannerId::HelpResources, "Help files and sounds"),
    (ScannerId::VirtualDevices, "Virtual devices"),
    (ScannerId::TempShortcuts, "Broken shortcuts and old temp files"),
    (ScannerId::RegistryIntegrity, "Shell folders (report only)"),
    (ScannerId::DeepScan, "Deep Scan (slower; review results closely)"),
];

const OPTIMIZE: [ScannerId; 4] = [
    ScannerId::StartupPrograms,
    ScannerId::AddRemovePrograms,
    ScannerId::SharedDlls,
    ScannerId::CustomControls,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Job {
    Idle,
    Scanning,
    Repairing,
    Restoring,
    Services,
    Cleaning,
}

/// Services page views: suggested Manual starts, or every service.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SvcView {
    Tuneup,
    Manage,
}

/// What a services worker did: re-read the list, or applied a change.
#[derive(Clone, Copy)]
enum SvcOp {
    Refresh,
    Apply,
}

#[derive(Clone, Copy)]
enum Action {
    Page(Page),
    ScanAll,
    Optimize,
    ResetStats,
    Elevate,
    OpenTool(usize),
    Refresh,
    SvcView(SvcView),
}

impl Action {
    fn starts_job(self) -> bool {
        matches!(self, Action::ScanAll | Action::Optimize | Action::Elevate)
    }
}

struct HotSpot {
    rect: RECT,
    action: Action,
}

enum JobResult {
    Scan {
        report: ScanReport,
        scope: Vec<ScannerId>,
        seconds: f32,
    },
    Repair {
        result: Result<RepairOutcome, String>,
        /// Ticked rows a fresh scan no longer reported.
        fixed_meanwhile: Vec<Finding>,
    },
    Restore {
        file: PathBuf,
        result: Result<(BackupSummary, usize, Vec<String>), String>,
    },
    Services {
        op: SvcOp,
        result: Result<ServiceOutcome, String>,
        services: Vec<ServiceInfo>,
    },
    Privacy {
        result: Result<CleanOutcome, String>,
    },
}

struct Progress {
    done: usize,
    total: usize,
    text: String,
}

static PROGRESS: Mutex<Progress> = Mutex::new(Progress {
    done: 0,
    total: 0,
    text: String::new(),
});
static RESULT: Mutex<Option<JobResult>> = Mutex::new(None);
static CANCEL: AtomicBool = AtomicBool::new(false);

struct Fonts {
    title: HFONT,
    heading: HFONT,
    body: HFONT,
    body_bold: HFONT,
    small: HFONT,
}

struct App {
    hwnd: HWND,
    page: Page,
    dpi: u32,
    fonts: Fonts,
    bg_brush: HBRUSH,
    icons: Vec<HBITMAP>,
    tool_icons: Vec<HBITMAP>,
    hotspots: Vec<HotSpot>,
    hover: Option<usize>,
    tracking: bool,
    elevated: bool,

    settings: Settings,
    exclusions: Exclusions,
    backups: Vec<BackupInfo>,

    job: Job,
    findings: Vec<Finding>,
    checked: Vec<bool>,
    scanned: bool,
    scope: Vec<ScannerId>,
    scan_note: String,
    filling_list: bool,

    list: HWND,
    progress: HWND,
    btn_scan: HWND,
    btn_all: HWND,
    btn_none: HWND,
    btn_ignore: HWND,
    btn_repair: HWND,
    btn_cancel: HWND,
    backup_list: HWND,
    btn_restore: HWND,
    btn_open_backups: HWND,
    scanner_boxes: Vec<(ScannerId, HWND)>,
    ignored_list: HWND,
    btn_unignore: HWND,

    svc_view: SvcView,
    services: Vec<ServiceInfo>,
    svc_loaded: bool,
    svc_proposals: Vec<ServiceChange>,
    svc_checked: Vec<bool>,
    svc_note: String,
    svc_filling: bool,
    svc_list: HWND,
    svc_tune_list: HWND,
    btn_svc_refresh: HWND,
    btn_svc_all: HWND,
    btn_svc_none: HWND,
    btn_svc_apply: HWND,
    btn_svc_start: HWND,
    btn_svc_stop: HWND,
    priv_items: Vec<PrivacyItem>,
    priv_checked: Vec<bool>,
    priv_preview: Option<Preview>,
    priv_outcome: Option<CleanOutcome>,
    priv_note: String,
    priv_filling: bool,
    priv_list: HWND,
    btn_priv_preview: HWND,
    btn_priv_all: HWND,
    btn_priv_none: HWND,
    btn_priv_clean: HWND,
}

pub fn run() -> std::process::ExitCode {
    unsafe {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES,
        };
        InitCommonControlsEx(&icc);
        let class_name = wide("RegistryMasterWindow");
        let class = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: GetModuleHandleW(std::ptr::null()),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            lpszClassName: class_name.as_ptr(),
            ..std::mem::zeroed()
        };
        if RegisterClassW(&class) == 0 {
            return std::process::ExitCode::from(1);
        }
        let dpi = GetDpiForSystem().max(96);
        let title = wide("Registry Master");
        let hwnd = CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            scale(1040, dpi),
            scale(720, dpi),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return std::process::ExitCode::from(1);
        }
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        std::process::ExitCode::from(msg.wParam as u8)
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_CREATE {
        let app = Box::new(App::new(hwnd));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(app) as isize);
        let app = &mut *window_app(hwnd);
        app.sync_controls();
        return 0;
    }
    if msg == WM_GETMINMAXINFO {
        let dpi = GetDpiForWindow(hwnd).max(96);
        let info = &mut *(lparam as *mut MINMAXINFO);
        info.ptMinTrackSize = POINT {
            x: scale(900, dpi),
            y: scale(660, dpi),
        };
        return 0;
    }
    let app = window_app(hwnd);
    if app.is_null() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    let app = &mut *app;
    match msg {
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            app.paint();
            0
        }
        WM_SIZE => {
            app.sync_controls();
            InvalidateRect(hwnd, std::ptr::null(), 0);
            0
        }
        WM_DPICHANGED => {
            app.set_dpi((wparam & 0xffff) as u32);
            let rect = &*(lparam as *const RECT);
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            0
        }
        WM_MOUSEMOVE => {
            let (x, y) = point(lparam);
            app.set_hover(app.spot_at(x, y));
            if !app.tracking {
                let mut track = TRACKMOUSEEVENT {
                    cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                    dwFlags: TME_LEAVE,
                    hwndTrack: hwnd,
                    dwHoverTime: 0,
                };
                TrackMouseEvent(&mut track);
                app.tracking = true;
            }
            0
        }
        WM_MOUSELEAVE => {
            app.tracking = false;
            app.set_hover(None);
            0
        }
        WM_SETCURSOR => {
            if (lparam & 0xffff) as u32 == HTCLIENT && wparam as HWND == hwnd {
                if let Some(index) = app.hover {
                    if app.spot_enabled(index) {
                        SetCursor(LoadCursorW(std::ptr::null_mut(), IDC_HAND));
                        return 1;
                    }
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_LBUTTONUP => {
            let (x, y) = point(lparam);
            if let Some(index) = app.spot_at(x, y) {
                if app.spot_enabled(index) {
                    let action = app.hotspots[index].action;
                    app.perform(action);
                }
            }
            0
        }
        WM_COMMAND => {
            app.command((wparam & 0xffff) as u16, ((wparam >> 16) & 0xffff) as u16);
            0
        }
        WM_NOTIFY => app.notify(&*(lparam as *const NMHDR), lparam),
        WM_CONTEXTMENU => {
            if wparam as HWND == app.list {
                app.findings_menu(lparam);
            } else if wparam as HWND == app.svc_list {
                app.services_menu(lparam);
            }
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            SetBkColor(wparam as HDC, BG);
            app.bg_brush as LRESULT
        }
        WM_JOB_PROGRESS => {
            app.show_progress();
            0
        }
        WM_JOB_DONE => {
            if let Some(result) = RESULT.lock().ok().and_then(|mut slot| slot.take()) {
                app.finish(result);
            }
            0
        }
        WM_CLOSE => {
            if matches!(app.job, Job::Repairing | Job::Restoring | Job::Services | Job::Cleaning) {
                app.message(
                    "Registry Master is still working. Please wait for it to finish before closing.",
                    MB_ICONWARNING,
                );
                return 0;
            }
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            let app = Box::from_raw(app as *mut App);
            app.release();
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn window_app(hwnd: HWND) -> *mut App {
    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App }
}

impl App {
    fn new(hwnd: HWND) -> Self {
        let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
        let mut app = Self {
            hwnd,
            page: Page::Status,
            dpi,
            fonts: make_fonts(dpi),
            bg_brush: unsafe { CreateSolidBrush(BG) },
            icons: [
                "PM-RegScan.bmp",
                "PM-ServiceOptimizer.bmp",
                "PM-SysMonitor.bmp",
                "PM-Settings.bmp",
                "PM-About.bmp",
            ]
            .into_iter()
            .map(load_bitmap)
            .collect(),
            tool_icons: WINDOWS_TOOLS.iter().map(|tool| load_bitmap(tool.icon)).collect(),
            hotspots: Vec::new(),
            hover: None,
            tracking: false,
            elevated: unsafe { IsUserAnAdmin() } != 0,
            settings: Settings::load(&settings_file()),
            exclusions: Exclusions::load(&exclusions_file()),
            backups: list_backups(&backups_dir()),
            job: Job::Idle,
            findings: Vec::new(),
            checked: Vec::new(),
            scanned: false,
            scope: Vec::new(),
            scan_note: String::new(),
            filling_list: false,
            list: std::ptr::null_mut(),
            progress: std::ptr::null_mut(),
            btn_scan: std::ptr::null_mut(),
            btn_all: std::ptr::null_mut(),
            btn_none: std::ptr::null_mut(),
            btn_ignore: std::ptr::null_mut(),
            btn_repair: std::ptr::null_mut(),
            btn_cancel: std::ptr::null_mut(),
            backup_list: std::ptr::null_mut(),
            btn_restore: std::ptr::null_mut(),
            btn_open_backups: std::ptr::null_mut(),
            scanner_boxes: Vec::new(),
            ignored_list: std::ptr::null_mut(),
            btn_unignore: std::ptr::null_mut(),
            svc_view: SvcView::Tuneup,
            services: Vec::new(),
            svc_loaded: false,
            svc_proposals: Vec::new(),
            svc_checked: Vec::new(),
            svc_note: String::new(),
            svc_filling: false,
            svc_list: std::ptr::null_mut(),
            svc_tune_list: std::ptr::null_mut(),
            btn_svc_refresh: std::ptr::null_mut(),
            btn_svc_all: std::ptr::null_mut(),
            btn_svc_none: std::ptr::null_mut(),
            btn_svc_apply: std::ptr::null_mut(),
            btn_svc_start: std::ptr::null_mut(),
            btn_svc_stop: std::ptr::null_mut(),
            priv_items: Vec::new(),
            priv_checked: Vec::new(),
            priv_preview: None,
            priv_outcome: None,
            priv_note: String::new(),
            priv_filling: false,
            priv_list: std::ptr::null_mut(),
            btn_priv_preview: std::ptr::null_mut(),
            btn_priv_all: std::ptr::null_mut(),
            btn_priv_none: std::ptr::null_mut(),
            btn_priv_clean: std::ptr::null_mut(),
        };
        app.create_controls();
        app
    }

    fn create_controls(&mut self) {
        let hwnd = self.hwnd;
        self.list = list_view(
            hwnd,
            ID_FINDINGS,
            0,
            LVS_EX_CHECKBOXES,
            &[("Category", 124), ("Problem", 320), ("Location", 360), ("Fix", 160)],
        );
        self.progress = unsafe {
            CreateWindowExW(
                0,
                PROGRESS_CLASSW,
                std::ptr::null(),
                WS_CHILD,
                0,
                0,
                10,
                10,
                hwnd,
                ID_PROGRESS as usize as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            )
        };
        unsafe { SendMessageW(self.progress, PBM_SETRANGE32, 0, 1000) };
        self.btn_scan = button(hwnd, ID_SCAN, "Start Scan", BS_PUSHBUTTON);
        self.btn_all = button(hwnd, ID_SELECT_ALL, "Tick All", BS_PUSHBUTTON);
        self.btn_none = button(hwnd, ID_SELECT_NONE, "Untick All", BS_PUSHBUTTON);
        self.btn_ignore = button(hwnd, ID_IGNORE, "Ignore Highlighted", BS_PUSHBUTTON);
        self.btn_repair = button(hwnd, ID_REPAIR, "Repair Ticked", BS_PUSHBUTTON);
        self.btn_cancel = button(hwnd, ID_CANCEL_SCAN, "Cancel", BS_PUSHBUTTON);

        self.backup_list = list_view(
            hwnd,
            ID_BACKUPS,
            LVS_SINGLESEL,
            0,
            &[("Saved", 170), ("Contents", 300), ("File", 360)],
        );
        self.btn_restore = button(hwnd, ID_RESTORE, "Restore Selected Backup", BS_PUSHBUTTON);
        self.btn_open_backups = button(hwnd, ID_OPEN_BACKUPS, "Open Backup Folder", BS_PUSHBUTTON);

        for (index, (id, label)) in SCANNERS.iter().enumerate() {
            let check = button(hwnd, ID_SCANNER_BASE + index as u16, label, BS_AUTOCHECKBOX);
            let state = if self.settings.enabled(*id) { 1 } else { 0 };
            unsafe { SendMessageW(check, BM_SETCHECK, state, 0) };
            self.scanner_boxes.push((*id, check));
        }
        self.ignored_list = list_view(hwnd, ID_IGNORED, 0, 0, &[("Ignored entry", 700)]);
        self.btn_unignore = button(hwnd, ID_UNIGNORE, "Stop Ignoring Highlighted", BS_PUSHBUTTON);

        self.svc_list = list_view(
            hwnd,
            ID_SVC_LIST,
            0,
            0,
            &[("Service", 300), ("Status", 110), ("Startup", 150), ("Name", 220)],
        );
        self.svc_tune_list = list_view(
            hwnd,
            ID_SVC_TUNE,
            0,
            LVS_EX_CHECKBOXES,
            &[("Service", 240), ("Now", 150), ("Change to", 130), ("Why", 300)],
        );
        self.btn_svc_refresh = button(hwnd, ID_SVC_REFRESH, "Refresh", BS_PUSHBUTTON);
        self.btn_svc_all = button(hwnd, ID_SVC_ALL, "Tick All", BS_PUSHBUTTON);
        self.btn_svc_none = button(hwnd, ID_SVC_NONE, "Untick All", BS_PUSHBUTTON);
        self.btn_svc_apply = button(hwnd, ID_SVC_APPLY, "Apply Ticked", BS_PUSHBUTTON);
        self.btn_svc_start = button(hwnd, ID_SVC_START, "Start", BS_PUSHBUTTON);
        self.btn_svc_stop = button(hwnd, ID_SVC_STOP, "Stop", BS_PUSHBUTTON);
        self.priv_list = list_view(
            hwnd,
            ID_PRIV_LIST,
            0,
            LVS_EX_CHECKBOXES,
            &[("Category", 250), ("Holds", 210), ("Detail", 360)],
        );
        self.btn_priv_preview = button(hwnd, ID_PRIV_PREVIEW, "Preview", BS_PUSHBUTTON);
        self.btn_priv_all = button(hwnd, ID_PRIV_ALL, "Tick All", BS_PUSHBUTTON);
        self.btn_priv_none = button(hwnd, ID_PRIV_NONE, "Untick All", BS_PUSHBUTTON);
        self.btn_priv_clean = button(hwnd, ID_PRIV_CLEAN, "Clean Ticked", BS_PUSHBUTTON);
        self.apply_fonts();
        self.fill_backups();
        self.fill_ignored();
    }

    fn all_controls(&self) -> Vec<HWND> {
        let mut all = vec![
            self.list,
            self.progress,
            self.btn_scan,
            self.btn_all,
            self.btn_none,
            self.btn_ignore,
            self.btn_repair,
            self.btn_cancel,
            self.backup_list,
            self.btn_restore,
            self.btn_open_backups,
            self.ignored_list,
            self.btn_unignore,
            self.svc_list,
            self.svc_tune_list,
            self.btn_svc_refresh,
            self.btn_svc_all,
            self.btn_svc_none,
            self.btn_svc_apply,
            self.btn_svc_start,
            self.btn_svc_stop,
            self.priv_list,
            self.btn_priv_preview,
            self.btn_priv_all,
            self.btn_priv_none,
            self.btn_priv_clean,
        ];
        all.extend(self.scanner_boxes.iter().map(|(_, hwnd)| *hwnd));
        all
    }

    fn apply_fonts(&self) {
        for control in self.all_controls() {
            unsafe { SendMessageW(control, WM_SETFONT, self.fonts.body as usize, 1) };
        }
    }

    fn set_dpi(&mut self, dpi: u32) {
        self.dpi = dpi.max(96);
        delete_fonts(&self.fonts);
        self.fonts = make_fonts(self.dpi);
        self.apply_fonts();
        self.sync_controls();
        unsafe { InvalidateRect(self.hwnd, std::ptr::null(), 0) };
    }

    fn release(self) {
        for bitmap in self.icons.iter().chain(self.tool_icons.iter()) {
            if !bitmap.is_null() {
                unsafe { DeleteObject(*bitmap) };
            }
        }
        delete_fonts(&self.fonts);
        unsafe { DeleteObject(self.bg_brush) };
    }

    fn s(&self, value: i32) -> i32 {
        scale(value, self.dpi)
    }

    fn busy(&self) -> bool {
        self.job != Job::Idle
    }

    fn client(&self) -> RECT {
        let mut rect = RECT::default();
        unsafe { GetClientRect(self.hwnd, &mut rect) };
        rect
    }

    fn invalidate(&self) {
        unsafe { InvalidateRect(self.hwnd, std::ptr::null(), 0) };
    }

    // ---- actions -------------------------------------------------------

    fn perform(&mut self, action: Action) {
        match action {
            Action::Page(page) => self.go(page),
            Action::ScanAll => self.start_scan(self.settings.full_scan()),
            Action::Optimize => {
                let scope = OPTIMIZE
                    .iter()
                    .copied()
                    .filter(|id| self.settings.enabled(*id))
                    .collect();
                self.start_scan(scope);
            }
            Action::ResetStats => {
                self.settings.last_scan.clear();
                self.settings.last_problems = None;
                self.settings.last_repair.clear();
                self.save_settings();
                self.invalidate();
            }
            Action::Elevate => self.elevate(),
            Action::OpenTool(index) => self.open_tool(index),
            Action::Refresh => self.invalidate(),
            Action::SvcView(view) => {
                if self.busy() {
                    return;
                }
                self.svc_view = view;
                self.sync_controls();
                self.invalidate();
            }
        }
    }

    /// Open a built-in Windows screen. Registry Master only launches it.
    fn open_tool(&self, index: usize) {
        if self.busy() {
            return;
        }
        let Some(tool) = WINDOWS_TOOLS.get(index) else {
            return;
        };
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        shell_open(self.hwnd, &expand_target(tool.target, &root), None);
    }

    fn go(&mut self, page: Page) {
        self.page = page;
        if matches!(page, Page::Restore | Page::Status | Page::Monitor) && !self.busy() {
            self.refresh_backups();
        }
        if page == Page::Services && !self.svc_loaded {
            self.refresh_services();
        }
        if page == Page::Privacy && self.priv_items.is_empty() && !self.busy() {
            self.rebuild_privacy();
        }
        self.sync_controls();
        self.invalidate();
    }

    fn command(&mut self, id: u16, code: u16) {
        const BN_CLICKED: u16 = 0;
        if (ID_SCANNER_BASE..ID_SCANNER_BASE + SCANNERS.len() as u16).contains(&id) {
            if code == BN_CLICKED {
                let index = (id - ID_SCANNER_BASE) as usize;
                let (scanner, check) = self.scanner_boxes[index];
                let on = unsafe { SendMessageW(check, BM_GETCHECK, 0, 0) } == 1;
                self.settings.set_enabled(scanner, on);
                self.save_settings();
            }
            return;
        }
        match id {
            ID_SCAN => {
                let scope = if self.scope.is_empty() {
                    self.settings.full_scan()
                } else {
                    self.scope.clone()
                };
                self.start_scan(scope);
            }
            ID_SELECT_ALL => self.tick_all(true),
            ID_SELECT_NONE => self.tick_all(false),
            ID_IGNORE => {
                let rows = selected_rows(self.list);
                self.ignore_rows(&rows);
            }
            ID_REPAIR => self.start_repair(),
            ID_CANCEL_SCAN | IDCANCEL => {
                if self.job == Job::Scanning {
                    CANCEL.store(true, Ordering::SeqCst);
                    progress_text("Stopping the scan...");
                    self.show_progress();
                } else if self.job == Job::Cleaning {
                    CANCEL.store(true, Ordering::SeqCst);
                    progress_text("Stopping after this category...");
                    self.show_progress();
                }
            }
            ID_RESTORE => {
                if let Some(row) = selected_rows(self.backup_list).first() {
                    self.start_restore(*row);
                } else {
                    self.message("Pick a backup in the list first.", MB_ICONINFORMATION);
                }
            }
            ID_OPEN_BACKUPS => {
                let dir = backups_dir();
                let _ = std::fs::create_dir_all(&dir);
                shell_open(self.hwnd, &dir.display().to_string(), None);
            }
            ID_UNIGNORE => self.unignore(),
            ID_SVC_REFRESH => self.refresh_services(),
            ID_SVC_ALL => self.svc_tick_all(true),
            ID_SVC_NONE => self.svc_tick_all(false),
            ID_SVC_APPLY => self.start_services_apply(),
            ID_SVC_START => self.power_highlighted(true),
            ID_SVC_STOP => self.power_highlighted(false),
            ID_PRIV_PREVIEW => self.run_priv_preview(),
            ID_PRIV_ALL => self.priv_tick_all(true),
            ID_PRIV_NONE => self.priv_tick_all(false),
            ID_PRIV_CLEAN => self.start_privacy_clean(),
            _ => {}
        }
    }

    fn notify(&mut self, header: &NMHDR, lparam: LPARAM) -> LRESULT {
        let id = header.idFrom as u16;
        if id == ID_FINDINGS {
            match header.code {
                LVN_ITEMCHANGING => {
                    let change = unsafe { &*(lparam as *const NMLISTVIEW) };
                    if !self.filling_list && change.uChanged & LVIF_STATE != 0 {
                        let new = (change.uNewState & LVIS_STATEIMAGEMASK) >> 12;
                        let old = (change.uOldState & LVIS_STATEIMAGEMASK) >> 12;
                        let row = change.iItem as usize;
                        let fixed = self.findings.get(row).is_some_and(|f| !f.repairable());
                        // Report-only rows have no check box and stay that way.
                        if new != old && fixed && new != 0 {
                            return 1;
                        }
                        if new != old && self.busy() {
                            return 1;
                        }
                    }
                }
                LVN_ITEMCHANGED => {
                    let change = unsafe { &*(lparam as *const NMLISTVIEW) };
                    if !self.filling_list && change.uChanged & LVIF_STATE != 0 {
                        let new = (change.uNewState & LVIS_STATEIMAGEMASK) >> 12;
                        let old = (change.uOldState & LVIS_STATEIMAGEMASK) >> 12;
                        if new != old {
                            if let Some(slot) = self.checked.get_mut(change.iItem as usize) {
                                *slot = new == 2;
                            }
                            self.update_repair_label();
                        }
                    }
                }
                NM_DBLCLK => {
                    if let Some(row) = selected_rows(self.list).first() {
                        self.show_details(*row);
                    }
                }
                _ => {}
            }
        } else if id == ID_BACKUPS && header.code == NM_DBLCLK {
            if let Some(row) = selected_rows(self.backup_list).first() {
                self.start_restore(*row);
            }
        } else if id == ID_SVC_TUNE {
            match header.code {
                LVN_ITEMCHANGING => {
                    let change = unsafe { &*(lparam as *const NMLISTVIEW) };
                    if !self.svc_filling && change.uChanged & LVIF_STATE != 0 {
                        let new = (change.uNewState & LVIS_STATEIMAGEMASK) >> 12;
                        let old = (change.uOldState & LVIS_STATEIMAGEMASK) >> 12;
                        if new != old && (self.busy() || new == 1) {
                            return 1;
                        }
                    }
                }
                LVN_ITEMCHANGED => {
                    let change = unsafe { &*(lparam as *const NMLISTVIEW) };
                    if !self.svc_filling && change.uChanged & LVIF_STATE != 0 {
                        let new = (change.uNewState & LVIS_STATEIMAGEMASK) >> 12;
                        let old = (change.uOldState & LVIS_STATEIMAGEMASK) >> 12;
                        if new != old {
                            if let Some(slot) = self.svc_checked.get_mut(change.iItem as usize) {
                                *slot = new == 2;
                            }
                            self.update_svc_apply_label();
                        }
                    }
                }
                NM_DBLCLK => {
                    if let Some(row) = selected_rows(self.svc_tune_list).first() {
                        self.show_svc_proposal(*row);
                    }
                }
                _ => {}
            }
        } else if id == ID_SVC_LIST && header.code == NM_DBLCLK {
            if let Some(row) = selected_rows(self.svc_list).first() {
                self.show_svc_details(*row);
            }
        } else if id == ID_PRIV_LIST {
            match header.code {
                LVN_ITEMCHANGING => {
                    let change = unsafe { &*(lparam as *const NMLISTVIEW) };
                    if !self.priv_filling && change.uChanged & LVIF_STATE != 0 {
                        let new = (change.uNewState & LVIS_STATEIMAGEMASK) >> 12;
                        let old = (change.uOldState & LVIS_STATEIMAGEMASK) >> 12;
                        if new != old && self.busy() {
                            return 1;
                        }
                    }
                }
                LVN_ITEMCHANGED => {
                    let change = unsafe { &*(lparam as *const NMLISTVIEW) };
                    if !self.priv_filling && change.uChanged & LVIF_STATE != 0 {
                        let new = (change.uNewState & LVIS_STATEIMAGEMASK) >> 12;
                        let old = (change.uOldState & LVIS_STATEIMAGEMASK) >> 12;
                        if new != old {
                            if let Some(slot) = self.priv_checked.get_mut(change.iItem as usize) {
                                *slot = new == 2;
                            }
                            self.save_priv_ticks();
                            self.update_priv_clean_label();
                        }
                    }
                }
                NM_DBLCLK => {
                    if let Some(row) = selected_rows(self.priv_list).first() {
                        self.show_priv_details(*row);
                    }
                }
                _ => {}
            }
        }
        0
    }

    // ---- scanning ------------------------------------------------------

    fn start_scan(&mut self, scope: Vec<ScannerId>) {
        if self.busy() {
            return;
        }
        if scope.is_empty() {
            self.message(
                "Every scan category is turned off. Turn some on in Settings, then scan again.",
                MB_ICONINFORMATION,
            );
            self.go(Page::Settings);
            return;
        }
        self.job = Job::Scanning;
        self.page = Page::Scan;
        CANCEL.store(false, Ordering::SeqCst);
        set_progress(0, scope.len(), "Starting the scan...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let started = Instant::now();
            let opts = ScanOptions {
                only: scope.clone(),
                include_deep: scope.contains(&ScannerId::DeepScan),
                wow64: true,
            };
            let report = scan_with_progress(
                &Engine::builtin(),
                &WindowsRegistry,
                &HostFs,
                &opts,
                &mut |step, total, name| {
                    if !name.is_empty() {
                        set_progress(step, total, &format!("Checking {name}  ({} of {total})", step + 1));
                        post(hwnd, WM_JOB_PROGRESS);
                    }
                    !CANCEL.load(Ordering::SeqCst)
                },
            );
            finish_job(
                hwnd,
                JobResult::Scan {
                    report,
                    scope,
                    seconds: started.elapsed().as_secs_f32(),
                },
            );
        });
    }

    fn finish_scan(&mut self, mut report: ScanReport, scope: Vec<ScannerId>, seconds: f32) {
        if report.canceled {
            self.scan_note = if self.scanned {
                "Scan canceled. These are the results of the previous scan.".into()
            } else {
                "Scan canceled. Nothing was changed.".into()
            };
            return;
        }
        let ignored = self.exclusions.filter(&mut report.findings);
        self.findings = report.findings;
        self.scanned = true;
        self.scope = scope;
        self.fill_findings();
        self.settings.last_scan = local_now();
        self.settings.last_problems = Some(self.findings.len());
        self.save_settings();
        let mut note = if self.findings.is_empty() {
            format!("No problems found ({seconds:.1} s).")
        } else {
            format!("{} problems found ({seconds:.1} s).", self.findings.len())
        };
        let report_only = self.findings.iter().filter(|f| !f.repairable()).count();
        if report_only > 0 {
            note.push_str(&format!(" {report_only} are for information only."));
        }
        if !self.elevated {
            let admin = self.findings.iter().filter(|f| f.needs_admin()).count();
            if admin > 0 {
                note.push_str(&format!(
                    " {admin} are machine-wide and need Run as administrator."
                ));
            }
        }
        if ignored > 0 {
            note.push_str(&format!(" {ignored} ignored entries hidden."));
        }
        if !report.warnings.is_empty() {
            note.push_str(&format!(" {} keys could not be read.", report.warnings.len()));
        }
        self.scan_note = note;
    }

    fn fill_findings(&mut self) {
        self.filling_list = true;
        self.checked = self.findings.iter().map(|f| self.default_tick(f)).collect();
        unsafe {
            SendMessageW(self.list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0);
            for (row, finding) in self.findings.iter().enumerate() {
                insert_row(
                    self.list,
                    row,
                    &[
                        category(finding.scanner),
                        &compact_detail(&finding.detail),
                        &short_location(finding),
                        &self.fix_label(finding),
                    ],
                );
                let image = if !finding.repairable() {
                    0
                } else if self.checked[row] {
                    2
                } else {
                    1
                };
                set_state_image(self.list, row, image);
            }
            SendMessageW(self.list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.list, std::ptr::null(), 1);
        }
        self.filling_list = false;
        self.update_repair_label();
    }

    /// Ticked unless it cannot be undone, or cannot succeed without rights.
    fn default_tick(&self, finding: &Finding) -> bool {
        finding.repairable()
            && !finding.permanent()
            && (self.elevated || !finding.needs_admin())
    }

    fn fix_label(&self, finding: &Finding) -> String {
        let mut label = match &finding.repair {
            Repair::None => return "Report only".into(),
            Repair::DeleteValue { .. } => "Delete value".to_string(),
            Repair::DeleteKey { .. } => "Delete key".to_string(),
            Repair::DeleteFile { keep_copy: true, .. } => "Delete shortcut (copy kept)".to_string(),
            Repair::DeleteFile { keep_copy: false, .. } => "Delete file (no undo)".to_string(),
        };
        if !self.elevated && finding.needs_admin() {
            label.push_str(", needs admin");
        }
        label
    }

    fn tick_all(&mut self, on: bool) {
        self.filling_list = true;
        for (row, finding) in self.findings.iter().enumerate() {
            if !finding.repairable() {
                continue;
            }
            self.checked[row] = on;
            set_state_image(self.list, row, if on { 2 } else { 1 });
        }
        self.filling_list = false;
        self.update_repair_label();
    }

    fn ticked(&self) -> Vec<Finding> {
        self.findings
            .iter()
            .zip(&self.checked)
            .filter(|(finding, on)| **on && finding.repairable())
            .map(|(finding, _)| finding.clone())
            .collect()
    }

    fn update_repair_label(&self) {
        let count = self.ticked().len();
        let text = if count == 0 {
            "Repair Ticked".to_string()
        } else {
            format!("Repair Ticked ({count})")
        };
        set_text(self.btn_repair, &text);
        unsafe { EnableWindow(self.btn_repair, (count > 0 && !self.busy()) as i32) };
    }

    fn ignore_rows(&mut self, rows: &[usize]) {
        if rows.is_empty() {
            self.message(
                "Click a row to highlight it first. Hold Ctrl or Shift to pick several.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let question = format!(
            "Ignore {} {}?\n\nIgnored entries are hidden from every future scan, so they are never repaired. You can undo this in Settings.",
            rows.len(),
            if rows.len() == 1 { "entry" } else { "entries" }
        );
        if !self.confirm(&question) {
            return;
        }
        for row in rows {
            if let Some(finding) = self.findings.get(*row) {
                self.exclusions.add(finding);
            }
        }
        if let Err(err) = self.exclusions.save(&exclusions_file()) {
            self.message(&format!("Could not save the ignore list: {err}"), MB_ICONWARNING);
        }
        self.drop_rows(rows);
        self.fill_ignored();
    }

    /// Remove rows from the results, keeping the other rows' ticks.
    fn drop_rows(&mut self, rows: &[usize]) {
        let mut keep_findings = Vec::new();
        let mut keep_ticks = Vec::new();
        for (row, (finding, tick)) in self.findings.drain(..).zip(self.checked.drain(..)).enumerate() {
            if !rows.contains(&row) {
                keep_findings.push(finding);
                keep_ticks.push(tick);
            }
        }
        self.findings = keep_findings;
        let ticks = keep_ticks;
        self.fill_findings();
        self.filling_list = true;
        for (row, tick) in ticks.into_iter().enumerate() {
            if self.findings[row].repairable() {
                self.checked[row] = tick;
                set_state_image(self.list, row, if tick { 2 } else { 1 });
            }
        }
        self.filling_list = false;
        self.update_repair_label();
        self.settings.last_problems = Some(self.findings.len());
        self.save_settings();
        self.invalidate();
    }

    fn show_details(&self, row: usize) {
        let Some(finding) = self.findings.get(row) else {
            return;
        };
        let value = match finding.value.as_deref() {
            None => String::new(),
            Some("") => "\nValue: (default)".into(),
            Some(name) => format!("\nValue: {name}"),
        };
        let text = format!(
            "{}\n\nProblem: {}\nLocation: {}{value}\n\nFix: {}",
            finding.scanner_name,
            sentence(&finding.detail),
            finding.key,
            self.fix_label(finding)
        );
        self.message(&text, MB_ICONINFORMATION);
    }

    fn findings_menu(&mut self, lparam: LPARAM) {
        let rows = selected_rows(self.list);
        if rows.is_empty() || self.busy() {
            return;
        }
        let mut at = POINT {
            x: (lparam & 0xffff) as i16 as i32,
            y: ((lparam >> 16) & 0xffff) as i16 as i32,
        };
        if lparam == -1 {
            let mut rect = RECT::default();
            unsafe {
                SendMessageW(self.list, LVM_GETITEMRECT, rows[0], &mut rect as *mut _ as isize);
                at = POINT {
                    x: rect.left + self.s(24),
                    y: rect.bottom,
                };
                ClientToScreen(self.list, &mut at);
            }
        }
        let first = &self.findings[rows[0]];
        let is_file = matches!(first.repair, Repair::DeleteFile { .. });
        let ignore_label = if rows.len() == 1 {
            "Ignore this entry".to_string()
        } else {
            format!("Ignore these {} entries", rows.len())
        };
        let choice = unsafe {
            let menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, MENU_DETAILS, wide("Details...").as_ptr());
            AppendMenuW(menu, MF_STRING, MENU_COPY, wide("Copy location").as_ptr());
            let show = if is_file { "Show in File Explorer" } else { "Show in Registry Editor" };
            AppendMenuW(menu, MF_STRING, MENU_SHOW, wide(show).as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
            AppendMenuW(menu, MF_STRING, MENU_IGNORE, wide(&ignore_label).as_ptr());
            if lparam != -1 {
                GetCursorPos(&mut at);
            }
            let choice = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                at.x,
                at.y,
                0,
                self.hwnd,
                std::ptr::null(),
            );
            DestroyMenu(menu);
            choice as usize
        };
        match choice {
            MENU_DETAILS => self.show_details(rows[0]),
            MENU_COPY => {
                let text = rows
                    .iter()
                    .filter_map(|row| self.findings.get(*row))
                    .map(location)
                    .collect::<Vec<_>>()
                    .join("\r\n");
                copy_text(self.hwnd, &text);
            }
            MENU_SHOW => {
                let finding = self.findings[rows[0]].clone();
                if is_file {
                    let arg = format!("/select,\"{}\"", finding.key);
                    shell_open(self.hwnd, "explorer.exe", Some(&arg));
                } else {
                    open_in_regedit(self.hwnd, &finding.key);
                }
            }
            MENU_IGNORE => self.ignore_rows(&rows),
            _ => {}
        }
    }

    // ---- services ------------------------------------------------------

    fn refresh_services(&mut self) {
        if self.busy() {
            return;
        }
        self.job = Job::Services;
        self.page = Page::Services;
        set_progress(0, 1, "Reading the service list...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let listed = ScmServiceStore.list();
            match listed {
                Ok(mut services) => {
                    sort_services(&mut services);
                    finish_job(
                        hwnd,
                        JobResult::Services {
                            op: SvcOp::Refresh,
                            result: Ok(ServiceOutcome::default()),
                            services,
                        },
                    );
                }
                Err(err) => finish_job(
                    hwnd,
                    JobResult::Services {
                        op: SvcOp::Refresh,
                        result: Err(err.0),
                        services: Vec::new(),
                    },
                ),
            }
        });
    }

    fn svc_ticked(&self) -> Vec<ServiceChange> {
        self.svc_proposals
            .iter()
            .zip(self.svc_checked.iter())
            .filter(|(_, on)| **on)
            .map(|(change, _)| change.clone())
            .collect()
    }

    fn svc_tick_all(&mut self, on: bool) {
        if self.busy() {
            return;
        }
        for slot in self.svc_checked.iter_mut() {
            *slot = on;
        }
        self.fill_services();
    }

    fn update_svc_apply_label(&self) {
        let count = self.svc_checked.iter().filter(|on| **on).count();
        let label = if count == 0 {
            "Apply Ticked".to_string()
        } else {
            format!("Apply Ticked ({count})")
        };
        set_text(self.btn_svc_apply, &label);
        unsafe {
            EnableWindow(
                self.btn_svc_apply,
                (count > 0 && self.elevated && !self.busy()) as i32,
            )
        };
    }

    fn rebuild_proposals(&mut self) {
        let old: Vec<(String, bool)> = self
            .svc_proposals
            .iter()
            .map(|change| change.name.clone())
            .zip(self.svc_checked.iter().copied())
            .collect();
        self.svc_proposals = plan_profile(&SUGGESTED, &self.services);
        self.svc_checked = self
            .svc_proposals
            .iter()
            .map(|change| {
                old.iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(&change.name))
                    .map(|(_, on)| *on)
                    .unwrap_or(false)
            })
            .collect();
    }

    fn start_services_apply(&mut self) {
        if self.busy() {
            return;
        }
        if !self.elevated {
            self.message(
                "Changing services needs administrator rights. Use Run as administrator in the header, then try again.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let selected = self.svc_ticked();
        if selected.is_empty() {
            self.message(
                "Tick the suggestions you want to apply first.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let backup_file = next_services_backup_file();
        let mut question = format!(
            "Set {} to start on demand (Manual)?\n\nRegistry Master saves the current start types to\n{}\nbefore changing anything. You can undo this on the Restore page. Each change takes full effect when the service next starts.",
            if selected.len() == 1 {
                format!("{} ({})", selected[0].display_name, selected[0].from.label())
            } else {
                format!("these {} services", selected.len())
            },
            backup_file.display()
        );
        for change in selected.iter().take(8) {
            question.push_str(&format!(
                "\n{}: {} -> Manual",
                change.display_name,
                change.from.label()
            ));
        }
        if selected.len() > 8 {
            question.push_str(&format!("\n...and {} more", selected.len() - 8));
        }
        if !self.confirm(&question) {
            return;
        }
        self.job = Job::Services;
        set_progress(0, selected.len().max(1), "Saving the current start types...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let outcome = apply_start_changes(
                &mut ScmServiceStore,
                &WindowsRegistry,
                &selected,
                &backup_file,
                &mut |done, total| {
                    set_progress(
                        done,
                        total,
                        &format!("Applying service changes ({done} of {total})..."),
                    );
                    post(hwnd, WM_JOB_PROGRESS);
                },
            );
            let mut services = ScmServiceStore.list().unwrap_or_default();
            sort_services(&mut services);
            finish_job(
                hwnd,
                JobResult::Services {
                    op: SvcOp::Apply,
                    result: outcome.map_err(|err| err.0),
                    services,
                },
            );
        });
    }

    /// Start or stop the highlighted rows in All services.
    fn power_rows(&mut self, rows: &[usize], start: bool) {
        if self.busy() {
            return;
        }
        if !self.elevated {
            self.message(
                "Starting and stopping services needs administrator rights. Use Run as administrator in the header, then try again.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let names: Vec<String> = rows
            .iter()
            .filter_map(|row| self.services.get(*row))
            .map(|info| info.name.clone())
            .collect();
        if names.is_empty() {
            self.message(
                "Highlight a service in All services first.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let verb = if start { "Start" } else { "Stop" };
        let mut question = if names.len() == 1 {
            let info = self
                .services
                .iter()
                .find(|info| info.name == names[0])
                .unwrap();
            format!(
                "{verb} {}?\n\nIt {} now and keeps its startup type{}.",
                info.display_name,
                if start { "starts" } else { "stops" },
                if start { "." } else { ". You can start it again here." }
            )
        } else {
            format!(
                "{verb} these {} services?\n\nStartup types are unchanged.",
                names.len()
            )
        };
        for name in names.iter().take(8) {
            question.push_str(&format!("\n{name}"));
        }
        if names.len() > 8 {
            question.push_str(&format!("\n...and {} more", names.len() - 8));
        }
        if !self.confirm(&question) {
            return;
        }
        self.job = Job::Services;
        set_progress(0, names.len().max(1), &format!("{verb}ing services..."));
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let outcome = if start {
                start_services(&mut ScmServiceStore, &names, &mut |done, total| {
                    set_progress(done, total, &format!("Starting services ({done} of {total})..."));
                    post(hwnd, WM_JOB_PROGRESS);
                })
            } else {
                stop_services(&mut ScmServiceStore, &names, &mut |done, total| {
                    set_progress(done, total, &format!("Stopping services ({done} of {total})..."));
                    post(hwnd, WM_JOB_PROGRESS);
                })
            };
            let mut services = ScmServiceStore.list().unwrap_or_default();
            sort_services(&mut services);
            finish_job(
                hwnd,
                JobResult::Services {
                    op: SvcOp::Apply,
                    result: Ok(outcome),
                    services,
                },
            );
        });
    }

    fn power_highlighted(&mut self, start: bool) {
        let rows = selected_rows(self.svc_list);
        self.power_rows(&rows, start);
    }

    /// Set one startup type for the highlighted rows in All services.
    fn set_rows(&mut self, rows: &[usize], to: StartType) {
        if self.busy() {
            return;
        }
        if !self.elevated {
            self.message(
                "Changing services needs administrator rights. Use Run as administrator in the header, then try again.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let changes: Vec<ServiceChange> = rows
            .iter()
            .filter_map(|row| self.services.get(*row))
            .map(|info| ServiceChange {
                name: info.name.clone(),
                display_name: info.display_name.clone(),
                from: info.start,
                to,
                why: "Chosen in All services.".into(),
            })
            .collect();
        if changes.is_empty() {
            self.message(
                "Highlight a service in All services first.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let backup_file = next_services_backup_file();
        let mut question = format!(
            "Set {} to {}?\n\nRegistry Master saves the current start types to\n{}\nbefore changing anything. You can undo this on the Restore page.",
            if changes.len() == 1 {
                format!(
                    "{} (now {})",
                    changes[0].display_name,
                    changes[0].from.label()
                )
            } else {
                format!("these {} services", changes.len())
            },
            to.label(),
            backup_file.display()
        );
        if to == StartType::Disabled {
            question.push_str("\n\nDisabled means Windows cannot start it at all, even on demand. Prefer Manual unless you are sure.");
        }
        if !self.confirm(&question) {
            return;
        }
        self.job = Job::Services;
        set_progress(0, changes.len().max(1), "Saving the current start types...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let outcome = apply_start_changes(
                &mut ScmServiceStore,
                &WindowsRegistry,
                &changes,
                &backup_file,
                &mut |done, total| {
                    set_progress(
                        done,
                        total,
                        &format!("Applying service changes ({done} of {total})..."),
                    );
                    post(hwnd, WM_JOB_PROGRESS);
                },
            );
            let mut services = ScmServiceStore.list().unwrap_or_default();
            sort_services(&mut services);
            finish_job(
                hwnd,
                JobResult::Services {
                    op: SvcOp::Apply,
                    result: outcome.map_err(|err| err.0),
                    services,
                },
            );
        });
    }

    fn finish_services(
        &mut self,
        op: SvcOp,
        result: Result<ServiceOutcome, String>,
        services: Vec<ServiceInfo>,
    ) {
        match result {
            Err(err) => {
                self.svc_note = "Could not read or change services.".to_string();
                self.message(
                    &format!("Nothing was changed.\n\n{err}"),
                    MB_ICONWARNING,
                );
            }
            Ok(outcome) => {
                if !services.is_empty() || matches!(op, SvcOp::Refresh) {
                    self.services = services;
                    self.svc_loaded = true;
                }
                self.rebuild_proposals();
                self.fill_services();
                match op {
                    SvcOp::Refresh => {
                        self.svc_note = if self.services.is_empty() {
                            "No services listed.".to_string()
                        } else {
                            format!("{} services listed.", self.services.len())
                        };
                    }
                    SvcOp::Apply => {
                        self.refresh_backups();
                        let mut lines = vec![format!("Applied: {}", outcome.applied.len())];
                        for applied in outcome.applied.iter().take(8) {
                            lines.push(applied.clone());
                        }
                        if outcome.applied.len() > 8 {
                            lines.push(format!("...and {} more", outcome.applied.len() - 8));
                        }
                        if outcome.already_correct > 0 {
                            lines.push(format!("Already set: {}", outcome.already_correct));
                        }
                        for refused in &outcome.refused {
                            lines.push(format!("Refused: {refused}"));
                        }
                        for skipped in &outcome.not_backed_up {
                            lines.push(format!("Not backed up, left alone: {skipped}"));
                        }
                        for error in outcome.errors.iter().take(5) {
                            lines.push(format!("Failed: {error}"));
                        }
                        if outcome.denied > 0 {
                            lines.push(
                                "Windows refused some changes for lack of rights. Run as administrator and try again."
                                    .to_string(),
                            );
                        }
                        if !outcome.backup_file.as_os_str().is_empty() {
                            lines.push(format!(
                                "Backup: {}",
                                outcome.backup_file.display()
                            ));
                        }
                        self.svc_note = if outcome.applied.is_empty() && outcome.errors.is_empty() {
                            "Nothing needed changing.".to_string()
                        } else {
                            format!(
                                "Applied {}, refused {}, failed {}.",
                                outcome.applied.len(),
                                outcome.refused.len() + outcome.not_backed_up.len(),
                                outcome.errors.len() + outcome.denied
                            )
                        };
                        let icon = if outcome.applied.is_empty()
                            && (outcome.denied > 0 || !outcome.errors.is_empty())
                        {
                            MB_ICONWARNING
                        } else {
                            MB_ICONINFORMATION
                        };
                        self.message(&lines.join("\n"), icon);
                    }
                }
            }
        }
    }

    // ---- privacy ----

    fn rebuild_privacy(&mut self) {
        let mut items = build_items(&WindowsSystemTargets);
        if let Ok(bytes) = std::fs::read(custom_privacy_file()) {
            let custom = parse_custom(&decode_text_owned(bytes), &HostFs);
            if !custom.targets.is_empty() || !custom.warnings.is_empty() {
                items.push(custom);
            }
        }
        let ticked: Vec<String> = self.settings.privacy_ticked.clone();
        self.priv_checked =
            items.iter().map(|item| ticked.iter().any(|id| id == &item.id)).collect();
        self.priv_items = items;
        self.priv_preview = None;
        self.priv_outcome = None;
        self.fill_privacy();
    }

    fn save_priv_ticks(&mut self) {
        self.settings.privacy_ticked = self
            .priv_items
            .iter()
            .zip(&self.priv_checked)
            .filter(|(_, on)| **on)
            .map(|(item, _)| item.id.clone())
            .collect();
        self.save_settings();
    }

    fn run_priv_preview(&mut self) {
        if self.busy() {
            return;
        }
        if self.priv_items.is_empty() {
            self.rebuild_privacy();
        }
        let report = preview(
            &WindowsRegistry,
            &HostFs,
            &WindowsSystemTargets,
            &WindowsProcessList,
            &self.priv_items,
        );
        self.priv_note = format!(
            "Preview: {} files, {} registry values, {} in scope.",
            report.files(),
            report.values(),
            format_bytes(report.bytes())
        );
        self.priv_preview = Some(report);
        self.fill_privacy();
        self.invalidate();
    }

    fn priv_preview_row(&self, id: &str) -> Option<(String, String)> {
        let row = self.priv_preview.as_ref()?.items.iter().find(|row| row.id == id)?;
        if row.skipped_running {
            let why = row.restricted.first().cloned().unwrap_or_default();
            return Some(("Waiting".to_string(), why));
        }
        if row.gated_out {
            return Some(("Not installed".to_string(), String::new()));
        }
        let mut parts = Vec::new();
        if row.files > 0 {
            parts.push(count(row.files, "file", "files"));
        }
        if row.values > 0 {
            parts.push(count(row.values, "value", "values"));
        }
        if row.other > 0 {
            parts.push(count(row.other, "item", "items"));
        }
        if row.bytes > 0 {
            parts.push(format_bytes(row.bytes));
        }
        if parts.is_empty() {
            parts.push("Empty".to_string());
        }
        let mut holds = parts.join(" · ");
        if !row.restricted.is_empty() {
            let more = row.restricted.len() + row.restricted_extra;
            holds.push_str(&format!(" (+{more} skipped)"));
        }
        Some((holds, String::new()))
    }

    fn fill_privacy(&mut self) {
        self.priv_filling = true;
        unsafe {
            SendMessageW(self.priv_list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.priv_list, LVM_DELETEALLITEMS, 0, 0);
            for (row, item) in self.priv_items.iter().enumerate() {
                let (holds, extra) = self.priv_preview_row(&item.id).unwrap_or_default();
                let detail =
                    if extra.is_empty() { item.detail.clone() } else { extra };
                insert_row(
                    self.priv_list,
                    row,
                    &[&item.name, &holds, &detail],
                );
                set_state_image(
                    self.priv_list,
                    row,
                    if self.priv_checked.get(row).copied().unwrap_or(false) { 2 } else { 1 },
                );
            }
            SendMessageW(self.priv_list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.priv_list, std::ptr::null(), 1);
        }
        self.priv_filling = false;
        self.update_priv_clean_label();
    }

    fn priv_tick_all(&mut self, on: bool) {
        if self.busy() {
            return;
        }
        for slot in self.priv_checked.iter_mut() {
            *slot = on;
        }
        self.fill_privacy();
        self.save_priv_ticks();
    }

    fn priv_ticked(&self) -> Vec<PrivacyItem> {
        self.priv_items
            .iter()
            .zip(&self.priv_checked)
            .filter(|(_, on)| **on)
            .map(|(item, _)| item.clone())
            .collect()
    }

    fn update_priv_clean_label(&self) {
        let count = self.priv_checked.iter().filter(|on| **on).count();
        let ready = self.priv_preview.is_some();
        let text = if count == 0 {
            "Clean Ticked".to_string()
        } else {
            format!("Clean Ticked ({count})")
        };
        set_text(self.btn_priv_clean, &text);
        unsafe { EnableWindow(self.btn_priv_clean, (count > 0 && ready && !self.busy()) as i32) };
    }

    fn start_privacy_clean(&mut self) {
        if self.busy() {
            return;
        }
        let selected = self.priv_ticked();
        if selected.is_empty() {
            self.message("Tick the categories you want to clean first.", MB_ICONINFORMATION);
            return;
        }
        if self.priv_preview.is_none() {
            self.message(
                "Preview first, so you can see what each category holds.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let backup_file = next_privacy_backup_file();
        let mut question = format!(
            "Clean {} {}?\n\nRegistry Master saves the registry entries to\n{}\nbefore removing anything. You can undo those on the Restore page. Files (temp, caches, bin contents) are deleted for good and are not backed up.",
            selected.len(),
            if selected.len() == 1 { "category" } else { "categories" },
            backup_file.display()
        );
        let shown = selected.iter().take(10);
        for item in shown {
            let holds = self
                .priv_preview_row(&item.id)
                .map(|(holds, _)| holds)
                .unwrap_or_default();
            question.push_str(&format!("\n{}: {holds}", item.name));
            if let Some(note) = &item.confirm_note {
                question.push_str(&format!("\n  {note}"));
            }
        }
        if selected.len() > 10 {
            question.push_str(&format!("\n...and {} more", selected.len() - 10));
        }
        if !self.confirm(&question) {
            return;
        }
        self.job = Job::Cleaning;
        self.page = Page::Privacy;
        CANCEL.store(false, Ordering::SeqCst);
        set_progress(0, selected.len().max(1), "Starting the clean...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let result = clean_with_progress(
                &mut WindowsRegistry,
                &mut HostFs,
                &mut WindowsSystemTargets,
                &WindowsProcessList,
                &selected,
                &backup_file,
                &mut |done, total, name| {
                    set_progress(
                        done,
                        total.max(1),
                        &format!("Cleaning {name} ({done} of {total})..."),
                    );
                    post(hwnd, WM_JOB_PROGRESS);
                    !CANCEL.load(Ordering::SeqCst)
                },
            )
            .map_err(|err| err.to_string());
            finish_job(hwnd, JobResult::Privacy { result });
        });
    }

    fn finish_privacy(&mut self, result: Result<CleanOutcome, String>) {
        match result {
            Err(err) => {
                self.priv_note = "The clean could not finish.".to_string();
                self.message(&format!("Nothing was changed.\n\n{err}"), MB_ICONWARNING);
            }
            Ok(outcome) => {
                self.refresh_backups();
                let mut lines = vec![format!(
                    "Removed {} files ({}) and {} registry values.",
                    outcome.files(),
                    format_bytes(outcome.bytes()),
                    outcome.values()
                )];
                if outcome.canceled {
                    lines.push("Canceled: categories after the stop were left alone.".to_string());
                }
                for item in outcome.items.iter().take(8) {
                    lines.push(self.priv_outcome_line(item));
                }
                if outcome.items.len() > 8 {
                    lines.push(format!("...and {} more", outcome.items.len() - 8));
                }
                for error in outcome.errors.iter().take(5) {
                    lines.push(format!("Failed: {error}"));
                }
                if !outcome.backup_file.as_os_str().is_empty() {
                    lines.push(format!("Backup: {}", outcome.backup_file.display()));
                }
                self.priv_note = if outcome.canceled {
                    format!(
                        "Canceled: removed {} files ({}) and {} values so far.",
                        outcome.files(),
                        format_bytes(outcome.bytes()),
                        outcome.values()
                    )
                } else {
                    format!(
                        "Removed {} files ({}) and {} registry values.",
                        outcome.files(),
                        format_bytes(outcome.bytes()),
                        outcome.values()
                    )
                };
                let icon =
                    if outcome.errors.is_empty() { MB_ICONINFORMATION } else { MB_ICONWARNING };
                self.priv_outcome = Some(outcome);
                self.message(&lines.join("\n"), icon);
                let report = preview(
                    &WindowsRegistry,
                    &HostFs,
                    &WindowsSystemTargets,
                    &WindowsProcessList,
                    &self.priv_items,
                );
                self.priv_preview = Some(report);
                self.fill_privacy();
            }
        }
    }

    fn priv_outcome_line(&self, item: &ItemOutcome) -> String {
        let name = self
            .priv_items
            .iter()
            .find(|have| have.id == item.id)
            .map(|have| have.name.clone())
            .unwrap_or_else(|| item.id.clone());
        if item.skipped_running {
            return format!("{name}: waiting, close the program first.");
        }
        if item.gated_out {
            return format!("{name}: not installed.");
        }
        if !item.note.is_empty() {
            return format!("{name}: {}", item.note);
        }
        let mut parts = Vec::new();
        if item.files > 0 {
            parts.push(format!("{} files ({})", item.files, format_bytes(item.bytes)));
        }
        if item.values > 0 {
            parts.push(count(item.values, "value", "values"));
        }
        if item.other > 0 {
            parts.push(count(item.other, "item", "items"));
        }
        if parts.is_empty() {
            parts.push("already empty".to_string());
        }
        let mut line = format!("{name}: {}", parts.join(", "));
        let skipped = item.restricted.len() + item.restricted_extra;
        if skipped > 0 {
            line.push_str(&format!(" ({skipped} skipped)"));
        }
        line
    }

    fn show_priv_details(&mut self, row: usize) {
        let Some(item) = self.priv_items.get(row) else { return };
        let mut lines = vec![item.detail.clone()];
        if let Some((holds, _)) = self.priv_preview_row(&item.id) {
            lines.push(format!("Holds: {holds}"));
        }
        if let Some(report) = &self.priv_preview
            && let Some(preview) = report.items.iter().find(|preview| preview.id == item.id)
        {
            for note in preview.restricted.iter().take(20) {
                lines.push(note.clone());
            }
            if preview.restricted.len() + preview.restricted_extra > 20 {
                lines.push(format!(
                    "...and {} more",
                    preview.restricted.len() + preview.restricted_extra - 20
                ));
            }
        }
        if let Some(outcome) = &self.priv_outcome
            && let Some(done) = outcome.items.iter().find(|done| done.id == item.id)
        {
            lines.push(self.priv_outcome_line(done));
        }
        self.message(&lines.join("\n"), MB_ICONINFORMATION);
    }

    fn size_priv_columns(&self, width: i32) {
        let category = self.s(250);
        let holds = self.s(210);
        let detail = (width - category - holds - self.s(26)).max(self.s(120));
        unsafe {
            SendMessageW(self.priv_list, LVM_SETCOLUMNWIDTH, 0, category as isize);
            SendMessageW(self.priv_list, LVM_SETCOLUMNWIDTH, 1, holds as isize);
            SendMessageW(self.priv_list, LVM_SETCOLUMNWIDTH, 2, detail as isize);
        }
    }

    fn fill_services(&mut self) {
        self.svc_filling = true;
        unsafe {
            SendMessageW(self.svc_tune_list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.svc_tune_list, LVM_DELETEALLITEMS, 0, 0);
            for (row, change) in self.svc_proposals.iter().enumerate() {
                insert_row(
                    self.svc_tune_list,
                    row,
                    &[
                        &change.display_name,
                        change.from.label(),
                        change.to.label(),
                        &change.why,
                    ],
                );
                let image = if self.svc_checked.get(row).copied().unwrap_or(false) {
                    2
                } else {
                    1
                };
                set_state_image(self.svc_tune_list, row, image);
            }
            SendMessageW(self.svc_tune_list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.svc_tune_list, std::ptr::null(), 1);
            SendMessageW(self.svc_list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.svc_list, LVM_DELETEALLITEMS, 0, 0);
            for (row, info) in self.services.iter().enumerate() {
                insert_row(
                    self.svc_list,
                    row,
                    &[
                        &info.display_name,
                        info.state.label(),
                        info.start.label(),
                        &info.name,
                    ],
                );
            }
            SendMessageW(self.svc_list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.svc_list, std::ptr::null(), 1);
        }
        self.svc_filling = false;
        self.update_svc_apply_label();
    }

    fn show_svc_details(&mut self, row: usize) {
        let Some(info) = self.services.get(row) else {
            return;
        };
        let startup = if info.start == StartType::AutomaticDelayed {
            "Automatic (delayed start)".to_string()
        } else {
            info.start.label().to_string()
        };
        self.message(
            &format!(
                "{}\nName: {}\nStatus: {}\nStartup: {}\n\nRight-click for Start, Stop, and startup-type changes. Startup changes save a backup first and can be undone on the Restore page.",
                info.display_name, info.name, info.state.label(), startup
            ),
            MB_ICONINFORMATION,
        );
    }

    fn show_svc_proposal(&mut self, row: usize) {
        let Some(change) = self.svc_proposals.get(row) else {
            return;
        };
        self.message(
            &format!(
                "{} ({})\n{} -> {}\n\n{}\n\nTick it and use Apply Ticked to change it. The old start type is backed up first.",
                change.display_name, change.name, change.from.label(), change.to.label(), change.why
            ),
            MB_ICONINFORMATION,
        );
    }

    fn services_menu(&mut self, lparam: LPARAM) {
        let rows = selected_rows(self.svc_list);
        if rows.is_empty() || self.busy() {
            return;
        }
        let mut at = POINT {
            x: (lparam & 0xffff) as i16 as i32,
            y: ((lparam >> 16) & 0xffff) as i16 as i32,
        };
        if lparam == -1 {
            let mut rect = RECT::default();
            unsafe {
                SendMessageW(self.svc_list, LVM_GETITEMRECT, rows[0], &mut rect as *mut _ as isize);
                at = POINT {
                    x: rect.left + self.s(24),
                    y: rect.bottom,
                };
                ClientToScreen(self.svc_list, &mut at);
            }
        }
        let first = &self.services[rows[0]];
        let running = first.state == ServiceState::Running;
        let stopped = first.state == ServiceState::Stopped;
        let can_write = self.elevated;
        let gray = |on: bool| if on { MF_GRAYED } else { MF_STRING };
        let choice = unsafe {
            let menu = CreatePopupMenu();
            AppendMenuW(
                menu,
                gray(!can_write || running),
                MENU_SVC_START,
                wide("Start").as_ptr(),
            );
            AppendMenuW(
                menu,
                gray(!can_write || stopped),
                MENU_SVC_STOP,
                wide("Stop").as_ptr(),
            );
            AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
            AppendMenuW(
                menu,
                gray(!can_write),
                MENU_SVC_AUTO,
                wide("Set Automatic").as_ptr(),
            );
            AppendMenuW(
                menu,
                gray(!can_write),
                MENU_SVC_AUTO_DELAYED,
                wide("Set Automatic (Delayed)").as_ptr(),
            );
            AppendMenuW(
                menu,
                gray(!can_write),
                MENU_SVC_MANUAL,
                wide("Set Manual").as_ptr(),
            );
            AppendMenuW(
                menu,
                gray(!can_write),
                MENU_SVC_DISABLED,
                wide("Set Disabled").as_ptr(),
            );
            if lparam != -1 {
                GetCursorPos(&mut at);
            }
            let choice = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                at.x,
                at.y,
                0,
                self.hwnd,
                std::ptr::null(),
            );
            DestroyMenu(menu);
            choice as usize
        };
        match choice {
            MENU_SVC_START => self.power_rows(&rows, true),
            MENU_SVC_STOP => self.power_rows(&rows, false),
            MENU_SVC_AUTO => self.set_rows(&rows, StartType::Automatic),
            MENU_SVC_AUTO_DELAYED => self.set_rows(&rows, StartType::AutomaticDelayed),
            MENU_SVC_MANUAL => self.set_rows(&rows, StartType::Manual),
            MENU_SVC_DISABLED => self.set_rows(&rows, StartType::Disabled),
            _ => {}
        }
    }

    // ---- repair --------------------------------------------------------

    fn start_repair(&mut self) {
        if self.busy() {
            return;
        }
        let selected = self.ticked();
        if selected.is_empty() {
            self.message("Tick the entries you want to repair first.", MB_ICONINFORMATION);
            return;
        }
        let backup_file = next_backup_file();
        let mut question = format!(
            "Repair {} {}?\n\nRegistry Master first checks that each one is still broken, then saves a backup to\n{}\nbefore removing anything. You can undo the repair on the Restore page.",
            selected.len(),
            if selected.len() == 1 { "entry" } else { "entries" },
            backup_file.display()
        );
        let permanent = selected.iter().filter(|f| f.permanent()).count();
        if permanent > 0 {
            question.push_str(&format!(
                "\n\n{permanent} temporary {} will be deleted for good. Files are not backed up.",
                if permanent == 1 { "file" } else { "files" }
            ));
        }
        let admin = selected.iter().filter(|f| f.needs_admin()).count();
        if !self.elevated && admin > 0 {
            question.push_str(&format!(
                "\n\n{admin} of these are machine-wide. Without administrator rights Windows will refuse them and they will stay as they are."
            ));
        }
        if !self.confirm(&question) {
            return;
        }
        self.job = Job::Repairing;
        self.page = Page::Scan;
        set_progress(0, 1, "Checking the ticked entries again...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let mut scope: Vec<ScannerId> = Vec::new();
            for finding in &selected {
                if !scope.contains(&finding.scanner) {
                    scope.push(finding.scanner);
                }
            }
            let opts = ScanOptions {
                only: scope,
                include_deep: true,
                wow64: true,
            };
            // The re-check is the first third of the bar, the repair the rest.
            let fresh = scan_with_progress(
                &Engine::builtin(),
                &WindowsRegistry,
                &HostFs,
                &opts,
                &mut |step, total, name| {
                    if !name.is_empty() {
                        set_progress(step, total * 3, &format!("Checking again: {name}"));
                        post(hwnd, WM_JOB_PROGRESS);
                    }
                    true
                },
            );
            let confirmed = still_reported(&selected, &fresh.findings);
            let fixed_meanwhile: Vec<Finding> = selected
                .iter()
                .filter(|finding| !confirmed.contains(finding))
                .cloned()
                .collect();
            let result = if confirmed.is_empty() {
                Ok(RepairOutcome {
                    backup_file: PathBuf::new(),
                    ..RepairOutcome::default()
                })
            } else {
                set_progress(1, 3, "Saving the backup...");
                post(hwnd, WM_JOB_PROGRESS);
                let total = confirmed.len();
                repair_with_progress(
                    &mut WindowsRegistry,
                    &mut HostFs,
                    &confirmed,
                    &backup_file,
                    &mut |done, _| {
                        set_progress(total + done * 2, total * 3, &format!("Removing {done} of {total}..."));
                        post(hwnd, WM_JOB_PROGRESS);
                    },
                )
                .map_err(|err| err.to_string())
            };
            finish_job(
                hwnd,
                JobResult::Repair {
                    result,
                    fixed_meanwhile,
                },
            );
        });
    }

    fn finish_repair(&mut self, result: Result<RepairOutcome, String>, fixed_meanwhile: Vec<Finding>) {
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(err) => {
                self.scan_note = "Repair stopped before changing anything.".into();
                self.message(
                    &format!("Nothing was changed. The backup could not be written:\n\n{err}"),
                    MB_ICONWARNING,
                );
                return;
            }
        };
        let resolved: Vec<&Finding> = outcome.resolved.iter().chain(&fixed_meanwhile).collect();
        let rows: Vec<usize> = self
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| resolved.contains(finding))
            .map(|(row, _)| row)
            .collect();
        self.drop_rows(&rows);
        let already = outcome.already_gone + fixed_meanwhile.len();
        let mut lines = vec![format!("Removed: {}", outcome.applied)];
        if already > 0 {
            lines.push(format!("Already fixed before repair reached them: {already}"));
        }
        let left = outcome.refused + outcome.not_backed_up;
        if left > 0 {
            lines.push(format!(
                "Left alone because they could not be backed up or are protected: {left}"
            ));
        }
        if !outcome.errors.is_empty() {
            let mut line = format!("Could not remove: {}", outcome.errors.len());
            if outcome.denied > 0 && !self.elevated {
                line.push_str(&format!(
                    " ({} need Run as administrator)",
                    outcome.denied
                ));
            }
            lines.push(line);
        }
        let mut text = format!("Repair finished.\n\n{}", lines.join("\n"));
        if outcome.applied > 0 {
            text.push_str(&format!(
                "\n\nBackup: {}\nTo undo, open Restore and pick this backup.",
                outcome.backup_file.display()
            ));
            self.settings.last_repair = format!(
                "{}: removed {}. Backup {}",
                local_now(),
                outcome.applied,
                outcome
                    .backup_file
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_default()
            );
            self.save_settings();
        } else if outcome.backup_file.as_os_str().is_empty() {
            text = "Nothing needed repair: every ticked entry was already fixed. No changes were made.".into();
        }
        if !outcome.errors.is_empty() {
            text.push_str("\n\nFirst problems:\n");
            for err in outcome.errors.iter().take(5) {
                text.push_str(&format!("{err}\n"));
            }
        }
        self.scan_note = format!(
            "Repair removed {} entries. {} problems remain.",
            outcome.applied,
            self.findings.len()
        );
        self.refresh_backups();
        let icon = if outcome.errors.is_empty() {
            MB_ICONINFORMATION
        } else {
            MB_ICONWARNING
        };
        self.message(&text, icon);
    }

    // ---- restore -------------------------------------------------------

    fn refresh_backups(&mut self) {
        self.backups = list_backups(&backups_dir());
        self.fill_backups();
    }

    fn fill_backups(&self) {
        unsafe {
            SendMessageW(self.backup_list, LVM_DELETEALLITEMS, 0, 0);
        }
        for (row, backup) in self.backups.iter().enumerate() {
            let saved = backup.modified.map(local_time_text).unwrap_or_default();
            let name = backup
                .path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            insert_row(self.backup_list, row, &[&saved, &contents(&backup.summary), &name]);
        }
    }

    fn start_restore(&mut self, row: usize) {
        if self.busy() {
            return;
        }
        let Some(backup) = self.backups.get(row).cloned() else {
            return;
        };
        if backup.summary.machine_wide && !self.elevated {
            let ask = "This backup includes machine-wide entries, so putting it back needs administrator rights.\n\nRestart Registry Master as administrator now?";
            if self.confirm(ask) {
                self.elevate();
            }
            return;
        }
        let saved = backup.modified.map(local_time_text).unwrap_or_default();
        let question = format!(
            "Restore the backup saved {saved}?\n\nThis puts back {}. Entries that exist now are overwritten with the saved copy.",
            contents(&backup.summary)
        );
        if !self.confirm(&question) {
            return;
        }
        self.job = Job::Restoring;
        set_progress(0, 2, "Restoring the backup...");
        self.sync_controls();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        let file = backup.path.clone();
        std::thread::spawn(move || {
            let result = read_backup(&file)
                .map_err(|err| err.to_string())
                .and_then(|text| {
                    let summary = BackupSummary::parse(&text);
                    import_reg_file(&file)?;
                    let (files, errors) = restore_files(&summary);
                    Ok((summary, files, errors))
                });
            finish_job(hwnd, JobResult::Restore { file, result });
        });
    }

    fn finish_restore(&mut self, file: PathBuf, result: Result<(BackupSummary, usize, Vec<String>), String>) {
        match result {
            Ok((summary, files, errors)) => {
                let mut text = format!(
                    "Restored {} from\n{}",
                    contents(&summary),
                    file.display()
                );
                if files > 0 {
                    text.push_str(&format!("\n\n{files} shortcuts were put back."));
                }
                if !errors.is_empty() {
                    text.push_str("\n\nSome files could not be put back:\n");
                    text.push_str(&errors.iter().take(5).cloned().collect::<Vec<_>>().join("\n"));
                }
                if self.scanned {
                    self.scan_note = "A backup was restored since this scan. Scan again to refresh the results.".into();
                }
                let icon = if errors.is_empty() { MB_ICONINFORMATION } else { MB_ICONWARNING };
                self.message(&text, icon);
            }
            Err(err) => self.message(&format!("The backup could not be restored:\n\n{err}"), MB_ICONWARNING),
        }
    }

    // ---- settings ------------------------------------------------------

    fn save_settings(&self) {
        let _ = self.settings.save(&settings_file());
    }

    fn fill_ignored(&self) {
        unsafe { SendMessageW(self.ignored_list, LVM_DELETEALLITEMS, 0, 0) };
        for (row, entry) in self.exclusions.entries().iter().enumerate() {
            insert_row(self.ignored_list, row, &[&entry.label()]);
        }
    }

    fn unignore(&mut self) {
        let rows = selected_rows(self.ignored_list);
        if rows.is_empty() {
            self.message("Click an ignored entry to highlight it first.", MB_ICONINFORMATION);
            return;
        }
        for row in rows.iter().rev() {
            self.exclusions.remove(*row);
        }
        if let Err(err) = self.exclusions.save(&exclusions_file()) {
            self.message(&format!("Could not save the ignore list: {err}"), MB_ICONWARNING);
        }
        self.fill_ignored();
        self.invalidate();
        self.message(
            "Those entries will show up again the next time you scan.",
            MB_ICONINFORMATION,
        );
    }

    fn elevate(&mut self) {
        if self.busy() || self.elevated {
            return;
        }
        let exe = wide(&exe_path().display().to_string());
        let result = unsafe {
            ShellExecuteW(
                self.hwnd,
                wide("runas").as_ptr(),
                exe.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // Above 32 means the elevated copy started. Otherwise the prompt was declined.
        if result as isize > 32 {
            unsafe { DestroyWindow(self.hwnd) };
        }
    }

    // ---- jobs ----------------------------------------------------------

    fn show_progress(&self) {
        // The text line is painted by draw_scan.
        let (done, total) = PROGRESS.lock().map(|p| (p.done, p.total)).unwrap_or_default();
        let pos = if total == 0 { 0 } else { (done * 1000 / total).min(1000) };
        unsafe { SendMessageW(self.progress, PBM_SETPOS, pos, 0) };
        let mut rect = self.client();
        rect.top = self.s(HEADER_H);
        rect.left = self.s(CONTENT_X);
        unsafe { InvalidateRect(self.hwnd, &rect, 0) };
    }

    fn finish(&mut self, result: JobResult) {
        self.job = Job::Idle;
        match result {
            JobResult::Scan { report, scope, seconds } => self.finish_scan(report, scope, seconds),
            JobResult::Repair { result, fixed_meanwhile } => {
                self.sync_controls();
                self.finish_repair(result, fixed_meanwhile);
            }
            JobResult::Restore { file, result } => {
                self.sync_controls();
                self.finish_restore(file, result);
                self.refresh_backups();
            }
            JobResult::Services {
                op,
                result,
                services,
            } => {
                self.sync_controls();
                self.finish_services(op, result, services);
            }
            JobResult::Privacy { result } => {
                self.sync_controls();
                self.finish_privacy(result);
            }
        }
        self.sync_controls();
        self.invalidate();
    }

    fn confirm(&self, text: &str) -> bool {
        let text = wide(text);
        let title = wide("Registry Master");
        unsafe {
            MessageBoxW(
                self.hwnd,
                text.as_ptr(),
                title.as_ptr(),
                MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
            ) == IDYES
        }
    }

    fn message(&self, text: &str, icon: u32) {
        let text = wide(text);
        let title = wide("Registry Master");
        unsafe { MessageBoxW(self.hwnd, text.as_ptr(), title.as_ptr(), MB_OK | icon) };
    }

    // ---- layout --------------------------------------------------------

    fn sync_controls(&mut self) {
        let rect = self.client();
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        let width = (right - left).max(self.s(200));
        let bottom = rect.bottom - self.s(FOOTER_H);
        let button_y = bottom - self.s(48);
        let button_h = self.s(32);
        let list_top = self.s(LIST_Y);
        let list_h = (button_y - self.s(14) - list_top).max(self.s(80));

        let mut visible: Vec<HWND> = Vec::new();
        match self.page {
            Page::Scan => {
                if matches!(self.job, Job::Scanning | Job::Repairing) {
                    visible.push(self.progress);
                    place(self.progress, left, self.s(BODY_Y + 16), width, self.s(22));
                    if self.job == Job::Scanning {
                        visible.push(self.btn_cancel);
                        place(self.btn_cancel, left, self.s(BODY_Y + 88), self.s(110), button_h);
                    }
                } else if !self.scanned {
                    visible.push(self.btn_scan);
                    set_text(self.btn_scan, "Start Scan");
                    place(self.btn_scan, left, self.s(BODY_Y + 128), self.s(150), self.s(38));
                } else {
                    visible.extend([
                        self.list,
                        self.btn_scan,
                        self.btn_all,
                        self.btn_none,
                        self.btn_ignore,
                        self.btn_repair,
                    ]);
                    set_text(self.btn_scan, "Scan Again");
                    place(self.list, left, list_top, width, list_h);
                    let mut x = left;
                    for (control, w) in [
                        (self.btn_scan, 110),
                        (self.btn_all, 96),
                        (self.btn_none, 104),
                        (self.btn_ignore, 156),
                    ] {
                        place(control, x, button_y, self.s(w), button_h);
                        x += self.s(w + 8);
                    }
                    let repair_w = self.s(200);
                    place(self.btn_repair, right - repair_w, button_y, repair_w, button_h);
                    self.size_finding_columns(width);
                }
            }
            Page::Restore => {
                visible.extend([self.backup_list, self.btn_restore, self.btn_open_backups]);
                place(self.backup_list, left, self.s(BODY_Y), width, list_h + list_top - self.s(BODY_Y));
                place(self.btn_restore, left, button_y, self.s(200), button_h);
                place(self.btn_open_backups, left + self.s(208), button_y, self.s(170), button_h);
                let file_w = width - self.s(170 + 300) - self.s(24);
                unsafe {
                    SendMessageW(self.backup_list, LVM_SETCOLUMNWIDTH, 0, self.s(170) as isize);
                    SendMessageW(self.backup_list, LVM_SETCOLUMNWIDTH, 1, self.s(300) as isize);
                    SendMessageW(self.backup_list, LVM_SETCOLUMNWIDTH, 2, file_w.max(self.s(120)) as isize);
                }
            }
            Page::Settings => {
                let column_w = width / 2;
                for (index, (_, check)) in self.scanner_boxes.iter().enumerate() {
                    let column = (index / 6) as i32;
                    let row = (index % 6) as i32;
                    visible.push(*check);
                    place(
                        *check,
                        left + column * column_w,
                        self.s(BODY_Y + 34) + row * self.s(30),
                        column_w - self.s(12),
                        self.s(26),
                    );
                }
                let ignored_top = self.s(SETTINGS_IGNORED_Y + 62);
                visible.extend([self.ignored_list, self.btn_unignore]);
                place(
                    self.ignored_list,
                    left,
                    ignored_top,
                    width,
                    (button_y - self.s(14) - ignored_top).max(self.s(60)),
                );
                place(self.btn_unignore, left, button_y, self.s(220), button_h);
                unsafe {
                    SendMessageW(self.ignored_list, LVM_SETCOLUMNWIDTH, 0, (width - self.s(24)) as isize);
                }
            }
            Page::Services => {
                if matches!(self.job, Job::Services) {
                    visible.push(self.progress);
                    place(self.progress, left, self.s(BODY_Y + 16), width, self.s(22));
                } else if self.svc_view == SvcView::Tuneup {
                    visible.extend([
                        self.svc_tune_list,
                        self.btn_svc_all,
                        self.btn_svc_none,
                        self.btn_svc_refresh,
                        self.btn_svc_apply,
                    ]);
                    let top = self.s(BODY_Y + 44);
                    place(
                        self.svc_tune_list,
                        left,
                        top,
                        width,
                        (button_y - self.s(14) - top).max(self.s(80)),
                    );
                    let mut x = left;
                    for (control, w) in [
                        (self.btn_svc_all, 96),
                        (self.btn_svc_none, 104),
                        (self.btn_svc_refresh, 110),
                    ] {
                        place(control, x, button_y, self.s(w), button_h);
                        x += self.s(w + 8);
                    }
                    let apply_w = self.s(220);
                    place(self.btn_svc_apply, right - apply_w, button_y, apply_w, button_h);
                    self.size_svc_columns(width);
                } else {
                    visible.extend([
                        self.svc_list,
                        self.btn_svc_refresh,
                        self.btn_svc_start,
                        self.btn_svc_stop,
                    ]);
                    let top = self.s(BODY_Y + 44);
                    place(
                        self.svc_list,
                        left,
                        top,
                        width,
                        (button_y - self.s(14) - top).max(self.s(80)),
                    );
                    let mut x = left;
                    for (control, w) in [
                        (self.btn_svc_refresh, 110),
                        (self.btn_svc_start, 110),
                        (self.btn_svc_stop, 110),
                    ] {
                        place(control, x, button_y, self.s(w), button_h);
                        x += self.s(w + 8);
                    }
                    self.size_svc_columns(width);
                }
            }
            Page::Privacy => {
                if matches!(self.job, Job::Cleaning) {
                    visible.push(self.progress);
                    place(self.progress, left, self.s(BODY_Y + 16), width, self.s(22));
                    visible.push(self.btn_cancel);
                    place(self.btn_cancel, left, self.s(BODY_Y + 88), self.s(110), button_h);
                } else {
                    visible.extend([
                        self.priv_list,
                        self.btn_priv_preview,
                        self.btn_priv_all,
                        self.btn_priv_none,
                        self.btn_priv_clean,
                    ]);
                    place(self.priv_list, left, list_top, width, list_h);
                    let mut x = left;
                    for (control, w) in [
                        (self.btn_priv_preview, 110),
                        (self.btn_priv_all, 96),
                        (self.btn_priv_none, 104),
                    ] {
                        place(control, x, button_y, self.s(w), button_h);
                        x += self.s(w + 8);
                    }
                    let clean_w = self.s(220);
                    place(self.btn_priv_clean, right - clean_w, button_y, clean_w, button_h);
                    self.size_priv_columns(width);
                }
            }
            Page::Status | Page::About | Page::Monitor | Page::Tools => {}
        }
        for control in self.all_controls() {
            let show = visible.contains(&control);
            unsafe { ShowWindow(control, if show { SW_SHOW } else { SW_HIDE }) };
        }
        let idle = !self.busy();
        for control in [
            self.btn_scan,
            self.btn_all,
            self.btn_none,
            self.btn_ignore,
            self.btn_restore,
            self.btn_unignore,
            self.btn_svc_refresh,
            self.btn_svc_all,
            self.btn_svc_none,
            self.btn_priv_preview,
            self.btn_priv_all,
            self.btn_priv_none,
        ] {
            unsafe { EnableWindow(control, idle as i32) };
        }
        let can_write = idle && self.elevated;
        for control in [self.btn_svc_start, self.btn_svc_stop] {
            unsafe { EnableWindow(control, can_write as i32) };
        }
        unsafe { EnableWindow(self.list, idle as i32) };
        unsafe { EnableWindow(self.svc_list, idle as i32) };
        unsafe { EnableWindow(self.svc_tune_list, idle as i32) };
        unsafe { EnableWindow(self.priv_list, idle as i32) };
        self.update_repair_label();
        self.update_svc_apply_label();
        self.update_priv_clean_label();
    }

    fn size_svc_columns(&self, width: i32) {
        let now = self.s(150);
        let change = self.s(130);
        let why = (width - self.s(240) - now - change - self.s(26)).max(self.s(120));
        unsafe {
            SendMessageW(self.svc_tune_list, LVM_SETCOLUMNWIDTH, 0, self.s(240) as isize);
            SendMessageW(self.svc_tune_list, LVM_SETCOLUMNWIDTH, 1, now as isize);
            SendMessageW(self.svc_tune_list, LVM_SETCOLUMNWIDTH, 2, change as isize);
            SendMessageW(self.svc_tune_list, LVM_SETCOLUMNWIDTH, 3, why as isize);
        }
        let status = self.s(110);
        let startup = self.s(150);
        let name = (width - self.s(300) - status - startup - self.s(26)).max(self.s(120));
        unsafe {
            SendMessageW(self.svc_list, LVM_SETCOLUMNWIDTH, 0, self.s(300) as isize);
            SendMessageW(self.svc_list, LVM_SETCOLUMNWIDTH, 1, status as isize);
            SendMessageW(self.svc_list, LVM_SETCOLUMNWIDTH, 2, startup as isize);
            SendMessageW(self.svc_list, LVM_SETCOLUMNWIDTH, 3, name as isize);
        }
    }

    fn size_finding_columns(&self, width: i32) {
        let category = self.s(124);
        let fix = self.s(156);
        let rest = (width - category - fix - self.s(26)).max(self.s(200));
        let problem = rest * 11 / 20;
        unsafe {
            SendMessageW(self.list, LVM_SETCOLUMNWIDTH, 0, category as isize);
            SendMessageW(self.list, LVM_SETCOLUMNWIDTH, 1, problem as isize);
            SendMessageW(self.list, LVM_SETCOLUMNWIDTH, 2, (rest - problem) as isize);
            SendMessageW(self.list, LVM_SETCOLUMNWIDTH, 3, fix as isize);
        }
    }

    // ---- painting ------------------------------------------------------

    fn spot_at(&self, x: i32, y: i32) -> Option<usize> {
        self.hotspots.iter().position(|spot| hit(spot.rect, x, y))
    }

    fn spot_enabled(&self, index: usize) -> bool {
        self.hotspots
            .get(index)
            .is_some_and(|spot| !(spot.action.starts_job() && self.busy()))
    }

    fn set_hover(&mut self, hover: Option<usize>) {
        if self.hover != hover {
            self.hover = hover;
            self.invalidate();
        }
    }

    fn paint(&mut self) {
        unsafe {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(self.hwnd, &mut ps);
            let rect = self.client();
            let mem = CreateCompatibleDC(hdc);
            let bitmap = CreateCompatibleBitmap(hdc, rect.right.max(1), rect.bottom.max(1));
            let old = SelectObject(mem, bitmap);
            SetBkMode(mem, TRANSPARENT as i32);
            // Hover tests during this paint use the previous frame's spots.
            let previous_hover = self.hover.and_then(|i| self.hotspots.get(i)).map(|s| s.rect);
            self.hotspots.clear();
            fill(mem, rect, BG);
            self.draw_chrome(mem, rect, previous_hover);
            match self.page {
                Page::Status => self.draw_status(mem, rect, previous_hover),
                Page::Scan => self.draw_scan(mem, rect),
                Page::Restore => self.draw_restore(mem, rect),
                Page::Settings => self.draw_settings(mem, rect),
                Page::Services => self.draw_services(mem, rect, previous_hover),
                Page::Privacy => self.draw_privacy(mem, rect),
                Page::Monitor => self.draw_monitor(mem, rect, previous_hover),
                Page::Tools => self.draw_tools(mem, rect, previous_hover),
                Page::About => self.draw_about(mem, rect),
            }
            if let Some(prev) = previous_hover {
                self.hover = self.hotspots.iter().position(|spot| same(spot.rect, prev));
            }
            BitBlt(hdc, 0, 0, rect.right, rect.bottom, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old);
            DeleteObject(bitmap);
            DeleteDC(mem);
            EndPaint(self.hwnd, &ps);
        }
    }

    fn spot(&mut self, rect: RECT, action: Action) {
        self.hotspots.push(HotSpot { rect, action });
    }

    unsafe fn draw_chrome(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        let header = self.s(HEADER_H);
        // A lighter top half over a deeper bottom half gives the header its gloss.
        gradient(hdc, RECT { left: 0, top: 0, right: rect.right, bottom: header / 2 }, (44, 110, 196), (96, 166, 230), false);
        gradient(hdc, RECT { left: 0, top: header / 2, right: rect.right, bottom: header }, (16, 72, 160), (52, 128, 206), false);
        fill(hdc, RECT { left: 0, top: header - 1, right: rect.right, bottom: header }, rgb(12, 52, 120));
        text(
            hdc,
            self.fonts.title,
            rgb(255, 255, 255),
            RECT { left: self.s(24), top: 0, right: rect.right / 2, bottom: header },
            "Registry Master",
            DT_SINGLELINE | DT_VCENTER,
        );
        let help_size = measure(hdc, self.fonts.body_bold, "Help");
        let help = RECT {
            left: rect.right - self.s(20) - help_size.0,
            top: header / 2 - self.s(13),
            right: rect.right - self.s(20),
            bottom: header / 2 + self.s(13),
        };
        let help_lit = lit(hover, help);
        text(
            hdc,
            self.fonts.body_bold,
            if help_lit { rgb(255, 255, 255) } else { rgb(214, 232, 250) },
            help,
            "Help",
            DT_SINGLELINE | DT_VCENTER | DT_RIGHT,
        );
        if help_lit {
            fill(hdc, RECT { left: help.left, top: help.bottom - 1, right: help.right, bottom: help.bottom }, rgb(255, 255, 255));
        }
        self.spot(help, Action::Page(Page::About));
        let badge = RECT {
            left: rect.right - self.s(260),
            top: 0,
            right: help.left - self.s(16),
            bottom: header,
        };
        if self.elevated {
            text(hdc, self.fonts.small, rgb(220, 236, 255), badge, "Running as administrator", DT_SINGLELINE | DT_VCENTER | DT_RIGHT);
        } else {
            let label = "Run as administrator";
            let size = measure(hdc, self.fonts.body_bold, label);
            let link = RECT {
                left: badge.right - size.0 - self.s(24),
                top: header / 2 - self.s(17),
                right: badge.right,
                bottom: header / 2 + self.s(17),
            };
            let lit = lit(hover, link);
            round_box(
                hdc,
                link,
                self.s(16),
                if lit { rgb(255, 255, 255) } else { rgb(232, 242, 255) },
                rgb(160, 196, 236),
                1,
            );
            text(hdc, self.fonts.body_bold, BLUE_INK, link, label, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
            self.spot(link, Action::Elevate);
        }

        let side = RECT { left: 0, top: header, right: self.s(SIDEBAR_W), bottom: rect.bottom - self.s(FOOTER_H) };
        fill(hdc, side, SIDEBAR_BG);
        fill(hdc, RECT { left: side.right, top: header, right: side.right + 1, bottom: side.bottom }, rgb(206, 212, 222));
        gradient(
            hdc,
            RECT { left: 0, top: rect.bottom - self.s(FOOTER_H), right: rect.right, bottom: rect.bottom },
            (236, 214, 70),
            (90, 176, 72),
            false,
        );
        let mut y = header + self.s(20);
        for (label, page) in NAV {
            let pill = RECT {
                left: self.s(16),
                top: y,
                right: self.s(SIDEBAR_W - 16),
                bottom: y + self.s(38),
            };
            let selected = self.page == *page;
            let lit = lit(hover, pill);
            let (fill_color, border, width) = if selected {
                (rgb(222, 236, 253), rgb(40, 110, 190), 2)
            } else if lit {
                (rgb(246, 250, 255), rgb(120, 160, 210), 1)
            } else {
                (rgb(255, 255, 255), rgb(184, 190, 200), 1)
            };
            round_box(hdc, pill, self.s(18), fill_color, border, width);
            let font = if selected { self.fonts.body_bold } else { self.fonts.body };
            let label = label.replace("&&", "&");
            text(hdc, font, if selected { BLUE_INK } else { INK }, pill, &label, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
            self.spot(pill, Action::Page(*page));
            y += self.s(46);
        }
        if self.busy() {
            let note = match self.job {
                Job::Scanning => "Scanning...",
                Job::Repairing => "Repairing...",
                Job::Restoring => "Restoring...",
                Job::Services => "Working...",
                Job::Cleaning => "Cleaning...",
                Job::Idle => "",
            };
            text(
                hdc,
                self.fonts.small,
                MUTED,
                RECT { left: self.s(16), top: y + self.s(8), right: self.s(SIDEBAR_W - 16), bottom: y + self.s(30) },
                note,
                DT_SINGLELINE | DT_CENTER,
            );
        }
    }

    unsafe fn heading(&self, hdc: HDC, rect: RECT, title: &str, accent: Option<&str>) {
        let left = self.s(CONTENT_X);
        let top = self.s(TITLE_Y);
        let size = measure(hdc, self.fonts.title, title);
        text(hdc, self.fonts.title, INK, RECT { left, top, right: rect.right, bottom: top + self.s(40) }, title, DT_SINGLELINE);
        if let Some(accent) = accent {
            let x = left + size.0 + self.s(8);
            text(hdc, self.fonts.title, ACCENT, RECT { left: x, top, right: rect.right, bottom: top + self.s(40) }, accent, DT_SINGLELINE);
        }
    }

    unsafe fn subtitle(&self, hdc: HDC, rect: RECT, line: &str) {
        let left = self.s(CONTENT_X);
        let top = self.s(SUBTITLE_Y);
        text(
            hdc,
            self.fonts.body,
            MUTED,
            RECT { left, top, right: rect.right - self.s(24), bottom: top + self.s(26) },
            line,
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    /// Status & Summary rows, shared by the Status and Monitor pages.
    fn summary_rows(&self) -> Vec<(&'static str, String)> {
        let last_scan = if self.settings.last_scan.is_empty() {
            "Never".to_string()
        } else {
            self.settings.last_scan.clone()
        };
        let problems = match self.settings.last_problems {
            Some(0) => "No problems found".to_string(),
            Some(count) => format!("{count} problem(s) found"),
            None => "No scan yet".to_string(),
        };
        let last_repair = if self.settings.last_repair.is_empty() {
            "None yet".to_string()
        } else {
            self.settings.last_repair.clone()
        };
        let backups = match self.backups.len() {
            0 => "None yet".to_string(),
            1 => "1 backup saved".to_string(),
            count => format!("{count} backups saved"),
        };
        let ignored = match self.exclusions.len() {
            0 => "None".to_string(),
            count => format!("{count} entries"),
        };
        vec![
            ("Last scan", last_scan),
            ("Result", problems),
            ("Last repair", last_repair),
            ("Backups", backups),
            ("Ignored", ignored),
        ]
    }

    unsafe fn draw_status(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        self.heading(hdc, rect, "Select an", Some("Action"));
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(28);
        let cards = [
            (0, "Scan Your Registry", "Find entries left behind by programs that are no longer installed", Action::ScanAll),
            (1, "Optimize Your System", "Quick check of startup programs, uninstall entries, shared DLLs, and COM controls", Action::Optimize),
            (2, "Monitor Your System", "Memory, disk space, and uptime at a glance", Action::Page(Page::Monitor)),
        ];
        let mut y = self.s(HEADER_H + 64);
        let card_h = self.s(84);
        for (icon, title, subtitle, action) in cards {
            let card = RECT { left, top: y, right, bottom: y + card_h };
            let disabled = action.starts_job() && self.busy();
            let lit = !disabled && lit(hover, card);
            round_box(
                hdc,
                card,
                self.s(18),
                if lit { rgb(236, 244, 253) } else { rgb(248, 250, 252) },
                if lit { rgb(60, 130, 210) } else { rgb(186, 196, 210) },
                if lit { 2 } else { 1 },
            );
            let icon_w = self.s(70);
            if let Some(bitmap) = self.icons.get(icon).copied().filter(|b| !b.is_null()) {
                blit(hdc, bitmap, card.left + self.s(14), card.top + (card_h - self.s(64)) / 2, icon_w, self.s(64));
            }
            let text_left = card.left + self.s(104);
            let color = if disabled { MUTED } else { BLUE_INK };
            text(hdc, self.fonts.heading, color, RECT { left: text_left, top: card.top + self.s(14), right: card.right - self.s(16), bottom: card.top + self.s(44) }, title, DT_SINGLELINE);
            text(hdc, self.fonts.body, MUTED, RECT { left: text_left, top: card.top + self.s(46), right: card.right - self.s(16), bottom: card.bottom - self.s(8) }, subtitle, DT_SINGLELINE | DT_END_ELLIPSIS);
            self.spot(card, action);
            y += card_h + self.s(12);
        }

        y += self.s(10);
        text(hdc, self.fonts.title, INK, RECT { left, top: y, right, bottom: y + self.s(40) }, "Status & Summary", DT_SINGLELINE);
        y += self.s(46);
        let label_w = self.s(150);
        for (label, value) in self.summary_rows() {
            text(hdc, self.fonts.body_bold, INK, RECT { left, top: y, right: left + label_w, bottom: y + self.s(24) }, label, DT_SINGLELINE);
            text(hdc, self.fonts.body, INK, RECT { left: left + label_w, top: y, right, bottom: y + self.s(24) }, &value, DT_SINGLELINE | DT_END_ELLIPSIS);
            y += self.s(26);
        }
        y += self.s(6);
        let mut x = left;
        if self.scanned && self.page == Page::Status {
            let label = "View scan results";
            let size = measure(hdc, self.fonts.body, label);
            let link = RECT { left: x, top: y, right: x + size.0, bottom: y + size.1 };
            text(hdc, self.fonts.body, LINK, link, label, DT_SINGLELINE);
            if lit(hover, link) {
                fill(hdc, RECT { left: link.left, top: link.bottom - 1, right: link.right, bottom: link.bottom }, LINK);
            }
            self.spot(link, Action::Page(Page::Scan));
            x = link.right + self.s(24);
        }
        let label = "Click to reset statistics";
        let size = measure(hdc, self.fonts.body, label);
        let link = RECT { left: x, top: y, right: x + size.0, bottom: y + size.1 };
        text(hdc, self.fonts.body, LINK, link, label, DT_SINGLELINE);
        if lit(hover, link) {
            fill(hdc, RECT { left: link.left, top: link.bottom - 1, right: link.right, bottom: link.bottom }, LINK);
        }
        self.spot(link, Action::ResetStats);
    }

    unsafe fn draw_privacy(&mut self, hdc: HDC, rect: RECT) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        if self.job == Job::Cleaning {
            self.heading(hdc, rect, "Privacy", None);
            self.subtitle(hdc, rect, "Please keep Registry Master open until it finishes.");
            let text_line = PROGRESS.lock().map(|p| p.text.clone()).unwrap_or_default();
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT { left, top: self.s(BODY_Y + 48), right, bottom: self.s(BODY_Y + 74) },
                &text_line,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            return;
        }
        self.heading(hdc, rect, "Privacy", None);
        let line = if !self.priv_note.is_empty() {
            self.priv_note.clone()
        } else {
            "Tick what to clean, then Preview. Cleaning never touches Windows itself.".to_string()
        };
        self.subtitle(hdc, rect, &line);
        text(
            hdc,
            self.fonts.small,
            MUTED,
            RECT { left, top: self.s(BODY_Y), right, bottom: self.s(BODY_Y + 22) },
            "Double-click a row for details. Registry entries are backed up first; files are not.",
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    unsafe fn draw_services(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        if self.job == Job::Services {
            self.heading(hdc, rect, "Services", None);
            self.subtitle(hdc, rect, "Please keep Registry Master open until it finishes.");
            let text_line = PROGRESS.lock().map(|p| p.text.clone()).unwrap_or_default();
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT { left, top: self.s(BODY_Y + 48), right, bottom: self.s(BODY_Y + 74) },
                &text_line,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            return;
        }
        self.heading(hdc, rect, "Services", None);
        let line = if !self.svc_note.is_empty() {
            self.svc_note.clone()
        } else if !self.elevated {
            "Listing never changes anything. Run as administrator to change services.".to_string()
        } else {
            "Suggested Manual starts, or every service. Listing never changes anything.".to_string()
        };
        self.subtitle(hdc, rect, &line);
        let tabs = [("Suggested", SvcView::Tuneup), ("All services", SvcView::Manage)];
        let mut x = left;
        for (label, view) in tabs {
            let size = measure(hdc, self.fonts.body_bold, label);
            let tab = RECT {
                left: x,
                top: self.s(BODY_Y),
                right: x + size.0 + self.s(28),
                bottom: self.s(BODY_Y + 30),
            };
            let selected = self.svc_view == view;
            let lit = lit(hover, tab);
            round_box(
                hdc,
                tab,
                self.s(14),
                if selected {
                    rgb(225, 236, 250)
                } else if lit {
                    rgb(240, 244, 250)
                } else {
                    rgb(248, 250, 252)
                },
                if selected { rgb(60, 130, 210) } else { rgb(186, 196, 210) },
                if selected { 2 } else { 1 },
            );
            text(
                hdc,
                self.fonts.body_bold,
                if selected { BLUE_INK } else { INK },
                tab,
                label,
                DT_SINGLELINE | DT_VCENTER | DT_CENTER,
            );
            self.spot(tab, Action::SvcView(view));
            x = tab.right + self.s(8);
        }
        let hint = match self.svc_view {
            SvcView::Tuneup => {
                "Ticked suggestions are set to Manual. Everything is backed up first."
            }
            SvcView::Manage => {
                "Double-click for details. Right-click to start, stop, or change the startup type."
            }
        };
        text(
            hdc,
            self.fonts.small,
            MUTED,
            RECT { left: x + self.s(8), top: self.s(BODY_Y), right, bottom: self.s(BODY_Y + 30) },
            hint,
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
        );
    }

    unsafe fn draw_scan(&mut self, hdc: HDC, rect: RECT) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        match self.job {
            Job::Scanning | Job::Repairing => {
                let title = if self.job == Job::Scanning { "Scanning" } else { "Repairing" };
                self.heading(hdc, rect, title, None);
                let line = if self.job == Job::Scanning {
                    "Scanning only reads the registry. Nothing is changed."
                } else {
                    "Please keep Registry Master open until the repair finishes."
                };
                self.subtitle(hdc, rect, line);
                let text_line = PROGRESS.lock().map(|p| p.text.clone()).unwrap_or_default();
                text(
                    hdc,
                    self.fonts.body,
                    INK,
                    RECT { left, top: self.s(BODY_Y + 48), right, bottom: self.s(BODY_Y + 74) },
                    &text_line,
                    DT_SINGLELINE | DT_END_ELLIPSIS,
                );
            }
            _ if !self.scanned => {
                self.heading(hdc, rect, "Scan & Repair", None);
                self.subtitle(hdc, rect, "No scan has been run in this session.");
                let width = right.min(left + self.s(720));
                let y = paragraph(hdc, self.fonts.body, INK, left, width, self.s(BODY_Y), "A scan looks for registry entries and shortcuts that point at programs and files that are no longer on this PC. Scanning never changes anything.");
                paragraph(hdc, self.fonts.body, INK, left, width, y + self.s(12), "After the scan you choose what to repair. Every repair saves a backup first, so it can be undone on the Restore page.");
                if !self.scan_note.is_empty() {
                    text(hdc, self.fonts.body, MUTED, RECT { left, top: self.s(BODY_Y + 180), right, bottom: self.s(BODY_Y + 206) }, &self.scan_note, DT_SINGLELINE);
                }
            }
            _ => {
                self.heading(hdc, rect, "Scan Results", None);
                let line = if self.findings.is_empty() {
                    "Your registry is clean. There is nothing to repair.".to_string()
                } else if self.scan_note.is_empty() {
                    format!("{} problems found.", self.findings.len())
                } else {
                    self.scan_note.clone()
                };
                self.subtitle(hdc, rect, &line);
                let hint = "Ticked rows are repaired. Double-click a row for details, or right-click to ignore it.";
                text(
                    hdc,
                    self.fonts.small,
                    MUTED,
                    RECT { left, top: self.s(BODY_Y - 6), right, bottom: self.s(LIST_Y - 2) },
                    hint,
                    DT_SINGLELINE | DT_END_ELLIPSIS,
                );
            }
        }
    }

    unsafe fn draw_restore(&mut self, hdc: HDC, rect: RECT) {
        self.heading(hdc, rect, "Restore", None);
        let line = if self.backups.is_empty() {
            "No backups yet. Each repair saves one here before it changes anything.".to_string()
        } else {
            "Each repair saved what it removed. Pick a backup to put those entries back.".to_string()
        };
        self.subtitle(hdc, rect, &line);
        if self.job == Job::Restoring {
            text(
                hdc,
                self.fonts.body_bold,
                BLUE_INK,
                RECT { left: rect.right - self.s(160), top: self.s(SUBTITLE_Y), right: rect.right - self.s(24), bottom: self.s(SUBTITLE_Y + 24) },
                "Restoring...",
                DT_SINGLELINE | DT_RIGHT,
            );
        }
    }

    unsafe fn draw_settings(&mut self, hdc: HDC, rect: RECT) {
        self.heading(hdc, rect, "Settings", None);
        self.subtitle(hdc, rect, "Changes are saved as you make them.");
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        text(hdc, self.fonts.heading, INK, RECT { left, top: self.s(BODY_Y), right, bottom: self.s(BODY_Y + 28) }, "What Scan Your Registry checks", DT_SINGLELINE);
        let top = self.s(SETTINGS_IGNORED_Y);
        text(hdc, self.fonts.heading, INK, RECT { left, top, right, bottom: top + self.s(28) }, "Ignored entries", DT_SINGLELINE);
        text(
            hdc,
            self.fonts.body,
            MUTED,
            RECT { left, top: top + self.s(30), right, bottom: top + self.s(56) },
            "These never appear in scans, so they are never repaired. To add one, right-click it in the scan results.",
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    unsafe fn draw_monitor(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        self.heading(hdc, rect, "Monitor Your System", None);
        self.subtitle(hdc, rect, "Read when this page paints. Nothing here changes your PC.");
        let snapshot = gather_snapshot();
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(28);
        let label_w = self.s(150);
        let mut y = self.s(BODY_Y);
        for (label, value) in [
            ("Windows", snapshot.os.clone()),
            ("Up time", format_uptime(snapshot.uptime_secs)),
        ] {
            text(hdc, self.fonts.body_bold, INK, RECT { left, top: y, right: left + label_w, bottom: y + self.s(24) }, label, DT_SINGLELINE);
            text(hdc, self.fonts.body, INK, RECT { left: left + label_w, top: y, right, bottom: y + self.s(24) }, &value, DT_SINGLELINE | DT_END_ELLIPSIS);
            y += self.s(26);
        }
        y += self.s(4);
        let memory_line = format!(
            "{} of {} in use ({}%)",
            format_bytes(snapshot.memory_used()),
            format_bytes(snapshot.memory_total),
            snapshot.memory_used_percent()
        );
        y = self.meter(hdc, left, right, label_w, y, "Memory", &memory_line, snapshot.memory_used_percent());
        let disk_line = format!(
            "{} {} free of {} ({}% used)",
            snapshot.system_drive,
            format_bytes(snapshot.disk_free),
            format_bytes(snapshot.disk_total),
            snapshot.disk_used_percent()
        );
        y = self.meter(hdc, left, right, label_w, y, "System drive", &disk_line, snapshot.disk_used_percent());
        y += self.s(14);
        text(hdc, self.fonts.title, INK, RECT { left, top: y, right, bottom: y + self.s(40) }, "Registry Master Health", DT_SINGLELINE);
        y += self.s(46);
        for (label, value) in self.summary_rows() {
            text(hdc, self.fonts.body_bold, INK, RECT { left, top: y, right: left + label_w, bottom: y + self.s(24) }, label, DT_SINGLELINE);
            text(hdc, self.fonts.body, INK, RECT { left: left + label_w, top: y, right, bottom: y + self.s(24) }, &value, DT_SINGLELINE | DT_END_ELLIPSIS);
            y += self.s(26);
        }
        y += self.s(6);
        let label = "Refresh readings";
        let size = measure(hdc, self.fonts.body, label);
        let link = RECT { left, top: y, right: left + size.0, bottom: y + size.1 };
        text(hdc, self.fonts.body, LINK, link, label, DT_SINGLELINE);
        if lit(hover, link) {
            fill(hdc, RECT { left: link.left, top: link.bottom - 1, right: link.right, bottom: link.bottom }, LINK);
        }
        self.spot(link, Action::Refresh);
    }

    /// Label, value line, and usage bar. Returns the y below the meter.
    unsafe fn meter(&mut self, hdc: HDC, left: i32, right: i32, label_w: i32, y: i32, label: &str, value: &str, used: u64) -> i32 {
        text(hdc, self.fonts.body_bold, INK, RECT { left, top: y, right: left + label_w, bottom: y + self.s(24) }, label, DT_SINGLELINE);
        text(hdc, self.fonts.body, INK, RECT { left: left + label_w, top: y, right, bottom: y + self.s(24) }, value, DT_SINGLELINE | DT_END_ELLIPSIS);
        let bar = RECT { left: left + label_w, top: y + self.s(28), right: (left + label_w + self.s(260)).min(right), bottom: y + self.s(40) };
        let track = if bar.right - bar.left >= self.s(60) { bar } else { RECT { right: bar.left + self.s(60), ..bar } };
        round_box(hdc, track, self.s(6), rgb(238, 242, 247), rgb(186, 196, 210), 1);
        let color = if used >= 90 {
            rgb(200, 60, 60)
        } else if used >= 70 {
            rgb(220, 160, 40)
        } else {
            rgb(70, 160, 80)
        };
        let inner = (track.right - track.left - self.s(4)) * used.min(100) as i32 / 100;
        if inner > 0 {
            fill(
                hdc,
                RECT { left: track.left + self.s(2), top: track.top + self.s(2), right: track.left + self.s(2) + inner, bottom: track.bottom - self.s(2) },
                color,
            );
        }
        y + self.s(48)
    }

    unsafe fn draw_tools(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        self.heading(hdc, rect, "Windows Tools", None);
        self.subtitle(hdc, rect, "Screens that ship with Windows. Registry Master only opens them.");
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(28);
        let gap = self.s(12);
        let col_w = (right - left - gap) / 2;
        let rows = (WINDOWS_TOOLS.len() + 1) / 2;
        let row_h = self.s(52);
        let step = row_h + self.s(6);
        for (index, tool) in WINDOWS_TOOLS.iter().enumerate() {
            let col = (index / rows) as i32;
            let row = (index % rows) as i32;
            let x = left + col * (col_w + gap);
            let y = self.s(BODY_Y) + row * step;
            let tile = RECT { left: x, top: y, right: x + col_w, bottom: y + row_h };
            let lit = lit(hover, tile);
            round_box(
                hdc,
                tile,
                self.s(12),
                if lit { rgb(236, 244, 253) } else { rgb(248, 250, 252) },
                if lit { rgb(60, 130, 210) } else { rgb(186, 196, 210) },
                if lit { 2 } else { 1 },
            );
            let icon_size = self.s(40);
            if let Some(bitmap) = self.tool_icons.get(index).copied().filter(|b| !b.is_null()) {
                blit(hdc, bitmap, tile.left + self.s(8), tile.top + (row_h - icon_size) / 2, icon_size, icon_size);
            }
            let text_left = tile.left + self.s(8) + icon_size + self.s(8);
            text(
                hdc,
                self.fonts.body_bold,
                BLUE_INK,
                RECT { left: text_left, top: tile.top + self.s(4), right: tile.right - self.s(8), bottom: tile.top + self.s(26) },
                tool.name,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            text(
                hdc,
                self.fonts.small,
                MUTED,
                RECT { left: text_left, top: tile.top + self.s(26), right: tile.right - self.s(8), bottom: tile.bottom - self.s(2) },
                tool.description,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            self.spot(tile, Action::OpenTool(index));
        }
    }

    unsafe fn draw_about(&mut self, hdc: HDC, rect: RECT) {
        self.heading(hdc, rect, "About", None);
        self.subtitle(hdc, rect, &format!("Registry Master {}", env!("CARGO_PKG_VERSION")));
        let left = self.s(CONTENT_X);
        let icon_w = self.s(70);
        let right = (rect.right - self.s(24) - icon_w - self.s(24)).max(left + self.s(200));
        if let Some(bitmap) = self.icons.get(4).copied().filter(|b| !b.is_null()) {
            blit(hdc, bitmap, rect.right - self.s(24) - icon_w, self.s(TITLE_Y), icon_w, self.s(64));
        }
        let gap = self.s(10);
        let mut y = self.s(BODY_Y);
        y = paragraph(hdc, self.fonts.body, INK, left, right, y, "Registry Master finds registry entries, shortcuts, and old temp files left behind by programs that are no longer installed on Windows 10 or 11, and removes the ones you pick.") + gap * 2;
        y = paragraph(hdc, self.fonts.heading, INK, left, right, y, "How it keeps your PC safe") + gap / 2;
        for line in [
            "Scanning only reads. Nothing changes until you choose Repair and confirm.",
            "A file only counts as missing when it is on a local disk that is plugged in. Network, USB, and unreadable paths are left alone.",
            "Before repairing, the ticked entries are checked again, and everything about to be removed is saved to a backup first.",
            "It never touches Winlogon, default-app choices, Windows Installer data, files inside the Windows folder, or built-in protocols such as http.",
            "Services change only on the Services page, one ticked row at a time, with the old start types backed up first.",
            "Privacy cleaning removes only your own history, temp, and cache files; registry entries are backed up first, and thumbnail caches, Prefetch, and Windows system folders are never touched.",
        ] {
            paragraph(hdc, self.fonts.body, BLUE_INK, left, left + self.s(16), y, "\u{2022}");
            y = paragraph(hdc, self.fonts.body, INK, left + self.s(16), right, y, line) + gap / 2;
        }
        y += gap * 2;
        y = paragraph(hdc, self.fonts.heading, INK, left, right, y, "Where things are kept") + gap / 2;
        for (label, value) in [
            ("Backups", backups_dir().display().to_string()),
            ("Settings and ignore list", registry_master::DATA_DIR.to_string()),
            ("Images", image_root().display().to_string()),
        ] {
            paragraph(hdc, self.fonts.body_bold, INK, left, left + self.s(190), y, label);
            y = paragraph(hdc, self.fonts.body, INK, left + self.s(190), right, y, &value) + gap / 2;
        }
        y += gap * 2;
        paragraph(hdc, self.fonts.body, MUTED, left, right, y, "From a terminal, run registry-master --help for the scan, repair, and restore commands.");
    }
}

// ---- worker helpers ----------------------------------------------------

fn set_progress(done: usize, total: usize, text: &str) {
    if let Ok(mut progress) = PROGRESS.lock() {
        progress.done = done;
        progress.total = total;
        progress.text = text.to_string();
    }
}

fn progress_text(text: &str) {
    if let Ok(mut progress) = PROGRESS.lock() {
        progress.text = text.to_string();
    }
}

fn post(hwnd: isize, message: u32) {
    unsafe { PostMessageW(hwnd as HWND, message, 0, 0) };
}

fn finish_job(hwnd: isize, result: JobResult) {
    if let Ok(mut slot) = RESULT.lock() {
        *slot = Some(result);
    }
    post(hwnd, WM_JOB_DONE);
}

// ---- formatting --------------------------------------------------------

fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Short names for the Category column.
fn category(id: ScannerId) -> &'static str {
    match id {
        ScannerId::SoftwareLocations => "Software",
        ScannerId::RegistryIntegrity => "Shell folders",
        ScannerId::WindowsFonts => "Fonts",
        ScannerId::HelpResources => "Help & sounds",
        ScannerId::SharedDlls => "Shared DLLs",
        ScannerId::StartupPrograms => "Startup",
        ScannerId::AddRemovePrograms => "Uninstall",
        ScannerId::VirtualDevices => "Devices",
        ScannerId::FileExtensions => "File types",
        ScannerId::TempShortcuts => "Shortcuts & temp",
        ScannerId::CustomControls => "COM & shell",
        ScannerId::DeepScan => "Deep scan",
    }
}

fn short_hive(key: &str) -> String {
    for (long, short) in [
        ("HKEY_LOCAL_MACHINE", "HKLM"),
        ("HKEY_CURRENT_USER", "HKCU"),
        ("HKEY_CLASSES_ROOT", "HKCR"),
        ("HKEY_USERS", "HKU"),
        ("HKEY_CURRENT_CONFIG", "HKCC"),
    ] {
        if let Some(rest) = key.strip_prefix(long) {
            return format!("{short}{rest}");
        }
    }
    key.to_string()
}

/// Full location, for Details and Copy.
fn location(finding: &Finding) -> String {
    let key = short_hive(&finding.key);
    match finding.value.as_deref() {
        None => key,
        Some("") => format!("{key}  >  (default)"),
        Some(name) => format!("{key}  >  {name}"),
    }
}

/// Location for the list: the middle of long keys and paths is elided so
/// the end, which names the program, stays visible.
fn short_location(finding: &Finding) -> String {
    let key = compact_path(&short_hive(&finding.key), 2);
    match finding.value.as_deref() {
        None => key,
        Some("") => format!("{key}  >  (default)"),
        Some(name) => format!("{key}  >  {}", compact_path(name, 2)),
    }
}

/// `C:\Users\Ada\AppData\Local\Old\Tool\bin\tool.exe` becomes
/// `C:\...\bin\tool.exe`.
fn compact_path(path: &str, tail: usize) -> String {
    let parts: Vec<&str> = path.split('\\').collect();
    if parts.len() <= tail + 2 {
        return path.to_string();
    }
    format!("{}\\\u{2026}\\{}", parts[0], parts[parts.len() - tail..].join("\\"))
}

/// Shorten every path inside a problem description.
fn compact_detail(detail: &str) -> String {
    let mut out = String::new();
    let mut rest = detail;
    while let Some(start) = find_path(rest) {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail.find(", ").unwrap_or(tail.len());
        out.push_str(&compact_path(&tail[..end], 2));
        rest = &tail[end..];
    }
    out.push_str(rest);
    sentence(&out)
}

fn find_path(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(2)).find(|&i| {
        bytes[i].is_ascii_alphabetic()
            && bytes[i + 1] == b':'
            && bytes[i + 2] == b'\\'
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
    })
}

fn contents(summary: &BackupSummary) -> String {
    let mut parts = Vec::new();
    if summary.keys > 0 {
        parts.push(plural(summary.keys, "key"));
    }
    if summary.values > 0 {
        parts.push(plural(summary.values, "value"));
    }
    if !summary.files.is_empty() {
        parts.push(plural(summary.files.len(), "shortcut"));
    }
    if parts.is_empty() {
        "nothing that can be restored".into()
    } else {
        parts.join(", ")
    }
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("1 {word}")
    } else {
        format!("{count} {word}s")
    }
}

fn local_now() -> String {
    unsafe {
        let mut time: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut time);
        format_time(&time)
    }
}

fn format_time(time: &SYSTEMTIME) -> String {
    format!(
        "{}-{:02}-{:02} {:02}:{:02}",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute
    )
}

fn local_time_text(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let ticks = since.as_nanos() as u64 / 100 + 116_444_736_000_000_000;
    let file_time = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    unsafe {
        let mut utc: SYSTEMTIME = std::mem::zeroed();
        let mut local: SYSTEMTIME = std::mem::zeroed();
        if FileTimeToSystemTime(&file_time, &mut utc) == 0
            || SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0
        {
            return String::new();
        }
        format_time(&local)
    }
}

/// `registry-master-YYYYMMDD-HHMMSS.reg` in local time, never reusing a name.
fn next_backup_file() -> PathBuf {
    next_backup_file_with("registry-master")
}

/// `services-YYYYMMDD-HHMMSS.reg` in local time, never reusing a name.
fn next_services_backup_file() -> PathBuf {
    next_backup_file_with("services")
}

fn next_privacy_backup_file() -> PathBuf {
    next_backup_file_with("privacy")
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn next_backup_file_with(prefix: &str) -> PathBuf {
    let dir = backups_dir();
    let stamp = unsafe {
        let mut t: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut t);
        format!(
            "{}{:02}{:02}-{:02}{:02}{:02}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
        )
    };
    let mut path = dir.join(format!("{prefix}-{stamp}.reg"));
    let mut n = 2;
    while path.exists() {
        path = dir.join(format!("{prefix}-{stamp}-{n}.reg"));
        n += 1;
    }
    path
}

// ---- Win32 helpers -----------------------------------------------------

const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

fn scale(value: i32, dpi: u32) -> i32 {
    (value as i64 * dpi as i64 / 96) as i32
}

fn point(lparam: LPARAM) -> (i32, i32) {
    (
        (lparam & 0xffff) as i16 as i32,
        ((lparam >> 16) & 0xffff) as i16 as i32,
    )
}

fn same(a: RECT, b: RECT) -> bool {
    a.left == b.left && a.top == b.top && a.right == b.right && a.bottom == b.bottom
}

fn lit(hover: Option<RECT>, rect: RECT) -> bool {
    hover.is_some_and(|h| same(h, rect))
}

fn hit(rect: RECT, x: i32, y: i32) -> bool {
    x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn make_fonts(dpi: u32) -> Fonts {
    let font = |size: i32, weight: i32| unsafe {
        CreateFontW(-scale(size, dpi), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, wide("Segoe UI").as_ptr())
    };
    Fonts {
        title: font(26, 600),
        heading: font(19, 600),
        body: font(15, 400),
        body_bold: font(15, 600),
        small: font(13, 400),
    }
}

fn delete_fonts(fonts: &Fonts) {
    for font in [fonts.title, fonts.heading, fonts.body, fonts.body_bold, fonts.small] {
        unsafe { DeleteObject(font) };
    }
}

fn button(parent: HWND, id: u16, label: &str, style: i32) -> HWND {
    let text = wide(label);
    unsafe {
        CreateWindowExW(
            0,
            wide("BUTTON").as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_TABSTOP | style as u32,
            0,
            0,
            10,
            10,
            parent,
            id as usize as HMENU,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    }
}

fn list_view(parent: HWND, id: u16, style: u32, ex_style: u32, columns: &[(&str, i32)]) -> HWND {
    unsafe {
        let list = CreateWindowExW(
            0,
            WC_LISTVIEWW,
            std::ptr::null(),
            WS_CHILD | WS_BORDER | WS_VSCROLL | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER | style,
            0,
            0,
            10,
            10,
            parent,
            id as usize as HMENU,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        );
        let extended = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | ex_style;
        SendMessageW(list, LVM_SETEXTENDEDLISTVIEWSTYLE, extended as usize, extended as isize);
        SetWindowTheme(list, wide("Explorer").as_ptr(), std::ptr::null());
        for (index, (title, width)) in columns.iter().enumerate() {
            let mut text = wide(title);
            let mut column: LVCOLUMNW = std::mem::zeroed();
            column.mask = LVCF_TEXT | LVCF_WIDTH;
            column.cx = *width;
            column.pszText = text.as_mut_ptr();
            SendMessageW(list, LVM_INSERTCOLUMNW, index, &mut column as *mut _ as isize);
        }
        list
    }
}

fn insert_row(list: HWND, row: usize, cells: &[&str]) {
    unsafe {
        let mut first = wide(cells.first().copied().unwrap_or(""));
        let mut item: LVITEMW = std::mem::zeroed();
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = row as i32;
        item.pszText = first.as_mut_ptr();
        item.lParam = row as isize;
        SendMessageW(list, LVM_INSERTITEMW, 0, &mut item as *mut _ as isize);
        for (column, cell) in cells.iter().enumerate().skip(1) {
            let mut text = wide(cell);
            let mut sub: LVITEMW = std::mem::zeroed();
            sub.mask = LVIF_TEXT;
            sub.iItem = row as i32;
            sub.iSubItem = column as i32;
            sub.pszText = text.as_mut_ptr();
            SendMessageW(list, LVM_SETITEMTEXTW, row, &mut sub as *mut _ as isize);
        }
    }
}

/// 0 hides the check box, 1 is unticked, 2 is ticked.
fn set_state_image(list: HWND, row: usize, image: u32) {
    unsafe {
        let mut item: LVITEMW = std::mem::zeroed();
        item.stateMask = LVIS_STATEIMAGEMASK;
        item.state = image << 12;
        SendMessageW(list, LVM_SETITEMSTATE, row, &mut item as *mut _ as isize);
    }
}

fn selected_rows(list: HWND) -> Vec<usize> {
    let mut rows = Vec::new();
    let mut from = usize::MAX;
    unsafe {
        let count = SendMessageW(list, LVM_GETITEMCOUNT, 0, 0) as usize;
        while rows.len() <= count {
            let next = SendMessageW(list, LVM_GETNEXTITEM, from, LVNI_SELECTED as isize);
            if next < 0 {
                break;
            }
            rows.push(next as usize);
            from = next as usize;
        }
    }
    rows
}

fn place(control: HWND, x: i32, y: i32, w: i32, h: i32) {
    unsafe { MoveWindow(control, x, y, w.max(1), h.max(1), 1) };
}

fn set_text(control: HWND, text: &str) {
    unsafe { SetWindowTextW(control, wide(text).as_ptr()) };
}

unsafe fn fill(hdc: HDC, rect: RECT, color: u32) {
    let brush = CreateSolidBrush(color);
    FillRect(hdc, &rect, brush);
    DeleteObject(brush);
}

unsafe fn round_box(hdc: HDC, rect: RECT, radius: i32, fill_color: u32, border: u32, width: i32) {
    let pen = CreatePen(0, width, border);
    let brush = CreateSolidBrush(fill_color);
    let old_pen = SelectObject(hdc, pen);
    let old_brush = SelectObject(hdc, brush);
    RoundRect(hdc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    SelectObject(hdc, old_pen);
    SelectObject(hdc, old_brush);
    DeleteObject(pen);
    DeleteObject(brush);
}

unsafe fn gradient(hdc: HDC, rect: RECT, start: (u8, u8, u8), end: (u8, u8, u8), vertical: bool) {
    let mut vert = [
        TRIVERTEX { x: rect.left, y: rect.top, Red: (start.0 as u16) << 8, Green: (start.1 as u16) << 8, Blue: (start.2 as u16) << 8, Alpha: 0 },
        TRIVERTEX { x: rect.right, y: rect.bottom, Red: (end.0 as u16) << 8, Green: (end.1 as u16) << 8, Blue: (end.2 as u16) << 8, Alpha: 0 },
    ];
    let mut mesh = windows_sys::Win32::Graphics::Gdi::GRADIENT_RECT { UpperLeft: 0, LowerRight: 1 };
    let mode = if vertical { GRADIENT_FILL_RECT_V } else { GRADIENT_FILL_RECT_H };
    GradientFill(hdc, vert.as_mut_ptr(), 2, &mut mesh as *mut _ as *mut _, 1, mode);
}

unsafe fn text(hdc: HDC, font: HFONT, color: u32, rect: RECT, value: &str, flags: u32) {
    let old = SelectObject(hdc, font);
    SetTextColor(hdc, color);
    SetBkMode(hdc, TRANSPARENT as i32);
    let mut rect = rect;
    let value = wide(value);
    DrawTextW(hdc, value.as_ptr(), -1, &mut rect, flags | DT_NOPREFIX);
    SelectObject(hdc, old);
}

/// Draw wrapped text at `y` and return the y just below it.
unsafe fn paragraph(hdc: HDC, font: HFONT, color: u32, left: i32, right: i32, y: i32, value: &str) -> i32 {
    let old = SelectObject(hdc, font);
    let wide_value = wide(value);
    let mut rect = RECT { left, top: y, right, bottom: y };
    DrawTextW(hdc, wide_value.as_ptr(), -1, &mut rect, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    SelectObject(hdc, old);
    let height = rect.bottom - rect.top;
    text(hdc, font, color, RECT { left, top: y, right, bottom: y + height }, value, DT_WORDBREAK);
    y + height
}

unsafe fn measure(hdc: HDC, font: HFONT, value: &str) -> (i32, i32) {
    let old = SelectObject(hdc, font);
    let mut rect = RECT::default();
    let value = wide(value);
    DrawTextW(hdc, value.as_ptr(), -1, &mut rect, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, old);
    (rect.right - rect.left, rect.bottom - rect.top)
}

unsafe fn blit(hdc: HDC, bitmap: HBITMAP, x: i32, y: i32, w: i32, h: i32) {
    let mem = CreateCompatibleDC(hdc);
    let old = SelectObject(mem, bitmap);
    SetStretchBltMode(hdc, HALFTONE);
    SetBrushOrgEx(hdc, 0, 0, std::ptr::null_mut());
    StretchBlt(hdc, x, y, w, h, mem, 0, 0, 70, 64, SRCCOPY);
    SelectObject(mem, old);
    DeleteDC(mem);
}

fn copy_text(hwnd: HWND, value: &str) {
    const CF_UNICODETEXT: u32 = 13;
    let data = wide(value);
    unsafe {
        let bytes = data.len() * 2;
        let memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if memory.is_null() {
            return;
        }
        let target = GlobalLock(memory) as *mut u16;
        if target.is_null() {
            return;
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), target, data.len());
        GlobalUnlock(memory);
        if OpenClipboard(hwnd) != 0 {
            EmptyClipboard();
            SetClipboardData(CF_UNICODETEXT, memory as HANDLE);
            CloseClipboard();
        }
    }
}

fn shell_open(hwnd: HWND, file: &str, args: Option<&str>) {
    let file = wide(file);
    let args = args.map(wide);
    unsafe {
        ShellExecuteW(
            hwnd,
            wide("open").as_ptr(),
            file.as_ptr(),
            args.as_ref().map_or(std::ptr::null(), |args| args.as_ptr()),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// Registry Editor opens at its saved `LastKey`, so set that and start it.
fn open_in_regedit(hwnd: HWND, key: &str) {
    let data = wide(&format!("Computer\\{key}"));
    unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            wide(r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit").as_ptr(),
            wide("LastKey").as_ptr(),
            REG_SZ,
            data.as_ptr() as *const _,
            (data.len() * 2) as u32,
        );
    }
    shell_open(hwnd, "regedit.exe", Some("-m"));
}

fn exe_path() -> PathBuf {
    let mut buffer = vec![0u16; 32_768];
    let len = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32) };
    buffer.truncate(len as usize);
    PathBuf::from(String::from_utf16_lossy(&buffer))
}

fn image_root() -> PathBuf {
    let shared = PathBuf::from(r"C:\registrymasterimages");
    if shared.is_dir() {
        return shared;
    }
    exe_path()
        .parent()
        .map(|dir| dir.join("images"))
        .unwrap_or_else(|| PathBuf::from("images"))
}

fn load_bitmap(name: &str) -> HBITMAP {
    let path = image_root().join(name);
    if !Path::new(&path).exists() {
        return std::ptr::null_mut();
    }
    let wide_path = wide(&path.display().to_string());
    unsafe {
        LoadImageW(
            std::ptr::null_mut(),
            wide_path.as_ptr(),
            IMAGE_BITMAP,
            0,
            0,
            LR_LOADFROMFILE | LR_CREATEDIBSECTION,
        ) as HBITMAP
    }
}
