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

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hive_mend::art::Icon;
use hive_mend::{
    BackupInfo, BackupInventory, BackupSummary, CleanOutcome, Engine, Exclusions, Finding,
    HiveEntry, HostFs, ItemOutcome, LEGACY_DIR, LeftAlone, Preview, PrivacyItem, Repair,
    RepairOutcome, SUGGESTED, ScanOptions, ScanReport, ScannerId, ScmServiceStore, ServiceChange,
    ServiceInfo, ServiceOutcome, ServiceState, ServiceStore, Settings, StartType, Store,
    WINDOWS_TOOLS, WindowsProcessList, WindowsRegistry, WindowsSystemTargets, apply_start_changes,
    backup_stores, backups_dir, backups_location, build_items, clean_with_progress,
    custom_privacy_file, decode_text_owned, exclusions_file, expand_target, format_bytes,
    format_uptime, gather_hives, gather_snapshot, group_digits, list_backups_until, parse_custom,
    plan_profile, preview_with, repair_with_progress, restore_backup, scan_with_progress,
    settings_file, sort_services, start_services, still_reported, stop_services, user_dir,
};
use windows_sys::Win32::Foundation::{
    FILETIME, GlobalFree, HANDLE, HWND, LPARAM, LRESULT, POINT, RECT, SYSTEMTIME, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, BitBlt, ClientToScreen, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW,
    CreateSolidBrush, DT_CALCRECT, DT_CENTER, DT_END_ELLIPSIS, DT_NOPREFIX, DT_RIGHT,
    DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, DeleteDC, DeleteObject, DrawTextW, EndPaint, FillRect,
    HBITMAP, HBRUSH, HDC, HFONT, InvalidateRect, PAINTSTRUCT, SRCCOPY, SelectObject, SetBkColor,
    SetBkMode, SetTextColor, TRANSPARENT,
};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows_sys::Win32::UI::Controls::WM_MOUSELEAVE;
use windows_sys::Win32::UI::Controls::{
    ICC_LISTVIEW_CLASSES, ICC_PROGRESS_CLASS, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX,
    InitCommonControlsEx, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_PARAM, LVIF_STATE, LVIF_TEXT,
    LVIS_STATEIMAGEMASK, LVITEMW, LVM_DELETEALLITEMS, LVM_GETITEMCOUNT, LVM_GETITEMRECT,
    LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETCOLUMNWIDTH,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMSTATE, LVM_SETITEMTEXTW, LVN_ITEMCHANGED,
    LVN_ITEMCHANGING, LVN_KEYDOWN, LVNI_SELECTED, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER,
    LVS_EX_FULLROWSELECT, LVS_EX_LABELTIP, LVS_NOSORTHEADER, LVS_REPORT, LVS_SHOWSELALWAYS,
    LVS_SINGLESEL, NM_DBLCLK, NM_RETURN, NMHDR, NMLISTVIEW, NMLVKEYDOWN, PBM_SETPOS,
    PBM_SETRANGE32, PROGRESS_CLASSW, SetWindowTheme, WC_LISTVIEWW,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_PUSHBUTTON, CW_USEDEFAULT,
    CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW,
    GWLP_USERDATA, GetClientRect, GetCursorPos, GetMessageW, GetWindowLongPtrW, HMENU, HTCLIENT,
    IDC_ARROW, IDC_HAND, IDYES, IsDialogMessageW, IsWindow, LoadCursorW, MB_DEFBUTTON2,
    MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MB_YESNO, MF_GRAYED, MF_SEPARATOR,
    MF_STRING, MINMAXINFO, MSG, MessageBoxW, MoveWindow, PostMessageW, PostQuitMessage,
    RegisterClassW, SW_HIDE, SW_SHOW, SW_SHOWNORMAL, SWP_NOACTIVATE, SWP_NOZORDER, SendMessageW,
    SetCursor, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE, WM_COMMAND,
    WM_CONTEXTMENU, WM_CREATE, WM_CTLCOLORBTN, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED,
    WM_ERASEBKGND, WM_GETMINMAXINFO, WM_LBUTTONUP, WM_MOUSEMOVE, WM_NOTIFY, WM_PAINT, WM_SETCURSOR,
    WM_SETFONT, WM_SETREDRAW, WM_SIZE, WNDCLASSW, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN,
    WS_EX_CONTROLPARENT, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_KILLFOCUS, BN_SETFOCUS, WM_ENDSESSION, WM_KEYDOWN, WM_QUERYENDSESSION,
};

const WM_JOB_PROGRESS: u32 = WM_APP + 1;
const WM_JOB_DONE: u32 = WM_APP + 2;
/// Lay out and repaint once a nested WM_SIZE or WM_DPICHANGED was deferred.
const WM_RELAYOUT: u32 = WM_APP + 3;
/// Re-run an action the user just confirmed (see [`App::confirm`]).
const WM_REDO: u32 = WM_APP + 4;
/// Apply a popup-menu choice made after its handler returned.
const WM_MENU_PICKED: u32 = WM_APP + 5;
/// The backup list was read in the background.
const WM_BACKUPS_READY: u32 = WM_APP + 6;
/// Ctrl+1 to Ctrl+9: go to that sidebar page (wParam is the NAV index).
const WM_SHORTCUT: u32 = WM_APP + 7;

/// Stand-ins that make the drawn parts of the window reachable by keyboard,
/// screen readers, and UI automation: a real, named control over each drawn
/// button or link, and a static control over each drawn status line. Each
/// has an empty window region, so it draws nothing and takes no mouse
/// clicks, but it can be focused with Tab, pressed with Enter or Space, and
/// reports its name and place. See [`App::sync_access`].
const ID_ACCESS_BASE: u16 = 3000;
const ACCESS_POOL: usize = 64;
const ID_TEXT_BASE: u16 = 3100;
const TEXT_POOL: usize = 16;

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
const ID_RESTORE_POINT: u16 = 1150;
const ID_SU_ENABLE: u16 = 1600;
const ID_SU_DISABLE: u16 = 1601;
const ID_SU_OPEN: u16 = 1602;
const ID_SU_REFRESH: u16 = 1603;
const ID_SU_LIST: u16 = 2010;
const ID_PG_UNINSTALL: u16 = 1610;
const ID_PG_OPEN: u16 = 1611;
const ID_PG_REFRESH: u16 = 1612;
const ID_PG_LIST: u16 = 2011;
const ID_DS_UP: u16 = 1620;
const ID_DS_OPEN: u16 = 1621;
const ID_DS_LIST: u16 = 2012;
const ID_DUP_EXTRAS: u16 = 1630;
const ID_DUP_NONE: u16 = 1631;
const ID_DUP_RECYCLE: u16 = 1632;
const ID_DUP_OPEN: u16 = 1633;
const ID_DUP_LIST: u16 = 2013;
const ID_SVC_REFRESH: u16 = 1300;
const ID_SVC_ALL: u16 = 1301;
const ID_SVC_NONE: u16 = 1302;
const ID_SVC_APPLY: u16 = 1303;
const ID_SVC_START: u16 = 1304;
const ID_SVC_STOP: u16 = 1305;
const ID_PRIV_PREVIEW: u16 = 1400;
const ID_PRIV_ALL: u16 = 1401;
const ID_PRIV_NONE: u16 = 1402;
const ID_PRIV_KEEP: u16 = 1404;
const ID_PRIV_CLEAN: u16 = 1403;
const ID_FINDINGS: u16 = 2000;
const ID_PROGRESS: u16 = 2001;
const ID_BACKUPS: u16 = 2002;
const ID_IGNORED: u16 = 2003;
const ID_SVC_LIST: u16 = 2004;
const ID_SVC_TUNE: u16 = 2005;
const ID_PRIV_LIST: u16 = 2006;
const IDOK: u16 = 1;
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
const HEADER_H: i32 = 56;
const SIDEBAR_W: i32 = 172;
const CONTENT_X: i32 = 196;
const FOOTER_H: i32 = 0;
const TITLE_Y: i32 = HEADER_H + 14;
const SUBTITLE_Y: i32 = HEADER_H + 52;
/// Where page content starts, below the title and subtitle.
const BODY_Y: i32 = HEADER_H + 90;
const LIST_Y: i32 = BODY_Y + 22;
/// The restore-point checkbox sits under the scanner grid.
const SETTINGS_RESTORE_POINT_Y: i32 = BODY_Y + 34 + 6 * 30 + 6;
const SETTINGS_IGNORED_Y: i32 = BODY_Y + 34 + 6 * 30 + 52;

/// The window background; cards and tiles sit on it as white surfaces.
const BG: u32 = rgb(245, 247, 246);
const SURFACE: u32 = rgb(255, 255, 255);
const BORDER: u32 = rgb(222, 229, 224);
/// The primary action colour (Scan now, the open page's marker).
const ACCENT_GREEN: u32 = rgb(24, 122, 66);
const ACCENT_GREEN_HOVER: u32 = rgb(16, 100, 52);
/// Soft green fill for the open page and hovered tiles.
const ACCENT_TINT: u32 = rgb(224, 240, 229);
const HOVER_TINT: u32 = rgb(232, 238, 234);
const SIDEBAR_BG: u32 = rgb(238, 242, 239);
const INK: u32 = rgb(28, 28, 28);
const MUTED: u32 = rgb(88, 98, 92);
const LINK: u32 = rgb(22, 110, 56);
/// Deep Celtic green, the theme colour shared with the icons in `art`.
const THEME_INK: u32 = rgb(22, 86, 48);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Status,
    Scan,
    Restore,
    Settings,
    Services,
    Privacy,
    Startup,
    Programs,
    DiskSpace,
    Duplicates,
    Monitor,
    Tools,
    About,
}

const NAV: &[(&str, Page, Icon)] = &[
    ("Home", Page::Status, Icon::Logo),
    ("Scan", Page::Scan, Icon::Scan),
    ("Restore", Page::Restore, Icon::Restore),
    ("Privacy", Page::Privacy, Icon::Privacy),
    ("Startup", Page::Startup, Icon::Startup),
    ("Programs", Page::Programs, Icon::Programs),
    ("Disk Space", Page::DiskSpace, Icon::DiskSpace),
    ("Duplicates", Page::Duplicates, Icon::Duplicates),
    ("Services", Page::Services, Icon::Optimize),
    ("Monitor", Page::Monitor, Icon::Monitor),
    ("Tools", Page::Tools, Icon::Tools),
    ("Settings", Page::Settings, Icon::Settings),
    ("About", Page::About, Icon::About),
];

/// Friendly names and what each scanner looks at, for Settings.
const SCANNERS: &[(ScannerId, &str)] = &[
    (
        ScannerId::SoftwareLocations,
        "Software locations and run history",
    ),
    (ScannerId::StartupPrograms, "Startup programs"),
    (
        ScannerId::AddRemovePrograms,
        "Uninstall entries and firewall rules",
    ),
    (
        ScannerId::CustomControls,
        "COM controls and shell extensions",
    ),
    (ScannerId::FileExtensions, "File associations and Open With"),
    (ScannerId::SharedDlls, "Shared DLLs"),
    (ScannerId::WindowsFonts, "Fonts"),
    (ScannerId::HelpResources, "Help files and sounds"),
    (ScannerId::VirtualDevices, "Virtual devices"),
    (
        ScannerId::TempShortcuts,
        "Broken shortcuts and old temp files",
    ),
    (ScannerId::RegistryIntegrity, "Shell folders (report only)"),
    (ScannerId::DeepScan, "Deep Scan (review results closely)"),
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
    Analyzing,
    Finding,
    Recycling,
    Previewing,
}

/// Disk Space page views.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DiskView {
    Folders,
    Files,
    Kinds,
}

/// What a Disk Space row stands for.
#[derive(Clone, Copy)]
enum DiskRow {
    Folder(usize),
    File(usize),
    Kind,
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
    DiskRoot(usize),
    DupRoot(usize),
    DiskView(DiskView),
}

impl Action {
    fn starts_job(self) -> bool {
        matches!(self, Action::ScanAll | Action::Optimize | Action::Elevate)
    }
}

struct HotSpot {
    rect: RECT,
    action: Action,
    /// What it says, for keyboard and screen-reader users.
    name: String,
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
        /// What happened with the Windows restore point, if one was asked for.
        restore_note: Option<String>,
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
    Disk {
        report: Box<hive_mend::DiskReport>,
    },
    Dups {
        result: Result<hive_mend::DupReport, String>,
    },
    Recycled {
        results: Vec<(String, Result<(), String>)>,
    },
    PrivacyPreview {
        report: Preview,
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
/// The backup listing: one reader at a time, newest request wins.
static BACKUPS: hive_mend::Refresher<BackupInventory> = hive_mend::Refresher::new();
static CANCEL: AtomicBool = AtomicBool::new(false);

// Reentrancy guard for the window procedure. Synchronous dispatches
// (SetWindowPos, control notifications) re-enter wnd_proc while the outer
// handler still holds its &mut App. A second &mut to the same App would be
// undefined behavior, so nested entries never touch App: they record what
// must not be lost in DEFERRED and fall through to DefWindowProcW. Native
// modal loops never run under the guard: messages App never handles go to
// DefWindowProcW before the guard is taken (title-bar drag, frame sizing,
// system menu, caption buttons), and message boxes, confirmations, popup
// menus, shell opens, and the UAC relaunch are queued in NATIVE and shown by
// run_native after the handler returns. Once an outer handler returns and
// releases the guard, flush_deferred re-posts everything recorded and runs
// the queued native UI.
static IN_HANDLER: AtomicBool = AtomicBool::new(false);
/// `DEFER_*` bits recorded by nested entries. One bit per kind, so a later
/// progress tick can never overwrite a parked completion.
static DEFERRED: AtomicU32 = AtomicU32::new(0);
const DEFER_PROGRESS: u32 = 1;
const DEFER_DONE: u32 = 2;
const DEFER_CLOSE: u32 = 4;
const DEFER_LAYOUT: u32 = 8;
const DEFER_PAINT: u32 = 16;
const DEFER_BACKUPS: u32 = 32;

// Native modal UI (message boxes, confirmations, popup menus, the UAC
// relaunch) never runs inside a handler. A handler queues it here and
// returns; run_native shows it once the guard is released, so the modal loop
// dispatches every message to a free handler instead of a parked one. A
// confirmation does not resume the code that asked: on Yes the action is
// re-run, recomputes its question from the state at that moment, and proceeds
// only if that question and the exact targets match what was approved.
static NATIVE: Mutex<VecDeque<Native>> = Mutex::new(VecDeque::new());
/// True while run_native has a modal loop open; nested flushes leave the
/// queue to it, so only one dialog is up at a time.
static SHOWING: AtomicBool = AtomicBool::new(false);
/// Confirmed actions waiting for WM_REDO, with their approval keys.
static REDO: Mutex<VecDeque<(Redo, String)>> = Mutex::new(VecDeque::new());
/// The approval key for the action WM_REDO is re-running right now.
static APPROVED: Mutex<Option<String>> = Mutex::new(None);
/// Menu choices waiting for WM_MENU_PICKED.
static PICKED: Mutex<VecDeque<Picked>> = Mutex::new(VecDeque::new());

enum Native {
    Message {
        text: String,
        icon: u32,
    },
    Confirm {
        text: String,
        key: String,
        redo: Redo,
    },
    Menu {
        /// HMENU, owned here until shown and destroyed.
        menu: isize,
        at: POINT,
        picked: Picked,
    },
    /// Relaunch elevated; close this window if the copy started.
    Elevate,
    /// Open a file, folder, or program with the shell.
    Shell {
        file: String,
        args: Option<String>,
    },
}

/// The action a confirmation guards, re-run once the user says Yes.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Redo {
    IgnoreRows(Vec<usize>),
    ServicesApply,
    PowerRows(Vec<usize>, bool),
    SetRows(Vec<usize>, StartType),
    PrivacyClean,
    Repair,
    Restore(usize),
    Startup(Vec<usize>, bool),
    Uninstall(usize),
    Recycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MenuKind {
    Findings,
    Services,
}

/// A popup menu shown for some rows. The choice is applied only if those
/// rows still name the same items (`identity`) when it arrives.
#[derive(Clone, Debug)]
struct Picked {
    kind: MenuKind,
    rows: Vec<usize>,
    identity: String,
    choice: usize,
}

fn lock<T>(slot: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The approval key for a confirmation: the question and the exact targets.
fn approval_key(question: &str, identity: &str) -> String {
    format!("{identity}\u{1f}{question}")
}

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
    /// Icons rendered by `art` at the pixel sizes drawn so far.
    art: HashMap<(Icon, i32), HBITMAP>,
    /// Anti-aliased corner sprites for rounded boxes, by radius and colours.
    corners: HashMap<(i32, u32, u32, i32, u32), HBITMAP>,
    hotspots: Vec<HotSpot>,
    /// Stand-in buttons for `hotspots`, in the same order, and what each
    /// was last set to (name, place, enabled) or `None` when hidden.
    access: Vec<HWND>,
    access_shown: Vec<Option<(String, Edges, bool)>>,
    /// Status lines drawn in the last paint, and their stand-in statics.
    texts: std::cell::RefCell<Vec<(RECT, String)>>,
    text_ctls: Vec<HWND>,
    text_shown: Vec<Option<(String, Edges)>>,
    hover: Option<usize>,
    tracking: bool,
    elevated: bool,

    settings: Settings,
    exclusions: Exclusions,
    backups: Vec<BackupInfo>,
    /// The refresh the shown list answers.
    backups_shown: u64,
    /// The newest backup listing could not be read.
    backups_failed: bool,
    /// What the shown listing failed to read: stores, entries, or files.
    backup_errors: Vec<String>,

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
    chk_restore_point: HWND,
    startup_items: Vec<hive_mend::StartupItem>,
    startup_loaded: bool,
    startup_note: String,
    startup_list: HWND,
    btn_su_enable: HWND,
    btn_su_disable: HWND,
    btn_su_open: HWND,
    btn_su_refresh: HWND,
    programs: Vec<hive_mend::InstalledProgram>,
    programs_loaded: bool,
    programs_note: String,
    /// Findings this window leaves alone without offering them, and why:
    /// forecast after each scan, and added to when a repair refuses one.
    left_alone: Vec<(Finding, LeftAlone)>,
    /// Report-only and protected findings of the last scan in this window,
    /// shown on Home when nothing is left to fix.
    last_info: usize,
    programs_list: HWND,
    btn_pg_uninstall: HWND,
    btn_pg_open: HWND,
    btn_pg_refresh: HWND,
    disk_roots: Vec<(String, String)>,
    disk_report: Option<Box<hive_mend::DiskReport>>,
    disk_root: Option<usize>,
    disk_at: usize,
    disk_view: DiskView,
    disk_rows: Vec<DiskRow>,
    disk_note: String,
    disk_list: HWND,
    btn_ds_up: HWND,
    btn_ds_open: HWND,
    dup_report: Option<hive_mend::DupReport>,
    dup_root: Option<usize>,
    /// (set, file) for each list row.
    dup_rows: Vec<(usize, usize)>,
    dup_checked: Vec<bool>,
    dup_filling: bool,
    dup_note: String,
    dup_list: HWND,
    btn_dup_extras: HWND,
    btn_dup_none: HWND,
    btn_dup_recycle: HWND,
    btn_dup_open: HWND,
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
    btn_priv_keep: HWND,
    /// When the cookies-to-keep list was last read, to notice edits.
    priv_keep_stamp: Option<std::time::SystemTime>,
    btn_priv_clean: HWND,
}

/// Set by [`run`] when Hivemend was started to open on the Programs page.
static OPEN_PROGRAMS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The command-line flag [`start_unelevated`] passes so the new window opens
/// on Programs.
pub const PROGRAMS_FLAG: &str = "--programs";

pub fn run(open_programs: bool) -> std::process::ExitCode {
    OPEN_PROGRAMS.store(open_programs, std::sync::atomic::Ordering::Relaxed);
    unsafe {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES,
        };
        InitCommonControlsEx(&icc);
        let class_name = wide("HiveMendWindow");
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetSystemMetrics, ICON_SMALL, SM_CXICON, SM_CXSMICON, WM_SETICON,
        };
        let big = logo_icon(GetSystemMetrics(SM_CXICON));
        let class = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: GetModuleHandleW(std::ptr::null()),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hIcon: big,
            lpszClassName: class_name.as_ptr(),
            ..std::mem::zeroed()
        };
        if RegisterClassW(&class) == 0 {
            return std::process::ExitCode::from(1);
        }
        let dpi = GetDpiForSystem().max(96);
        let title = wide("Hivemend");
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
        let small = logo_icon(GetSystemMetrics(SM_CXSMICON));
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL as usize, small as isize);
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            // Ctrl+1 to Ctrl+9 open the first nine sidebar pages.
            if msg.message == WM_KEYDOWN
                && windows_sys::Win32::UI::Input::KeyboardAndMouse::GetKeyState(
                    windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_CONTROL as i32,
                ) < 0
                && (0x31..=0x39).contains(&msg.wParam)
            {
                PostMessageW(hwnd, WM_SHORTCUT, msg.wParam - 0x31, 0);
                continue;
            }
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        std::process::ExitCode::from(msg.wParam as u8)
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_CREATE {
        let app = Box::new(App::new(hwnd));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(app) as isize);
        let _guard = HandlerGuard::enter();
        if _guard.is_none() {
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }
        let app = &mut *window_app(hwnd);
        app.sync_controls();
        app.refresh_backups();
        if OPEN_PROGRAMS.load(std::sync::atomic::Ordering::Relaxed) {
            app.go(Page::Programs);
        }
        drop(_guard);
        flush_deferred(hwnd);
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
    if app.is_null() || !app_handles(msg) {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    // Nested dispatch while a handler runs: record what must not be lost,
    // default the rest, and never form a second &mut App. WM_CLOSE must not
    // reach DefWindowProcW here — its default action destroys the window
    // without running our WM_DESTROY cleanup.
    let Some(guard) = HandlerGuard::enter() else {
        let (bits, reply) = nested_reply(msg);
        DEFERRED.fetch_or(bits, Ordering::SeqCst);
        return match reply {
            NestedReply::Handled => 0,
            NestedReply::Default => DefWindowProcW(hwnd, msg, wparam, lparam),
        };
    };
    let result = 'handled: {
        let _guard = guard;
        let app = &mut *app;
        match msg {
            WM_ERASEBKGND => 1,
            WM_PAINT => {
                app.paint();
                0
            }
            WM_SIZE | WM_RELAYOUT => {
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
                // The nested WM_SIZE is deferred by the guard, so lay out and
                // repaint directly instead of waiting for the flush.
                app.sync_controls();
                app.invalidate();
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
                if (lparam & 0xffff) as u32 == HTCLIENT
                    && wparam as HWND == hwnd
                    && let Some(index) = app.hover
                    && app.spot_enabled(index)
                {
                    SetCursor(LoadCursorW(std::ptr::null_mut(), IDC_HAND));
                    break 'handled 1;
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
            WM_LBUTTONUP => {
                let (x, y) = point(lparam);
                if let Some(index) = app.spot_at(x, y)
                    && app.spot_enabled(index)
                {
                    let action = app.hotspots[index].action;
                    app.perform(action);
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
            WM_BACKUPS_READY => {
                if let Some((refresh, inventory)) = BACKUPS.take()
                    && refresh == BACKUPS.wanted()
                {
                    // A failed read keeps the list shown before, and says so.
                    // A partial read replaces the list but labels what failed.
                    app.backups_failed = inventory.is_none();
                    if let Some(inventory) = inventory {
                        app.backups = inventory.items;
                        app.backup_errors = inventory.errors;
                    }
                    app.backups_shown = refresh;
                    app.fill_backups();
                    app.invalidate();
                }
                0
            }
            WM_JOB_DONE => {
                if let Some(result) = RESULT.lock().ok().and_then(|mut slot| slot.take()) {
                    app.finish(result);
                }
                0
            }
            WM_REDO => {
                if let Some((redo, key)) = lock(&REDO).pop_front() {
                    *lock(&APPROVED) = Some(key);
                    app.redo(redo);
                    *lock(&APPROVED) = None;
                }
                0
            }
            WM_SHORTCUT => {
                if let Some((_, page, _)) = NAV.get(wparam) {
                    app.go(*page);
                }
                0
            }
            WM_MENU_PICKED => {
                if let Some(picked) = lock(&PICKED).pop_front() {
                    app.menu_picked(picked);
                }
                0
            }
            // Sign-out, shutdown, and an installer closing Hivemend to
            // update it (Restart Manager): agree unless a job must finish,
            // then close as WM_CLOSE would.
            WM_QUERYENDSESSION => (!app.must_finish()) as LRESULT,
            WM_ENDSESSION => {
                if wparam != 0 && !app.must_finish() {
                    drop(_guard);
                    DestroyWindow(hwnd);
                }
                0
            }
            WM_CLOSE => {
                if app.must_finish() {
                    app.message(
                        "Hivemend is still working. Please wait for it to finish before closing.",
                        MB_ICONWARNING,
                    );
                    break 'handled 0;
                }
                // app is dead after this point: DestroyWindow dispatches
                // WM_DESTROY synchronously, which must run as a normal guarded
                // entry instead of being deferred.
                drop(_guard);
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
    };
    // The guard is released here, so re-posted messages reach a free handler.
    flush_deferred(hwnd);
    result
}

/// Messages the window procedure acts on. Everything else goes straight to
/// DefWindowProcW without taking the guard or borrowing App, so a native
/// modal loop it starts (title-bar drag, frame sizing, system menu, caption
/// buttons) is not run inside a handler.
fn app_handles(msg: u32) -> bool {
    matches!(
        msg,
        WM_ERASEBKGND
            | WM_PAINT
            | WM_SIZE
            | WM_RELAYOUT
            | WM_DPICHANGED
            | WM_MOUSEMOVE
            | WM_MOUSELEAVE
            | WM_SETCURSOR
            | WM_LBUTTONUP
            | WM_COMMAND
            | WM_NOTIFY
            | WM_CONTEXTMENU
            | WM_CTLCOLORSTATIC
            | WM_CTLCOLORBTN
            | WM_JOB_PROGRESS
            | WM_JOB_DONE
            | WM_BACKUPS_READY
            | WM_REDO
            | WM_MENU_PICKED
            | WM_SHORTCUT
            | WM_CLOSE
            | WM_QUERYENDSESSION
            | WM_ENDSESSION
            | WM_DESTROY
    )
}

#[derive(Debug, PartialEq, Eq)]
enum NestedReply {
    /// Answered here with 0; the deferred bit carries the real work.
    Handled,
    /// Also passed to DefWindowProcW.
    Default,
}

/// What a nested entry records for later, and how it answers now. Job and
/// close messages are answered without DefWindowProcW (whose WM_CLOSE default
/// would destroy the window behind our cleanup); a nested size or paint still
/// gets the default and is redone once the guard is free.
fn nested_reply(msg: u32) -> (u32, NestedReply) {
    match msg {
        WM_JOB_PROGRESS => (DEFER_PROGRESS, NestedReply::Handled),
        WM_JOB_DONE => (DEFER_DONE, NestedReply::Handled),
        WM_BACKUPS_READY => (DEFER_BACKUPS, NestedReply::Handled),
        WM_CLOSE => (DEFER_CLOSE, NestedReply::Handled),
        WM_SIZE | WM_DPICHANGED | WM_RELAYOUT => (DEFER_LAYOUT, NestedReply::Default),
        WM_PAINT => (DEFER_PAINT, NestedReply::Default),
        _ => (0, NestedReply::Default),
    }
}

/// The messages to re-post for a set of deferred bits, in delivery order.
/// Paint is not a message here: it is an invalidation.
fn deferred_messages(bits: u32) -> Vec<u32> {
    let mut out = Vec::new();
    if bits & DEFER_LAYOUT != 0 {
        out.push(WM_RELAYOUT);
    }
    if bits & DEFER_PROGRESS != 0 {
        out.push(WM_JOB_PROGRESS);
    }
    if bits & DEFER_DONE != 0 {
        out.push(WM_JOB_DONE);
    }
    if bits & DEFER_BACKUPS != 0 {
        out.push(WM_BACKUPS_READY);
    }
    if bits & DEFER_CLOSE != 0 {
        out.push(WM_CLOSE);
    }
    out
}

/// Re-post what nested entries deferred. Posting (rather than handling
/// here) means each message is dispatched later by a pump with no handler
/// active, so it takes the guard normally.
fn flush_deferred(hwnd: HWND) {
    let bits = DEFERRED.swap(0, Ordering::SeqCst);
    for message in deferred_messages(bits) {
        unsafe { PostMessageW(hwnd, message, 0, 0) };
    }
    if bits & DEFER_PAINT != 0 {
        unsafe { InvalidateRect(hwnd, std::ptr::null(), 0) };
    }
    run_native(hwnd);
}

/// Show queued native UI, one item at a time, with no handler active. Runs
/// only from flush_deferred, after the guard is released. A flush nested in
/// one of these modal loops leaves the queue to the loop already running.
/// The next queued native item. The queue's lock is released before this
/// returns: a modal call made with it held would leave any handler that runs
/// inside the dialog and queues a message waiting on it forever.
fn pop_native() -> Option<Native> {
    lock(&NATIVE).pop_front()
}

fn run_native(hwnd: HWND) {
    if SHOWING.swap(true, Ordering::SeqCst) {
        return;
    }
    let title = wide("Hivemend");
    while let Some(next) = pop_native() {
        if unsafe { IsWindow(hwnd) } == 0 {
            if let Native::Menu { menu, .. } = next {
                unsafe { DestroyMenu(menu as HMENU) };
            }
            continue;
        }
        match next {
            Native::Message { text, icon } => unsafe {
                MessageBoxW(hwnd, wide(&text).as_ptr(), title.as_ptr(), MB_OK | icon);
            },
            Native::Confirm { text, key, redo } => {
                let yes = unsafe {
                    MessageBoxW(
                        hwnd,
                        wide(&text).as_ptr(),
                        title.as_ptr(),
                        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
                    ) == IDYES
                };
                if yes {
                    lock(&REDO).push_back((redo, key));
                    unsafe { PostMessageW(hwnd, WM_REDO, 0, 0) };
                }
            }
            Native::Menu {
                menu,
                at,
                mut picked,
            } => {
                let choice = unsafe {
                    let choice = TrackPopupMenu(
                        menu as HMENU,
                        TPM_RETURNCMD | TPM_RIGHTBUTTON,
                        at.x,
                        at.y,
                        0,
                        hwnd,
                        std::ptr::null(),
                    );
                    DestroyMenu(menu as HMENU);
                    choice as usize
                };
                if choice != 0 {
                    picked.choice = choice;
                    lock(&PICKED).push_back(picked);
                    unsafe { PostMessageW(hwnd, WM_MENU_PICKED, 0, 0) };
                }
            }
            Native::Elevate => {
                let exe = wide(&exe_path().display().to_string());
                let result = unsafe {
                    ShellExecuteW(
                        hwnd,
                        wide("runas").as_ptr(),
                        exe.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        SW_SHOWNORMAL,
                    )
                };
                // Above 32 means the elevated copy started. Otherwise the
                // prompt was declined.
                if result as isize > 32 {
                    unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
                }
            }
            Native::Shell { file, args } => {
                let target = wide(&file);
                let params = args.as_deref().map(wide);
                let result = unsafe {
                    ShellExecuteW(
                        hwnd,
                        wide("open").as_ptr(),
                        target.as_ptr(),
                        params
                            .as_ref()
                            .map_or(std::ptr::null(), |params| params.as_ptr()),
                        std::ptr::null(),
                        SW_SHOWNORMAL,
                    )
                };
                // Values of 32 and below are errors; say so instead of
                // leaving it looking as if the program started.
                let code = result as isize;
                if code <= 32 {
                    let why = match code {
                        2 | 3 => "it was not found".to_string(),
                        5 => "access was denied".to_string(),
                        1223 => "it was canceled".to_string(),
                        other => format!("error {other}"),
                    };
                    let text = wide(&format!("Windows could not open {file}: {why}."));
                    unsafe {
                        MessageBoxW(hwnd, text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONWARNING);
                    }
                }
            }
        }
        unsafe { InvalidateRect(hwnd, std::ptr::null(), 0) };
    }
    SHOWING.store(false, Ordering::SeqCst);
}

fn window_app(hwnd: HWND) -> *mut App {
    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App }
}

struct HandlerGuard;

impl HandlerGuard {
    fn enter() -> Option<Self> {
        if IN_HANDLER.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(Self)
        }
    }
}

impl Drop for HandlerGuard {
    fn drop(&mut self) {
        IN_HANDLER.store(false, Ordering::SeqCst);
    }
}

impl App {
    fn new(hwnd: HWND) -> Self {
        let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
        let elevated = unsafe { IsUserAnAdmin() } != 0;
        // An administrator window takes no policy from the per-user folder,
        // which programs running without elevation can change: it starts
        // from the built-in settings (restore points on) and never saves.
        let settings = if elevated {
            Settings::default()
        } else {
            Settings::load(&settings_file())
        };
        let mut app = Self {
            hwnd,
            page: Page::Status,
            dpi,
            fonts: make_fonts(dpi),
            bg_brush: unsafe { CreateSolidBrush(BG) },
            art: HashMap::new(),
            corners: HashMap::new(),
            hotspots: Vec::new(),
            access: Vec::new(),
            access_shown: Vec::new(),
            texts: std::cell::RefCell::new(Vec::new()),
            text_ctls: Vec::new(),
            text_shown: Vec::new(),
            hover: None,
            tracking: false,
            elevated,
            settings,
            // An administrator window reads no per-user policy, the ignore
            // list included: programs running without elevation can change
            // that folder.
            exclusions: if elevated {
                Exclusions::default()
            } else {
                Exclusions::load(&exclusions_file())
            },
            // Read in the background once the window exists.
            backups: Vec::new(),
            backups_shown: 0,
            backups_failed: false,
            backup_errors: Vec::new(),
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
            chk_restore_point: std::ptr::null_mut(),
            startup_items: Vec::new(),
            startup_loaded: false,
            startup_note: String::new(),
            startup_list: std::ptr::null_mut(),
            btn_su_enable: std::ptr::null_mut(),
            btn_su_disable: std::ptr::null_mut(),
            btn_su_open: std::ptr::null_mut(),
            btn_su_refresh: std::ptr::null_mut(),
            programs: Vec::new(),
            programs_loaded: false,
            programs_note: String::new(),
            left_alone: Vec::new(),
            last_info: 0,
            programs_list: std::ptr::null_mut(),
            btn_pg_uninstall: std::ptr::null_mut(),
            btn_pg_open: std::ptr::null_mut(),
            btn_pg_refresh: std::ptr::null_mut(),
            disk_roots: Vec::new(),
            disk_report: None,
            disk_root: None,
            disk_at: 0,
            disk_view: DiskView::Folders,
            disk_rows: Vec::new(),
            disk_note: String::new(),
            disk_list: std::ptr::null_mut(),
            btn_ds_up: std::ptr::null_mut(),
            btn_ds_open: std::ptr::null_mut(),
            dup_report: None,
            dup_root: None,
            dup_rows: Vec::new(),
            dup_checked: Vec::new(),
            dup_filling: false,
            dup_note: String::new(),
            dup_list: std::ptr::null_mut(),
            btn_dup_extras: std::ptr::null_mut(),
            btn_dup_none: std::ptr::null_mut(),
            btn_dup_recycle: std::ptr::null_mut(),
            btn_dup_open: std::ptr::null_mut(),
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
            btn_priv_keep: std::ptr::null_mut(),
            priv_keep_stamp: None,
            btn_priv_clean: std::ptr::null_mut(),
        };
        app.create_controls();
        app
    }

    fn create_controls(&mut self) {
        let hwnd = self.hwnd;
        // Created first, so the Tab order starts with them: the sidebar,
        // then the page's drawn buttons, then its ordinary controls.
        self.access = (0..ACCESS_POOL)
            .map(|i| stand_in(hwnd, "BUTTON", ID_ACCESS_BASE + i as u16, true))
            .collect();
        self.access_shown = vec![None; ACCESS_POOL];
        self.text_ctls = (0..TEXT_POOL)
            .map(|i| stand_in(hwnd, "STATIC", ID_TEXT_BASE + i as u16, false))
            .collect();
        self.text_shown = vec![None; TEXT_POOL];
        self.list = list_view(
            hwnd,
            ID_FINDINGS,
            0,
            LVS_EX_CHECKBOXES,
            &[
                ("Category", 124),
                ("Problem", 320),
                ("Location", 360),
                ("Fix", 160),
            ],
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
        self.startup_list = list_view(
            hwnd,
            ID_SU_LIST,
            0,
            0,
            &[
                ("Name", 220),
                ("Status", 90),
                ("For", 110),
                ("Command", 420),
            ],
        );
        self.btn_su_enable = button(hwnd, ID_SU_ENABLE, "Enable", BS_PUSHBUTTON);
        self.btn_su_disable = button(hwnd, ID_SU_DISABLE, "Disable", BS_PUSHBUTTON);
        self.btn_su_open = button(hwnd, ID_SU_OPEN, "Open File Location", BS_PUSHBUTTON);
        self.btn_su_refresh = button(hwnd, ID_SU_REFRESH, "Refresh", BS_PUSHBUTTON);
        self.programs_list = list_view(
            hwnd,
            ID_PG_LIST,
            LVS_SINGLESEL,
            0,
            &[
                ("Name", 260),
                ("Publisher", 180),
                ("Installed", 95),
                ("Size", 80),
                ("Version", 120),
            ],
        );
        self.btn_pg_uninstall = button(hwnd, ID_PG_UNINSTALL, "Uninstall", BS_PUSHBUTTON);
        self.btn_pg_open = button(hwnd, ID_PG_OPEN, "Open Install Folder", BS_PUSHBUTTON);
        self.btn_pg_refresh = button(hwnd, ID_PG_REFRESH, "Refresh", BS_PUSHBUTTON);
        self.disk_list = list_view(
            hwnd,
            ID_DS_LIST,
            LVS_SINGLESEL,
            0,
            &[("Name", 380), ("Size", 100), ("Share", 80), ("Files", 100)],
        );
        self.btn_ds_up = button(hwnd, ID_DS_UP, "Up One Level", BS_PUSHBUTTON);
        self.btn_ds_open = button(hwnd, ID_DS_OPEN, "Open in Explorer", BS_PUSHBUTTON);
        self.dup_list = list_view(
            hwnd,
            ID_DUP_LIST,
            0,
            LVS_EX_CHECKBOXES,
            &[("Name", 240), ("Folder", 380), ("Size", 90), ("Set", 70)],
        );
        self.btn_dup_extras = button(hwnd, ID_DUP_EXTRAS, "Tick Extra Copies", BS_PUSHBUTTON);
        self.btn_dup_none = button(hwnd, ID_DUP_NONE, "Untick All", BS_PUSHBUTTON);
        self.btn_dup_recycle = button(
            hwnd,
            ID_DUP_RECYCLE,
            "Move Ticked to Recycle Bin",
            BS_PUSHBUTTON,
        );
        self.btn_dup_open = button(hwnd, ID_DUP_OPEN, "Open Folder", BS_PUSHBUTTON);
        self.chk_restore_point = button(
            hwnd,
            ID_RESTORE_POINT,
            "Create a Windows restore point before repairs (needs administrator rights)",
            BS_AUTOCHECKBOX,
        );
        unsafe {
            SendMessageW(
                self.chk_restore_point,
                BM_SETCHECK,
                (!self.settings.skip_restore_point) as usize,
                0,
            )
        };
        self.ignored_list = list_view(hwnd, ID_IGNORED, 0, 0, &[("Ignored entry", 700)]);
        self.btn_unignore = button(
            hwnd,
            ID_UNIGNORE,
            "Stop Ignoring Highlighted",
            BS_PUSHBUTTON,
        );

        self.svc_list = list_view(
            hwnd,
            ID_SVC_LIST,
            0,
            0,
            &[
                ("Service", 300),
                ("Status", 110),
                ("Startup", 150),
                ("Name", 220),
            ],
        );
        self.svc_tune_list = list_view(
            hwnd,
            ID_SVC_TUNE,
            0,
            LVS_EX_CHECKBOXES,
            &[
                ("Service", 240),
                ("Now", 150),
                ("Change to", 130),
                ("Why", 300),
            ],
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
        self.btn_priv_keep = button(hwnd, ID_PRIV_KEEP, "Cookies to Keep", BS_PUSHBUTTON);
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
            self.btn_priv_keep,
            self.btn_priv_clean,
        ];
        all.extend(self.scanner_boxes.iter().map(|(_, hwnd)| *hwnd));
        all.push(self.chk_restore_point);
        all.extend([
            self.startup_list,
            self.btn_su_enable,
            self.btn_su_disable,
            self.btn_su_open,
            self.btn_su_refresh,
            self.programs_list,
            self.btn_pg_uninstall,
            self.btn_pg_open,
            self.btn_pg_refresh,
            self.disk_list,
            self.btn_ds_up,
            self.btn_ds_open,
            self.dup_list,
            self.btn_dup_extras,
            self.btn_dup_none,
            self.btn_dup_recycle,
            self.btn_dup_open,
        ]);
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

    /// Draw `icon` `size` pixels square at (x, y), rendering it once per size.
    fn draw_icon(&mut self, hdc: HDC, icon: Icon, x: i32, y: i32, size: i32) {
        if size <= 0 {
            return;
        }
        let bitmap = *self.art.entry((icon, size)).or_insert_with(|| unsafe {
            dib(
                &hive_mend::art::render_bgra_premultiplied(icon, size as usize),
                size,
            )
        });
        if !bitmap.is_null() {
            unsafe { alpha_blit(hdc, bitmap, x, y, size) };
        }
    }

    fn release(self) {
        for bitmap in self.art.values().chain(self.corners.values()) {
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

    /// A job that changes the system and must not be cut off: closing,
    /// signing out, and an installer's upgrade all wait for it.
    fn must_finish(&self) -> bool {
        matches!(
            self.job,
            Job::Repairing | Job::Restoring | Job::Services | Job::Cleaning | Job::Recycling
        )
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
            Action::DiskRoot(index) => self.start_disk(index),
            Action::DupRoot(index) => self.start_dups(index),
            Action::DiskView(view) => {
                if self.busy() {
                    return;
                }
                self.disk_view = view;
                self.fill_disk();
                self.sync_controls();
                self.invalidate();
            }
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

    /// Open a built-in Windows screen. Hivemend only launches it.
    fn open_tool(&self, index: usize) {
        if self.busy() {
            return;
        }
        let Some(tool) = WINDOWS_TOOLS.get(index) else {
            return;
        };
        // The Windows folder from the API, not %SystemRoot%, so the intended
        // native tool opens. Without it, a path-based tool is not launched.
        let root = hive_mend::host_known_dir(hive_mend::KnownDir::Windows);
        let target = match root {
            Some(root) => expand_target(tool.target, &root),
            None if !tool.target.to_ascii_lowercase().contains("%systemroot%") => {
                tool.target.to_string()
            }
            None => {
                self.message("Could not locate the Windows folder.", MB_ICONWARNING);
                return;
            }
        };
        shell_open(self.hwnd, &target, None);
    }

    fn go(&mut self, page: Page) {
        self.page = page;
        if matches!(page, Page::Restore | Page::Status | Page::Monitor) && !self.busy() {
            self.refresh_backups();
        }
        if page == Page::Startup && !self.startup_loaded {
            self.refresh_startup();
        }
        if page == Page::Programs && !self.busy() {
            // Every visit: an uninstaller may have finished since.
            self.refresh_programs();
        }
        if matches!(page, Page::DiskSpace | Page::Duplicates) && self.disk_roots.is_empty() {
            self.disk_roots = disk_roots();
        }
        if page == Page::Services && !self.svc_loaded {
            self.refresh_services();
        }
        // An administrator window never looks at the keep list, not even
        // its timestamp: its Privacy page does not depend on that file.
        if page == Page::Privacy
            && !self.busy()
            && (self.priv_items.is_empty()
                || (!self.elevated && self.priv_keep_stamp != keep_list_stamp()))
        {
            self.rebuild_privacy();
        }
        self.sync_controls();
        self.invalidate();
    }

    fn command(&mut self, id: u16, code: u16) {
        const BN_CLICKED: u16 = 0;
        if (ID_ACCESS_BASE..ID_ACCESS_BASE + ACCESS_POOL as u16).contains(&id) {
            let index = (id - ID_ACCESS_BASE) as usize;
            match code as u32 {
                BN_SETFOCUS | BN_KILLFOCUS => self.invalidate(),
                _ if code == BN_CLICKED && self.spot_enabled(index) => {
                    let action = self.hotspots[index].action;
                    self.perform(action);
                }
                _ => {}
            }
            return;
        }
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
        if id == ID_RESTORE_POINT {
            if code == BN_CLICKED {
                let on = unsafe { SendMessageW(self.chk_restore_point, BM_GETCHECK, 0, 0) } == 1;
                self.settings.skip_restore_point = !on;
                self.save_settings();
            }
            return;
        }
        match id {
            ID_SU_ENABLE => {
                let rows = selected_rows(self.startup_list);
                self.toggle_startup(&rows, true);
                return;
            }
            ID_SU_DISABLE => {
                let rows = selected_rows(self.startup_list);
                self.toggle_startup(&rows, false);
                return;
            }
            ID_SU_OPEN => {
                self.open_startup_location();
                return;
            }
            ID_SU_REFRESH => {
                self.refresh_startup();
                self.invalidate();
                return;
            }
            ID_PG_UNINSTALL => {
                let rows = selected_rows(self.programs_list);
                self.uninstall_program(&rows);
                return;
            }
            ID_PG_OPEN => {
                self.open_program_folder();
                return;
            }
            ID_DS_UP => {
                if let Some(parent) = self
                    .disk_report
                    .as_ref()
                    .and_then(|report| report.nodes.get(self.disk_at))
                    .and_then(|node| node.parent)
                {
                    self.disk_at = parent;
                    self.disk_view = DiskView::Folders;
                    self.fill_disk();
                    self.sync_controls();
                    self.invalidate();
                }
                return;
            }
            ID_DS_OPEN => {
                self.open_disk_row();
                return;
            }
            ID_DUP_EXTRAS => {
                self.dup_tick(true);
                return;
            }
            ID_DUP_NONE => {
                self.dup_tick(false);
                return;
            }
            ID_DUP_RECYCLE => {
                self.recycle_ticked();
                return;
            }
            ID_DUP_OPEN => {
                self.open_dup_row();
                return;
            }
            // Enter, which IsDialogMessage turns into IDOK.
            IDOK if self.page == Page::DiskSpace && unsafe { GetFocus() } == self.disk_list => {
                self.open_disk_selection();
                return;
            }
            ID_PG_REFRESH => {
                self.refresh_programs();
                self.invalidate();
                return;
            }
            _ => {}
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
                } else if self.job == Job::Cleaning
                    || self.job == Job::Analyzing
                    || self.job == Job::Finding
                    || self.job == Job::Previewing
                {
                    CANCEL.store(true, Ordering::SeqCst);
                    progress_text("Stopping...");
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
            ID_OPEN_BACKUPS => match backups_dir() {
                Ok(dir) => shell_open(self.hwnd, &dir.display().to_string(), None),
                Err(err) => self.message(&err, MB_ICONWARNING),
            },
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
            ID_PRIV_KEEP => self.edit_cookie_keep(),
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
                        let fixed = self.findings.get(row).is_some_and(|f| !self.offered(f));
                        // Report-only and left-alone rows have no check box
                        // and stay that way.
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
        } else if id == ID_DS_LIST && header.code == LVN_KEYDOWN {
            // Backspace goes up a level, as in Explorer.
            let key = unsafe { &*(lparam as *const NMLVKEYDOWN) };
            if { key.wVKey } == 0x08 {
                self.command(ID_DS_UP, 0);
            }
        } else if id == ID_DS_LIST && matches!(header.code, NM_DBLCLK | NM_RETURN) {
            self.open_disk_selection();
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
        } else if id == ID_DUP_LIST {
            match header.code {
                LVN_ITEMCHANGING => {
                    let change = unsafe { &*(lparam as *const NMLISTVIEW) };
                    if !self.dup_filling && change.uChanged & LVIF_STATE != 0 {
                        let new = (change.uNewState & LVIS_STATEIMAGEMASK) >> 12;
                        let old = (change.uOldState & LVIS_STATEIMAGEMASK) >> 12;
                        if new != old && self.busy() {
                            return 1;
                        }
                    }
                }
                LVN_ITEMCHANGED => {
                    let change = unsafe { &*(lparam as *const NMLISTVIEW) };
                    if !self.dup_filling && change.uChanged & LVIF_STATE != 0 {
                        let new = (change.uNewState & LVIS_STATEIMAGEMASK) >> 12;
                        let old = (change.uOldState & LVIS_STATEIMAGEMASK) >> 12;
                        if new != old
                            && let Some(slot) = self.dup_checked.get_mut(change.iItem as usize)
                        {
                            *slot = new == 2;
                            self.update_dup_label();
                        }
                    }
                }
                NM_DBLCLK => self.open_dup_row(),
                _ => {}
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
        let engine = match Engine::try_builtin() {
            Ok(engine) => engine,
            Err(err) => {
                self.message(
                    &format!("Could not load the scanner rules: {err}"),
                    MB_ICONWARNING,
                );
                return;
            }
        };
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
                &engine,
                &WindowsRegistry,
                &HostFs,
                &opts,
                &mut |step, total, name| {
                    if !name.is_empty() {
                        set_progress(
                            step,
                            total,
                            &format!("Checking {name}  ({} of {total})", step + 1),
                        );
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
        self.left_alone = report
            .findings
            .iter()
            .filter_map(|finding| {
                hive_mend::left_alone_here(&WindowsRegistry, finding, self.elevated)
                    .map(|why| (finding.clone(), why))
            })
            .collect();
        report
            .findings
            .sort_by_key(|finding| self.row_rank(finding));
        self.findings = report.findings;
        self.scanned = true;
        self.scope = scope;
        self.fill_findings();
        self.settings.last_scan = local_now();
        let (problems, info) = self.finding_counts();
        self.settings.last_problems = Some(problems);
        self.last_info = info;
        self.save_settings();
        let mut note = if problems == 0 {
            format!("Nothing to fix ({seconds:.1} s).")
        } else {
            format!("{problems} problems found ({seconds:.1} s).")
        };
        if info > 0 {
            note.push_str(&format!(
                " {info} more are listed at the end for information only."
            ));
        }
        let normal = self.normal_window_count();
        if normal > 0 {
            note.push_str(&format!(
                " {normal} are in your own part of the registry: fix them from Hivemend started without administrator rights."
            ));
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
            note.push_str(&format!(
                " {} keys could not be read.",
                report.warnings.len()
            ));
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
                let image = if !self.offered(finding) {
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
        self.offered(finding) && !finding.permanent() && (self.elevated || !finding.needs_admin())
    }

    /// Why this window leaves `finding` alone, if it does.
    fn left_alone_why(&self, finding: &Finding) -> Option<&LeftAlone> {
        self.left_alone
            .iter()
            .find(|(held, _)| held == finding)
            .map(|(_, why)| why)
    }

    /// Offered for repair here: it has a check box.
    fn offered(&self, finding: &Finding) -> bool {
        finding.repairable() && self.left_alone_why(finding).is_none()
    }

    /// Rows that can be fixed come first, then those to fix from a normal
    /// window, then the ones listed for information only.
    fn row_rank(&self, finding: &Finding) -> u8 {
        match self.left_alone_why(finding) {
            _ if !finding.repairable() => 3,
            None => 0,
            Some(LeftAlone::NormalWindow) => 1,
            Some(LeftAlone::Protected(_)) => 2,
        }
    }

    /// (problems, information only). A protected or report-only finding is
    /// not a problem anyone can fix, so it is never counted as one; an entry
    /// left to a normal window still is.
    fn finding_counts(&self) -> (usize, usize) {
        let info = self
            .findings
            .iter()
            .filter(|finding| {
                !finding.repairable()
                    || matches!(self.left_alone_why(finding), Some(LeftAlone::Protected(_)))
            })
            .count();
        (self.findings.len() - info, info)
    }

    fn normal_window_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| {
                finding.repairable()
                    && matches!(self.left_alone_why(finding), Some(LeftAlone::NormalWindow))
            })
            .count()
    }

    fn fix_label(&self, finding: &Finding) -> String {
        match self.left_alone_why(finding) {
            _ if !finding.repairable() => {}
            Some(LeftAlone::NormalWindow) => {
                return "Fix from Hivemend without administrator rights".into();
            }
            Some(LeftAlone::Protected(_)) => return "Protected, left alone (information)".into(),
            None => {}
        }
        let mut label = match &finding.repair {
            Repair::None => return "Report only (information)".into(),
            Repair::DeleteValue { .. } => "Delete value".to_string(),
            Repair::DeleteKey { .. } => "Delete key".to_string(),
            Repair::DeleteFile {
                keep_copy: true, ..
            } => "Move shortcut into backup".to_string(),
            Repair::DeleteFile {
                keep_copy: false, ..
            } => "Delete file (no undo)".to_string(),
        };
        if !self.elevated && finding.needs_admin() {
            label.push_str(", needs admin");
        }
        label
    }

    fn tick_all(&mut self, on: bool) {
        self.filling_list = true;
        for (row, finding) in self.findings.iter().enumerate() {
            if !self.offered(finding) {
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
            .filter(|(finding, on)| **on && self.offered(finding))
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
        if self.elevated {
            self.message(
                "The ignore list is changed from Hivemend started without administrator rights. An administrator window does not write to your per-user folder.",
                MB_ICONINFORMATION,
            );
            return;
        }
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
        if !self.confirm(&question, Redo::IgnoreRows(rows.to_vec())) {
            return;
        }
        for row in rows {
            if let Some(finding) = self.findings.get(*row) {
                self.exclusions.add(finding);
            }
        }
        if let Err(err) = self.exclusions.save(&exclusions_file()) {
            self.message(
                &format!("Could not save the ignore list: {err}"),
                MB_ICONWARNING,
            );
        }
        self.drop_rows(rows);
        self.fill_ignored();
    }

    /// Remove rows from the results, keeping the other rows' ticks.
    fn drop_rows(&mut self, rows: &[usize]) {
        let mut keep_findings = Vec::new();
        let mut keep_ticks = Vec::new();
        for (row, (finding, tick)) in self
            .findings
            .drain(..)
            .zip(self.checked.drain(..))
            .enumerate()
        {
            if !rows.contains(&row) {
                keep_findings.push(finding);
                keep_ticks.push(tick);
            }
        }
        // Rows a repair just refused move down with the information rows.
        let mut kept: Vec<(Finding, bool)> = keep_findings.into_iter().zip(keep_ticks).collect();
        kept.sort_by_key(|(finding, _)| self.row_rank(finding));
        let (findings, ticks): (Vec<Finding>, Vec<bool>) = kept.into_iter().unzip();
        self.findings = findings;
        self.fill_findings();
        self.filling_list = true;
        for (row, tick) in ticks.into_iter().enumerate() {
            if self.offered(&self.findings[row]) {
                self.checked[row] = tick;
                set_state_image(self.list, row, if tick { 2 } else { 1 });
            }
        }
        self.filling_list = false;
        self.update_repair_label();
        let (problems, info) = self.finding_counts();
        self.settings.last_problems = Some(problems);
        self.last_info = info;
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
                SendMessageW(
                    self.list,
                    LVM_GETITEMRECT,
                    rows[0],
                    &mut rect as *mut _ as isize,
                );
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
        let menu = unsafe {
            let menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, MENU_DETAILS, wide("Details...").as_ptr());
            AppendMenuW(menu, MF_STRING, MENU_COPY, wide("Copy location").as_ptr());
            let show = if is_file {
                "Show in File Explorer"
            } else {
                "Show in Registry Editor"
            };
            AppendMenuW(menu, MF_STRING, MENU_SHOW, wide(show).as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
            AppendMenuW(menu, MF_STRING, MENU_IGNORE, wide(&ignore_label).as_ptr());
            if lparam != -1 {
                GetCursorPos(&mut at);
            }
            menu
        };
        // Shown by run_native after this handler returns; the choice comes
        // back as WM_MENU_PICKED and applies only to the same items.
        let identity = self.menu_identity(MenuKind::Findings, &rows);
        lock(&NATIVE).push_back(Native::Menu {
            menu: menu as isize,
            at,
            picked: Picked {
                kind: MenuKind::Findings,
                rows,
                identity,
                choice: 0,
            },
        });
    }

    fn findings_choice(&mut self, rows: &[usize], choice: usize) {
        let Some(first) = rows.first().and_then(|row| self.findings.get(*row)) else {
            return;
        };
        let is_file = matches!(first.repair, Repair::DeleteFile { .. });
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
                    open_in_regedit(self.hwnd, &finding.key, self.elevated);
                }
            }
            MENU_IGNORE => self.ignore_rows(rows),
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
        let Some(mut backup) = next_services_backup_file() else {
            self.message(
                "Could not reserve a backup file in the backups folder. Nothing was changed.",
                MB_ICONWARNING,
            );
            return;
        };
        let mut question = format!(
            "Set {} to start on demand (Manual)?\n\nHivemend saves the current start types in\n{}\nbefore changing anything. You can undo this on the Restore page. Each change takes full effect when the service next starts.",
            if selected.len() == 1 {
                format!(
                    "{} ({})",
                    selected[0].display_name,
                    selected[0].from.label()
                )
            } else {
                format!("these {} services", selected.len())
            },
            backup
                .path()
                .parent()
                .map(|dir| dir.display().to_string())
                .unwrap_or_default()
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
        if !self.confirm(&question, Redo::ServicesApply) {
            backup.discard();
            return;
        }
        self.job = Job::Services;
        set_progress(
            0,
            selected.len().max(1),
            "Saving the current start types...",
        );
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let outcome = apply_start_changes(
                &mut ScmServiceStore,
                &WindowsRegistry,
                &selected,
                &mut backup,
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
            // names[0] was just cloned from this list, so the lookup only
            // misses if the impossible happens; fall back to the bare name
            // rather than panic across the window procedure.
            let display = self
                .services
                .iter()
                .find(|info| info.name == names[0])
                .map(|info| info.display_name.clone())
                .unwrap_or_else(|| names[0].clone());
            format!(
                "{verb} {}?\n\nIt {} now and keeps its startup type{}.",
                display,
                if start { "starts" } else { "stops" },
                if start {
                    "."
                } else {
                    ". You can start it again here."
                }
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
        if !self.confirm(&question, Redo::PowerRows(rows.to_vec(), start)) {
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
                    set_progress(
                        done,
                        total,
                        &format!("Starting services ({done} of {total})..."),
                    );
                    post(hwnd, WM_JOB_PROGRESS);
                })
            } else {
                stop_services(&mut ScmServiceStore, &names, &mut |done, total| {
                    set_progress(
                        done,
                        total,
                        &format!("Stopping services ({done} of {total})..."),
                    );
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
        let Some(mut backup) = next_services_backup_file() else {
            self.message(
                "Could not reserve a backup file in the backups folder. Nothing was changed.",
                MB_ICONWARNING,
            );
            return;
        };
        let mut question = format!(
            "Set {} to {}?\n\nHivemend saves the current start types in\n{}\nbefore changing anything. You can undo this on the Restore page.",
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
            backup
                .path()
                .parent()
                .map(|dir| dir.display().to_string())
                .unwrap_or_default()
        );
        if to == StartType::Disabled {
            question.push_str("\n\nDisabled means Windows cannot start it at all, even on demand. Prefer Manual unless you are sure.");
        }
        if !self.confirm(&question, Redo::SetRows(rows.to_vec(), to)) {
            backup.discard();
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
                &mut backup,
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
                self.message(&format!("Nothing was changed.\n\n{err}"), MB_ICONWARNING);
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
                        for pending in outcome.unconfirmed.iter().take(5) {
                            lines.push(format!("Not confirmed: {pending}"));
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
                            lines.push(format!("Backup: {}", outcome.backup_file.display()));
                        }
                        self.svc_note = if outcome.applied.is_empty()
                            && outcome.errors.is_empty()
                            && outcome.unconfirmed.is_empty()
                        {
                            "Nothing needed changing.".to_string()
                        } else {
                            format!(
                                "Applied {}, refused {}, failed {}, not confirmed {}.",
                                outcome.applied.len(),
                                outcome.refused.len() + outcome.not_backed_up.len(),
                                outcome.errors.len() + outcome.denied,
                                outcome.unconfirmed.len()
                            )
                        };
                        let icon = if outcome.applied.is_empty()
                            && (outcome.denied > 0
                                || !outcome.errors.is_empty()
                                || !outcome.unconfirmed.is_empty())
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
        let ticked = self.settings.privacy_ticked.clone();
        let (items, checked, stamp) = privacy_plan(self.elevated, &mut PolicyOnDisk, &ticked);
        self.priv_keep_stamp = stamp;
        self.priv_checked = checked;
        self.priv_items = items;
        self.priv_preview = None;
        self.priv_outcome = None;
        self.fill_privacy();
    }

    /// Open the cookies-to-keep list in Notepad, creating it with help text.
    fn edit_cookie_keep(&mut self) {
        if self.elevated {
            self.message(
                "Edit your cookies-to-keep list from Hivemend started without administrator rights. An administrator window does not write to your per-user folder.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let file = hive_mend::cookies_keep_file();
        if !file.exists() {
            if let Some(parent) = file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let help = "# Cookies to keep: one site per line, such as github.com.\r\n# Its subdomains are kept too. Every other cookie is removed when\r\n# you clean a browser's cookies. Save, then go back to\r\n# Hivemend's Privacy page.\r\n";
            if let Err(err) = std::fs::write(&file, help) {
                self.message(
                    &format!("Could not create {}: {err}", file.display()),
                    MB_ICONWARNING,
                );
                return;
            }
        }
        let Some(system) = hive_mend::host_known_dir(hive_mend::KnownDir::System) else {
            self.message("Could not locate Notepad.", MB_ICONWARNING);
            return;
        };
        let notepad = format!(r"{system}\notepad.exe");
        shell_open(
            self.hwnd,
            &notepad,
            Some(&format!("\"{}\"", file.display())),
        );
    }

    fn save_priv_ticks(&mut self) {
        // An elevated window never stores ticks for the per-user settings,
        // so it cannot change what a later window starts with.
        if self.elevated {
            return;
        }
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
        // Counting can walk large folders: do it off the window's thread so
        // the window stays responsive.
        self.job = Job::Previewing;
        CANCEL.store(false, Ordering::SeqCst);
        self.priv_preview = None;
        self.priv_note = "Counting what each category holds...".to_string();
        set_progress(0, 0, "Counting what each category holds...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let items = self.priv_items.clone();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let report = preview_with(
                &WindowsRegistry,
                &HostFs,
                &WindowsSystemTargets,
                &WindowsProcessList,
                &items,
                &mut || !CANCEL.load(Ordering::SeqCst),
            );
            finish_job(hwnd, JobResult::PrivacyPreview { report });
        });
    }

    fn finish_priv_preview(&mut self, report: Preview) {
        if report.canceled {
            // A partial count is not a preview: Clean stays unavailable.
            self.priv_preview = None;
            self.priv_note = "Preview canceled. Preview again before cleaning.".to_string();
            self.sync_controls();
            self.fill_privacy();
            self.invalidate();
            return;
        }
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
        let row = self
            .priv_preview
            .as_ref()?
            .items
            .iter()
            .find(|row| row.id == id)?;
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
        if row.cookies > 0 {
            parts.push(count(row.cookies, "cookie", "cookies"));
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
                let detail = if extra.is_empty() {
                    item.detail.clone()
                } else {
                    extra
                };
                insert_row(self.priv_list, row, &[&item.name, &holds, &detail]);
                set_state_image(
                    self.priv_list,
                    row,
                    if self.priv_checked.get(row).copied().unwrap_or(false) {
                        2
                    } else {
                        1
                    },
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
        unsafe {
            EnableWindow(
                self.btn_priv_clean,
                (count > 0 && ready && !self.busy()) as i32,
            )
        };
    }

    fn start_privacy_clean(&mut self) {
        if self.busy() {
            return;
        }
        let selected = self.priv_ticked();
        if selected.is_empty() {
            self.message(
                "Tick the categories you want to clean first.",
                MB_ICONINFORMATION,
            );
            return;
        }
        if self.priv_preview.is_none() {
            self.message(
                "Preview first, so you can see what each category holds.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let Some(mut backup) = next_privacy_backup_file() else {
            self.message(
                "Could not reserve a backup file in the backups folder. Nothing was changed.",
                MB_ICONWARNING,
            );
            return;
        };
        let mut question = format!(
            "Clean {} {}?\n\nHivemend saves the registry entries in\n{}\nbefore removing anything. You can undo those on the Restore page. Files (temp, caches, bin contents) are deleted for good and are not backed up. On SSDs the drive clears deleted files itself; for stronger protection, turn on BitLocker or Device Encryption.",
            selected.len(),
            if selected.len() == 1 {
                "category"
            } else {
                "categories"
            },
            backup
                .path()
                .parent()
                .map(|dir| dir.display().to_string())
                .unwrap_or_default()
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
        if !self.confirm(&question, Redo::PrivacyClean) {
            backup.discard();
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
                &mut backup,
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
                let cookies: usize = outcome.items.iter().map(|item| item.cookies).sum();
                if cookies > 0 {
                    lines.push(format!(
                        "Removed {} and kept the ones for sites on your list.",
                        count(cookies, "cookie", "cookies")
                    ));
                }
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
                let icon = if outcome.errors.is_empty() {
                    MB_ICONINFORMATION
                } else {
                    MB_ICONWARNING
                };
                self.priv_outcome = Some(outcome);
                self.message(&lines.join("\n"), icon);
                // Count again in the background, as Preview does.
                self.priv_preview = None;
                self.fill_privacy();
                self.run_priv_preview();
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
            parts.push(format!(
                "{} files ({})",
                item.files,
                format_bytes(item.bytes)
            ));
        }
        if item.values > 0 {
            parts.push(count(item.values, "value", "values"));
        }
        if item.other > 0 {
            parts.push(count(item.other, "item", "items"));
        }
        if item.cookies > 0 {
            parts.push(count(item.cookies, "cookie", "cookies"));
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
        let Some(item) = self.priv_items.get(row) else {
            return;
        };
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

    // ---- startup -------------------------------------------------------

    fn refresh_startup(&mut self) {
        self.startup_items = hive_mend::list_startup(&WindowsRegistry, &HostFs);
        self.startup_loaded = true;
        let off = self
            .startup_items
            .iter()
            .filter(|item| !item.enabled)
            .count();
        self.startup_note = format!(
            "{} programs start with Windows; {off} turned off.",
            self.startup_items.len() - off
        );
        unsafe {
            SendMessageW(self.startup_list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.startup_list, LVM_DELETEALLITEMS, 0, 0);
        }
        for (row, item) in self.startup_items.iter().enumerate() {
            insert_row(
                self.startup_list,
                row,
                &[
                    &item.name,
                    if item.enabled { "Enabled" } else { "Disabled" },
                    item.scope.label(),
                    &item.command,
                ],
            );
        }
        unsafe {
            SendMessageW(self.startup_list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.startup_list, std::ptr::null(), 1);
        }
    }

    /// Turn the highlighted startup items on or off, after a confirmation and
    /// a backup of their current flags.
    fn toggle_startup(&mut self, rows: &[usize], enable: bool) {
        if self.busy() {
            return;
        }
        let picked: Vec<hive_mend::StartupItem> = rows
            .iter()
            .filter_map(|row| self.startup_items.get(*row).cloned())
            .collect();
        if picked.is_empty() {
            self.message(
                "Highlight one or more startup items first.",
                MB_ICONINFORMATION,
            );
            return;
        }
        // Your own items are changed from a normal window: an administrator
        // window does not write into your hive, which programs running
        // without elevation can redirect.
        if self.elevated
            && picked
                .iter()
                .any(|item| item.scope == hive_mend::StartupScope::User)
        {
            self.message(
                "Items for your account are changed from Hivemend started without administrator rights. Highlight only items for all users here.",
                MB_ICONINFORMATION,
            );
            return;
        }
        if !self.elevated
            && picked
                .iter()
                .any(|item| item.scope == hive_mend::StartupScope::Machine)
        {
            self.message(
                "Items that start for all users can only be changed with administrator rights. Use Run as administrator, or highlight only your own items.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let changing = picked.iter().filter(|item| item.enabled != enable).count();
        if changing == 0 {
            self.message(
                if enable {
                    "Those items are already enabled."
                } else {
                    "Those items are already disabled."
                },
                MB_ICONINFORMATION,
            );
            return;
        }
        let verb = if enable { "Enable" } else { "Disable" };
        let question = format!(
            "{verb} {changing} startup {}?\n\n{}Hivemend saves the current settings in\n{}\nfirst, so this can be undone on the Restore page.",
            if changing == 1 { "item" } else { "items" },
            if enable {
                ""
            } else {
                "Disabled items stay installed; they just stop starting with Windows, the same switch Task Manager uses. "
            },
            backups_location()
                .map(|dir| dir.display().to_string())
                .unwrap_or_default()
        );
        if !self.confirm(&question, Redo::Startup(rows.to_vec(), enable)) {
            return;
        }
        let Some(mut backup) = next_backup_file_with("startup") else {
            self.message(
                "Could not reserve a backup file in the backups folder. Nothing was changed.",
                MB_ICONWARNING,
            );
            return;
        };
        let refs: Vec<&hive_mend::StartupItem> = picked.iter().collect();
        let (body, refused) = hive_mend::startup_backup(&WindowsRegistry, &refs);
        if let Err(err) = backup.append(&body) {
            self.message(
                &format!("The backup could not be written, so nothing was changed.\n\n{err}"),
                MB_ICONWARNING,
            );
            return;
        }
        let outcome = hive_mend::set_startup(
            &mut WindowsRegistry,
            &refs,
            enable,
            hive_mend::filetime_now(),
            &refused,
        );
        let mut lines = vec![format!(
            "{} {}.",
            if enable { "Enabled:" } else { "Disabled:" },
            outcome.changed
        )];
        if !refused.is_empty() {
            lines.push(format!(
                "Left alone (its current setting could not be recorded): {}",
                refused.join(", ")
            ));
        }
        for error in outcome.errors.iter().take(5) {
            lines.push(format!("Failed: {error}"));
        }
        lines.push(format!("Backup: {}", backup.path().display()));
        self.refresh_startup();
        self.refresh_backups();
        self.message(
            &lines.join("\n"),
            if outcome.errors.is_empty() {
                MB_ICONINFORMATION
            } else {
                MB_ICONWARNING
            },
        );
    }

    fn open_startup_location(&mut self) {
        let Some(item) = selected_rows(self.startup_list)
            .first()
            .and_then(|row| self.startup_items.get(*row))
            .cloned()
        else {
            self.message("Highlight a startup item first.", MB_ICONINFORMATION);
            return;
        };
        // The program it starts, or the shortcut itself when the target is
        // not a plain path.
        let target = hive_mend::paths_in_command(&item.command)
            .into_iter()
            .next()
            .filter(|path| path.as_bytes().get(1) == Some(&b':'))
            .unwrap_or_else(|| format!(r"{}\{}", item.location, item.name));
        if target.starts_with("HKEY_") {
            open_in_regedit(self.hwnd, &item.location, self.elevated);
        } else {
            let arg = format!("/select,\"{target}\"");
            shell_open(self.hwnd, "explorer.exe", Some(&arg));
        }
    }

    // ---- programs ------------------------------------------------------

    fn refresh_programs(&mut self) {
        self.programs = hive_mend::list_programs(&WindowsRegistry);
        self.programs_loaded = true;
        let total: u64 = self
            .programs
            .iter()
            .filter_map(|program| program.size)
            .sum();
        self.programs_note = format!(
            "{} programs installed, using about {} by their own estimates.",
            self.programs.len(),
            hive_mend::format_bytes(total)
        );
        unsafe {
            SendMessageW(self.programs_list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.programs_list, LVM_DELETEALLITEMS, 0, 0);
        }
        for (row, program) in self.programs.iter().enumerate() {
            let size = program
                .size
                .map(hive_mend::format_bytes)
                .unwrap_or_default();
            insert_row(
                self.programs_list,
                row,
                &[
                    &program.name,
                    &program.publisher,
                    &program.installed,
                    &size,
                    &program.version,
                ],
            );
        }
        unsafe {
            SendMessageW(self.programs_list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.programs_list, std::ptr::null(), 1);
        }
    }

    /// Start the highlighted program's own uninstaller, after a confirmation.
    fn uninstall_program(&mut self, rows: &[usize]) {
        if self.busy() {
            return;
        }
        let Some(&row) = rows.first() else {
            self.message("Highlight a program first.", MB_ICONINFORMATION);
            return;
        };
        let Some(program) = self.programs.get(row).cloned() else {
            return;
        };
        // An administrator window never starts uninstallers: one started
        // from here would run with administrator rights, whatever wrote it.
        // Instead it opens Hivemend without administrator rights on this
        // page; from there the uninstaller asks for rights itself.
        if self.elevated {
            let question = format!(
                "Uninstallers are started from Hivemend without administrator rights, so a program's uninstaller never gets them unless it asks Windows itself.\n\nOpen Hivemend without administrator rights on the Programs page to uninstall {}? This window closes.",
                program.name
            );
            if !self.confirm(&question, Redo::Uninstall(row)) {
                return;
            }
            match start_unelevated(&exe_path(), PROGRAMS_FLAG) {
                Ok(()) => unsafe {
                    PostMessageW(self.hwnd, WM_CLOSE, 0, 0);
                },
                Err(err) => self.message(
                    &format!(
                        "Hivemend could not open a window without administrator rights: {err}.\n\nClose this window and start Hivemend normally, or use Settings > Apps > Installed apps."
                    ),
                    MB_ICONWARNING,
                ),
            }
            return;
        }
        let launch = match hive_mend::uninstall_launch(&HostFs, &program.uninstall, self.elevated) {
            Ok(launch) => launch,
            Err(err) => {
                self.message(
                    &format!(
                        "Hivemend cannot start the uninstaller for {}: {err}.\n\nYou can try Settings > Apps > Installed apps instead.",
                        program.name
                    ),
                    MB_ICONWARNING,
                );
                return;
            }
        };
        let question = format!(
            "Start the uninstaller for {}?\n\n{} {}\n\nThis runs the program's own uninstaller with the command it registered. Most ask before removing anything, but a silent one (such as /S) removes the program right away. Programs are not backed up.",
            program.name, launch.exe, launch.params
        );
        if !self.confirm(&question, Redo::Uninstall(row)) {
            return;
        }
        let params = (!launch.params.is_empty()).then_some(launch.params.as_str());
        shell_open(self.hwnd, &launch.exe, params);
        self.programs_note = format!(
            "Asked Windows to start the uninstaller for {}. Click Refresh when it finishes.",
            program.name
        );
        self.invalidate();
    }

    fn open_program_folder(&mut self) {
        let Some(program) = selected_rows(self.programs_list)
            .first()
            .and_then(|row| self.programs.get(*row))
            .cloned()
        else {
            self.message("Highlight a program first.", MB_ICONINFORMATION);
            return;
        };
        let folder = program.install_location.trim_end_matches('\\').to_string();
        if folder.as_bytes().get(1) == Some(&b':') && std::path::Path::new(&folder).is_dir() {
            shell_open(self.hwnd, "explorer.exe", Some(&format!("\"{folder}\"")));
            return;
        }
        match hive_mend::uninstall_launch(&HostFs, &program.uninstall, false) {
            Ok(launch) => {
                let arg = format!("/select,\"{}\"", launch.exe);
                shell_open(self.hwnd, "explorer.exe", Some(&arg));
            }
            Err(_) => self.message(
                &format!("{} did not record where it is installed.", program.name),
                MB_ICONINFORMATION,
            ),
        }
    }

    // ---- disk space ----------------------------------------------------

    fn start_disk(&mut self, index: usize) {
        if self.busy() {
            return;
        }
        let Some((_, root)) = self.disk_roots.get(index).cloned() else {
            return;
        };
        self.job = Job::Analyzing;
        self.disk_root = Some(index);
        self.disk_report = None;
        self.disk_view = DiskView::Folders;
        CANCEL.store(false, Ordering::SeqCst);
        let used = drive_used_bytes(&root).max(1);
        set_progress(0, 1000, &format!("Reading {root}..."));
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let mut last = std::time::Instant::now();
            let report =
                hive_mend::analyze(&hive_mend::HostLister, &root, &mut |files, bytes, dir| {
                    if last.elapsed() >= std::time::Duration::from_millis(200) {
                        last = std::time::Instant::now();
                        let done = (bytes.saturating_mul(1000) / used).min(990) as usize;
                        set_progress(
                            done,
                            1000,
                            &format!(
                                "{} in {} files so far. Reading {dir}",
                                format_bytes(bytes),
                                group_digits(files)
                            ),
                        );
                        post(hwnd, WM_JOB_PROGRESS);
                    }
                    !CANCEL.load(Ordering::SeqCst)
                });
            finish_job(
                hwnd,
                JobResult::Disk {
                    report: Box::new(report),
                },
            );
        });
    }

    fn fill_disk(&mut self) {
        let Some(report) = self.disk_report.as_ref() else {
            return;
        };
        let total = report.nodes[0].bytes.max(1);
        let share = |bytes: u64| format!("{:.1}%", bytes as f64 * 100.0 / total as f64);
        let mut rows: Vec<(DiskRow, [String; 4])> = Vec::new();
        match self.disk_view {
            DiskView::Folders => {
                let here = report.nodes[self.disk_at].bytes.max(1);
                for child in report.children_by_size(self.disk_at) {
                    let node = &report.nodes[child];
                    rows.push((
                        DiskRow::Folder(child),
                        [
                            node.name.clone(),
                            format_bytes(node.bytes),
                            format!("{:.1}%", node.bytes as f64 * 100.0 / here as f64),
                            group_digits(node.files),
                        ],
                    ));
                }
                let own = report.nodes[self.disk_at].bytes
                    - report.nodes[self.disk_at]
                        .children
                        .iter()
                        .map(|child| report.nodes[*child].bytes)
                        .sum::<u64>();
                if own > 0 {
                    rows.push((
                        DiskRow::Kind,
                        [
                            "(files in this folder)".to_string(),
                            format_bytes(own),
                            format!("{:.1}%", own as f64 * 100.0 / here as f64),
                            String::new(),
                        ],
                    ));
                }
            }
            DiskView::Files => {
                for (index, file) in report.largest.iter().enumerate() {
                    rows.push((
                        DiskRow::File(index),
                        [
                            file.path.clone(),
                            format_bytes(file.bytes),
                            share(file.bytes),
                            String::new(),
                        ],
                    ));
                }
            }
            DiskView::Kinds => {
                let mut kinds = report.kinds.clone();
                kinds.sort_by_key(|kind| std::cmp::Reverse(kind.1));
                for (kind, bytes, files) in kinds {
                    rows.push((
                        DiskRow::Kind,
                        [
                            kind.label().to_string(),
                            format_bytes(bytes),
                            share(bytes),
                            group_digits(files),
                        ],
                    ));
                }
            }
        }
        unsafe {
            SendMessageW(self.disk_list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.disk_list, LVM_DELETEALLITEMS, 0, 0);
        }
        for (row, (_, cells)) in rows.iter().enumerate() {
            let cells: Vec<&str> = cells.iter().map(String::as_str).collect();
            insert_row(self.disk_list, row, &cells);
        }
        self.disk_rows = rows.into_iter().map(|(row, _)| row).collect();
        unsafe {
            SendMessageW(self.disk_list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.disk_list, std::ptr::null(), 1);
        }
    }

    /// Go into the highlighted folder, or show the highlighted file.
    fn open_disk_selection(&mut self) {
        let row = selected_rows(self.disk_list).first().copied();
        match row.and_then(|row| self.disk_rows.get(row).copied()) {
            Some(DiskRow::Folder(node)) => {
                self.disk_at = node;
                self.fill_disk();
                self.sync_controls();
                self.invalidate();
            }
            Some(DiskRow::File(_)) => self.open_disk_row(),
            _ => {}
        }
    }

    fn open_disk_row(&mut self) {
        let Some(report) = self.disk_report.as_ref() else {
            return;
        };
        let row = selected_rows(self.disk_list).first().copied();
        let arg = match row.and_then(|row| self.disk_rows.get(row).copied()) {
            Some(DiskRow::Folder(node)) => format!("\"{}\"", report.path_of(node)),
            Some(DiskRow::File(index)) => match report.largest.get(index) {
                Some(file) => format!("/select,\"{}\"", file.path),
                None => return,
            },
            _ => format!("\"{}\"", report.path_of(self.disk_at)),
        };
        shell_open(self.hwnd, "explorer.exe", Some(&arg));
    }

    // ---- duplicates ----------------------------------------------------

    fn start_dups(&mut self, index: usize) {
        if self.busy() {
            return;
        }
        let Some((_, root)) = self.disk_roots.get(index).cloned() else {
            return;
        };
        let protected = match hive_mend::protected_roots(&HostFs) {
            Ok(protected) => protected,
            Err(err) => {
                self.message(
                    &format!("The search cannot run safely: {err}."),
                    MB_ICONWARNING,
                );
                return;
            }
        };
        self.job = Job::Finding;
        self.dup_root = Some(index);
        self.dup_report = None;
        CANCEL.store(false, Ordering::SeqCst);
        set_progress(0, 1, &format!("Reading {root}..."));
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let mut last = std::time::Instant::now();
            let report = hive_mend::find_duplicates(
                &hive_mend::HostLister,
                &hive_mend::HostContent {
                    stop: Some(&CANCEL),
                },
                &root,
                DUP_MIN_BYTES,
                &protected,
                &mut |text, done, total| {
                    if last.elapsed() >= std::time::Duration::from_millis(200) {
                        last = std::time::Instant::now();
                        set_progress(done, total.max(1), text);
                        post(hwnd, WM_JOB_PROGRESS);
                    }
                    !CANCEL.load(Ordering::SeqCst)
                },
            );
            finish_job(hwnd, JobResult::Dups { result: Ok(report) });
        });
    }

    fn fill_dups(&mut self) {
        self.dup_filling = true;
        self.dup_rows.clear();
        unsafe {
            SendMessageW(self.dup_list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.dup_list, LVM_DELETEALLITEMS, 0, 0);
        }
        if let Some(report) = self.dup_report.as_ref() {
            for (set, group) in report.groups.iter().enumerate() {
                for (file, path) in group.files.iter().enumerate() {
                    let (folder, name) = path.rsplit_once('\\').unwrap_or(("", path));
                    let row = self.dup_rows.len();
                    insert_row(
                        self.dup_list,
                        row,
                        &[
                            name,
                            folder,
                            &format_bytes(group.bytes),
                            &(set + 1).to_string(),
                        ],
                    );
                    self.dup_rows.push((set, file));
                }
            }
        }
        self.dup_checked.resize(self.dup_rows.len(), false);
        self.dup_checked.truncate(self.dup_rows.len());
        for (row, on) in self.dup_checked.iter().enumerate() {
            set_state_image(self.dup_list, row, if *on { 2 } else { 1 });
        }
        unsafe {
            SendMessageW(self.dup_list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.dup_list, std::ptr::null(), 1);
        }
        self.dup_filling = false;
        self.update_dup_label();
    }

    /// Tick every copy but the first of each set, or untick everything.
    fn dup_tick(&mut self, extras: bool) {
        if self.busy() {
            return;
        }
        self.dup_checked = self
            .dup_rows
            .iter()
            .map(|(_, file)| extras && *file > 0)
            .collect();
        self.fill_dups();
    }

    fn dup_ticked_paths(&self) -> Vec<String> {
        let Some(report) = self.dup_report.as_ref() else {
            return Vec::new();
        };
        self.dup_rows
            .iter()
            .zip(&self.dup_checked)
            .filter(|(_, on)| **on)
            .filter_map(|((set, file), _)| report.groups.get(*set)?.files.get(*file).cloned())
            .collect()
    }

    fn update_dup_label(&self) {
        let count = self.dup_checked.iter().filter(|on| **on).count();
        let label = if count == 0 {
            "Move Ticked to Recycle Bin".to_string()
        } else {
            format!("Move {count} to Recycle Bin")
        };
        set_text(self.btn_dup_recycle, &label);
    }

    fn recycle_ticked(&mut self) {
        if self.busy() {
            return;
        }
        if self.elevated {
            self.message(
                "Hivemend does not remove duplicates with administrator rights. Open it without administrator rights to move your own files to the Recycle Bin.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let Some(report) = self.dup_report.clone() else {
            return;
        };
        let mut plan: Vec<(hive_mend::DupGroup, Vec<usize>)> = Vec::new();
        for (set, group) in report.groups.iter().enumerate() {
            let remove: Vec<usize> = self
                .dup_rows
                .iter()
                .zip(&self.dup_checked)
                .filter(|((row_set, _), on)| **on && *row_set == set)
                .map(|((_, file), _)| *file)
                .collect();
            if remove.is_empty() {
                continue;
            }
            if remove.len() >= group.files.len() {
                self.message(
                    &format!(
                        "Every copy in set {} is ticked. Untick at least one copy to keep.",
                        set + 1
                    ),
                    MB_ICONINFORMATION,
                );
                return;
            }
            plan.push((group.clone(), remove));
        }
        let count: usize = plan.iter().map(|(_, remove)| remove.len()).sum();
        if count == 0 {
            self.message(
                "Tick the copies to remove first, or use Tick Extra Copies.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let bytes: u64 = plan
            .iter()
            .map(|(group, remove)| group.bytes * remove.len() as u64)
            .sum();
        let question = format!(
            "Move {} ({}) to the Recycle Bin?\n\nOne copy of every set is kept. Each file is compared byte by byte with the kept copy first and left alone if it no longer matches. You can put files back from the Recycle Bin.",
            count_of(count as u64, "file", "files"),
            format_bytes(bytes)
        );
        if !self.confirm(&question, Redo::Recycle) {
            return;
        }
        let protected = match hive_mend::protected_roots(&HostFs) {
            Ok(protected) => protected,
            Err(err) => {
                self.message(&format!("Nothing was moved: {err}."), MB_ICONWARNING);
                return;
            }
        };
        self.job = Job::Recycling;
        set_progress(0, count.max(1), "Checking and moving files...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx};
            unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
            let mut results = Vec::new();
            let mut done = 0;
            for (group, remove) in plan {
                let outcomes = hive_mend::remove_checked(
                    &hive_mend::HostContent::default(),
                    &group,
                    &remove,
                    &protected,
                    &mut |path, held| {
                        done += 1;
                        set_progress(done, count.max(1), &format!("Moving {path}"));
                        post(hwnd, WM_JOB_PROGRESS);
                        hive_mend::recycle(held)
                    },
                );
                results.extend(outcomes);
            }
            finish_job(hwnd, JobResult::Recycled { results });
        });
    }

    fn finish_recycle(&mut self, results: Vec<(String, Result<(), String>)>) {
        let moved: Vec<&String> = results
            .iter()
            .filter(|(_, outcome)| outcome.is_ok())
            .map(|(path, _)| path)
            .collect();
        let kept: Vec<&String> = results
            .iter()
            .filter(|(_, outcome)| outcome.is_err())
            .map(|(path, _)| path)
            .collect();
        if let Some(report) = self.dup_report.as_mut() {
            // A set with a file that was kept may have changed since the
            // search; it is dropped until the next search.
            report
                .groups
                .retain(|group| !group.files.iter().any(|path| kept.contains(&path)));
            for group in &mut report.groups {
                group.files.retain(|path| !moved.contains(&path));
            }
            report.groups.retain(|group| group.files.len() > 1);
        }
        let mut lines = vec![format!(
            "Moved {} to the Recycle Bin.",
            count_of(moved.len() as u64, "file", "files")
        )];
        for (path, outcome) in results
            .iter()
            .filter(|(_, outcome)| outcome.is_err())
            .take(8)
        {
            if let Err(why) = outcome {
                lines.push(format!("Kept {path}: {why}"));
            }
        }
        let failed = !kept.is_empty();
        if failed {
            lines.push("Search again to list the sets with kept files.".to_string());
        }
        self.dup_checked.clear();
        self.sync_controls();
        self.fill_dups();
        self.message(
            &lines.join("\n"),
            if failed {
                MB_ICONWARNING
            } else {
                MB_ICONINFORMATION
            },
        );
    }

    fn open_dup_row(&mut self) {
        let Some(path) = selected_rows(self.dup_list)
            .first()
            .and_then(|row| self.dup_rows.get(*row))
            .and_then(|(set, file)| {
                self.dup_report
                    .as_ref()?
                    .groups
                    .get(*set)?
                    .files
                    .get(*file)
                    .cloned()
            })
        else {
            self.message("Highlight a file first.", MB_ICONINFORMATION);
            return;
        };
        shell_open(
            self.hwnd,
            "explorer.exe",
            Some(&format!("/select,\"{path}\"")),
        );
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
                SendMessageW(
                    self.svc_list,
                    LVM_GETITEMRECT,
                    rows[0],
                    &mut rect as *mut _ as isize,
                );
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
        let menu = unsafe {
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
            menu
        };
        // Shown by run_native after this handler returns; the choice comes
        // back as WM_MENU_PICKED and applies only to the same items.
        let identity = self.menu_identity(MenuKind::Services, &rows);
        lock(&NATIVE).push_back(Native::Menu {
            menu: menu as isize,
            at,
            picked: Picked {
                kind: MenuKind::Services,
                rows,
                identity,
                choice: 0,
            },
        });
    }

    fn services_choice(&mut self, rows: &[usize], choice: usize) {
        match choice {
            MENU_SVC_START => self.power_rows(rows, true),
            MENU_SVC_STOP => self.power_rows(rows, false),
            MENU_SVC_AUTO => self.set_rows(rows, StartType::Automatic),
            MENU_SVC_AUTO_DELAYED => self.set_rows(rows, StartType::AutomaticDelayed),
            MENU_SVC_MANUAL => self.set_rows(rows, StartType::Manual),
            MENU_SVC_DISABLED => self.set_rows(rows, StartType::Disabled),
            _ => {}
        }
    }

    // ---- repair --------------------------------------------------------

    fn start_repair(&mut self) {
        if self.busy() {
            return;
        }
        let mut selected = self.ticked();
        if selected.is_empty() {
            self.message(
                "Tick the entries you want to repair first.",
                MB_ICONINFORMATION,
            );
            return;
        }
        // An administrator window leaves per-user registry entries to a
        // normal window: a program running without elevation can redirect
        // keys in those hives.
        let per_user = if self.elevated {
            let before = selected.len();
            selected.retain(|finding| !finding.per_user());
            before - selected.len()
        } else {
            0
        };
        if selected.is_empty() {
            self.message(
                "The ticked entries are in your own part of the registry. Repair them from Hivemend started without administrator rights.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let Some(mut backup) = next_backup_file() else {
            self.message(
                "Could not reserve a backup file in the backups folder. Nothing was changed.",
                MB_ICONWARNING,
            );
            return;
        };
        let mut question = format!(
            "Repair {} {}?\n\nHivemend first checks that each one is still broken, then saves a backup in\n{}\nbefore removing anything. You can undo the repair on the Restore page.",
            selected.len(),
            if selected.len() == 1 {
                "entry"
            } else {
                "entries"
            },
            backup
                .path()
                .parent()
                .map(|dir| dir.display().to_string())
                .unwrap_or_default()
        );
        if per_user > 0 {
            question.push_str(&format!(
                "\n\n{per_user} ticked {} in your own part of the registry {} left alone; repair {} from Hivemend started without administrator rights.",
                if per_user == 1 { "entry" } else { "entries" },
                if per_user == 1 { "is" } else { "are" },
                if per_user == 1 { "it" } else { "them" },
            ));
        }
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
        if !self.confirm(&question, Redo::Repair) {
            backup.discard();
            return;
        }
        self.job = Job::Repairing;
        self.page = Page::Scan;
        set_progress(0, 1, "Checking the ticked entries again...");
        self.sync_controls();
        self.show_progress();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        // Windows only creates restore points for administrators.
        let make_point = self.elevated && !self.settings.skip_restore_point;
        std::thread::spawn(move || {
            let engine = match Engine::try_builtin() {
                Ok(engine) => engine,
                Err(err) => {
                    finish_job(
                        hwnd,
                        JobResult::Repair {
                            result: Err(format!("Could not load the scanner rules: {err}")),
                            fixed_meanwhile: Vec::new(),
                            restore_note: None,
                        },
                    );
                    return;
                }
            };
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
                &engine,
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
            let mut restore_note = None;
            let result = if confirmed.is_empty() {
                backup.discard();
                Ok(RepairOutcome {
                    backup_file: PathBuf::new(),
                    ..RepairOutcome::default()
                })
            } else {
                let point = if make_point {
                    set_progress(1, 3, "Creating a Windows restore point...");
                    post(hwnd, WM_JOB_PROGRESS);
                    Some(hive_mend::restorepoint::begin("Hivemend repair"))
                } else {
                    None
                };
                set_progress(1, 3, "Saving the backup...");
                post(hwnd, WM_JOB_PROGRESS);
                let total = confirmed.len();
                let repaired = repair_with_progress(
                    &mut WindowsRegistry,
                    &mut HostFs,
                    &confirmed,
                    &mut backup,
                    &mut |done, _| {
                        set_progress(
                            total + done * 2,
                            total * 3,
                            &format!("Removing {done} of {total}..."),
                        );
                        post(hwnd, WM_JOB_PROGRESS);
                    },
                )
                .map_err(|err| format!("The backup could not be written: {err}"));
                restore_note = match point {
                    Some(Ok(point)) => {
                        let changed = repaired.as_ref().is_ok_and(|outcome| outcome.applied > 0);
                        match hive_mend::restorepoint::end(point, changed) {
                            Ok(()) => changed.then(|| {
                                "Windows also saved a restore point before the repair. (Windows keeps at most one a day, so it may reuse today's.)".to_string()
                            }),
                            Err(why) if changed => Some(format!(
                                "The Windows restore point may not have been saved: {why}. The registry backup was saved as usual."
                            )),
                            Err(_) => None,
                        }
                    }
                    Some(Err(why)) => Some(format!(
                        "No Windows restore point was made: {why}. The registry backup was saved as usual."
                    )),
                    None => None,
                };
                repaired
            };
            finish_job(
                hwnd,
                JobResult::Repair {
                    result,
                    fixed_meanwhile,
                    restore_note,
                },
            );
        });
    }

    fn finish_repair(
        &mut self,
        result: Result<RepairOutcome, String>,
        fixed_meanwhile: Vec<Finding>,
        restore_note: Option<String>,
    ) {
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(err) => {
                self.scan_note = "Repair stopped before changing anything.".into();
                self.message(&format!("Nothing was changed:\n\n{err}"), MB_ICONWARNING);
                return;
            }
        };
        for finding in &outcome.refused_findings {
            if self.left_alone_why(finding).is_none() {
                self.left_alone.push((
                    finding.clone(),
                    LeftAlone::Protected("a safety rule left it alone in the last repair".into()),
                ));
            }
        }
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
        if let Some(note) = restore_note {
            lines.push(note);
        }
        if already > 0 {
            lines.push(format!(
                "Already fixed before repair reached them: {already}"
            ));
        }
        let left = outcome.refused + outcome.not_backed_up;
        if left > 0 {
            lines.push(format!(
                "Left alone because they could not be backed up or are protected: {left}"
            ));
        }
        for note in outcome.notes.iter().take(5) {
            lines.push(format!("Left alone: {note}"));
        }
        if outcome.notes.len() > 5 {
            lines.push(format!(
                "...and {} more left alone",
                outcome.notes.len() - 5
            ));
        }
        if !outcome.errors.is_empty() {
            let mut line = format!("Could not remove: {}", outcome.errors.len());
            if outcome.denied > 0 && !self.elevated {
                line.push_str(&format!(" ({} need Run as administrator)", outcome.denied));
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

    /// Read the backup list off the window's thread (each file is read and
    /// parsed), and show it when it arrives. One reader runs at a time: a
    /// refresh while it reads makes it stop early and read again.
    fn refresh_backups(&mut self) {
        let Some(refresh) = BACKUPS.request() else {
            return;
        };
        let hwnd = self.hwnd as isize;
        let started = std::thread::Builder::new().spawn(move || {
            BACKUPS.work(refresh, all_backups, || post(hwnd, WM_BACKUPS_READY));
        });
        if started.is_err() {
            BACKUPS.not_started(refresh);
            post(hwnd, WM_BACKUPS_READY);
        }
    }

    fn fill_backups(&self) {
        unsafe {
            SendMessageW(self.backup_list, LVM_DELETEALLITEMS, 0, 0);
        }
        for (row, backup) in self.backups.iter().enumerate() {
            let saved = backup.modified.map(local_time_text).unwrap_or_default();
            let mut name = backup
                .path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            match backup.store {
                Store::Protected => {}
                Store::User => name.push_str("  (your account)"),
                Store::Legacy => name.push_str("  (old shared folder)"),
            }
            insert_row(
                self.backup_list,
                row,
                &[&saved, &contents(&backup.summary), &name],
            );
        }
    }

    fn start_restore(&mut self, row: usize) {
        if self.busy() {
            return;
        }
        let Some(backup) = self.backups.get(row).cloned() else {
            return;
        };
        if let Some(text) = restore_block(&backup.summary, &backup.path, self.elevated) {
            self.message(&text, MB_ICONINFORMATION);
            return;
        }
        if self.elevated && !backup.store.elevated_may_restore() {
            let place = if backup.store == Store::Legacy {
                format!(
                    "the old shared folder {LEGACY_DIR}, which every account on this PC can change"
                )
            } else {
                "your account's folder, which programs you run without administrator rights can change".to_string()
            };
            self.message(
                &format!(
                    "This backup is in {place}, so Hivemend does not restore it with administrator rights.\n\nStart Hivemend without administrator rights to put back the entries for your own account."
                ),
                MB_ICONWARNING,
            );
            return;
        }
        // A backup with entries for this account restores that part here;
        // only a backup that is entirely machine-wide needs elevation first.
        let only_machine = backup.summary.machine_wide && !backup.summary.per_user;
        if only_machine && !self.elevated && !backup.store.elevated_may_restore() {
            self.message(
                "This backup includes machine-wide entries but was not saved in the protected backup store, so Hivemend cannot restore it with administrator rights. Check the file and merge it yourself with Registry Editor if you need those entries back.",
                MB_ICONWARNING,
            );
            return;
        }
        if only_machine && !self.elevated {
            let ask = "This backup includes machine-wide entries, so putting it back needs administrator rights.\n\nRestart Hivemend as administrator now?";
            if self.confirm(ask, Redo::Restore(row)) {
                self.elevate();
            }
            return;
        }
        let saved = backup.modified.map(local_time_text).unwrap_or_default();
        let question = format!(
            "Restore the backup saved {saved}?\n\nThis puts back {}. Entries that exist now are overwritten with the saved copy.",
            contents(&backup.summary)
        );
        if !self.confirm(&question, Redo::Restore(row)) {
            return;
        }
        self.job = Job::Restoring;
        set_progress(0, 2, "Restoring the backup...");
        self.sync_controls();
        self.invalidate();
        let hwnd = self.hwnd as isize;
        let file = backup.path.clone();
        std::thread::spawn(move || {
            let result = restore_backup(&file);
            finish_job(hwnd, JobResult::Restore { file, result });
        });
    }

    fn finish_restore(
        &mut self,
        file: PathBuf,
        result: Result<(BackupSummary, usize, Vec<String>), String>,
    ) {
        match result {
            Ok((summary, files, errors)) => {
                // The headline counts only what was verified: shortcuts put
                // back by this restore, not every shortcut the backup names.
                // A missing archive is never claimed as restored.
                let expected = summary.files.len();
                let mut text = if errors.is_empty() && files == expected {
                    format!("Restored {} from\n{}", contents(&summary), file.display())
                } else {
                    format!(
                        "Restore from\n{} put back {files} of {expected} shortcuts ({}).",
                        file.display(),
                        contents(&summary)
                    )
                };
                if !errors.is_empty() {
                    text.push_str("\n\nSome files could not be put back:\n");
                    text.push_str(
                        &errors
                            .iter()
                            .take(5)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }
                if self.scanned {
                    self.scan_note =
                        "A backup was restored since this scan. Scan again to refresh the results."
                            .into();
                }
                let icon = if errors.is_empty() {
                    MB_ICONINFORMATION
                } else {
                    MB_ICONWARNING
                };
                self.message(&text, icon);
            }
            Err(err) => self.message(
                &format!("The backup could not be restored:\n\n{err}"),
                MB_ICONWARNING,
            ),
        }
    }

    // ---- settings ------------------------------------------------------

    fn save_settings(&self) {
        // Never written from an administrator window: a program running
        // without elevation could redirect the per-user folder.
        if self.elevated {
            return;
        }
        let _ = self.settings.save(&settings_file());
    }

    fn fill_ignored(&self) {
        unsafe { SendMessageW(self.ignored_list, LVM_DELETEALLITEMS, 0, 0) };
        for (row, entry) in self.exclusions.entries().iter().enumerate() {
            insert_row(self.ignored_list, row, &[&entry.label()]);
        }
    }

    fn unignore(&mut self) {
        if self.elevated {
            self.message(
                "The ignore list is changed from Hivemend started without administrator rights. An administrator window does not write to your per-user folder.",
                MB_ICONINFORMATION,
            );
            return;
        }
        let rows = selected_rows(self.ignored_list);
        if rows.is_empty() {
            self.message(
                "Click an ignored entry to highlight it first.",
                MB_ICONINFORMATION,
            );
            return;
        }
        for row in rows.iter().rev() {
            self.exclusions.remove(*row);
        }
        if let Err(err) = self.exclusions.save(&exclusions_file()) {
            self.message(
                &format!("Could not save the ignore list: {err}"),
                MB_ICONWARNING,
            );
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
        // ShellExecuteW waits on the UAC prompt; it runs from run_native,
        // outside any handler.
        lock(&NATIVE).push_back(Native::Elevate);
    }

    // ---- jobs ----------------------------------------------------------

    fn show_progress(&self) {
        // The text line is painted by draw_scan.
        let (done, total) = PROGRESS
            .lock()
            .map(|p| (p.done, p.total))
            .unwrap_or_default();
        let pos = (done * 1000)
            .checked_div(total)
            .map_or(0, |pos| pos.min(1000));
        unsafe { SendMessageW(self.progress, PBM_SETPOS, pos, 0) };
        let mut rect = self.client();
        rect.top = self.s(HEADER_H);
        rect.left = self.s(CONTENT_X);
        unsafe { InvalidateRect(self.hwnd, &rect, 0) };
    }

    fn finish(&mut self, result: JobResult) {
        self.job = Job::Idle;
        match result {
            JobResult::Scan {
                report,
                scope,
                seconds,
            } => self.finish_scan(report, scope, seconds),
            JobResult::Repair {
                result,
                fixed_meanwhile,
                restore_note,
            } => {
                self.sync_controls();
                self.finish_repair(result, fixed_meanwhile, restore_note);
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
            JobResult::Disk { report } => {
                let unread = if report.unreadable > 0 {
                    format!(
                        " {} could not be read{}.",
                        count_of(report.unreadable, "folder", "folders"),
                        if self.elevated {
                            ""
                        } else {
                            " (Run as administrator to include more)"
                        }
                    )
                } else {
                    String::new()
                };
                self.disk_note = format!(
                    "{}{} holds {} in {}.{unread}",
                    if report.canceled {
                        "Stopped early: "
                    } else if report.incomplete {
                        "Too many folders to count them all; partial totals: "
                    } else {
                        ""
                    },
                    report.path_of(0),
                    format_bytes(report.nodes[0].bytes),
                    count_of(report.nodes[0].files, "file", "files"),
                );
                self.disk_at = 0;
                self.disk_report = Some(report);
                self.sync_controls();
                self.fill_disk();
            }
            JobResult::Dups { result } => {
                match result {
                    Ok(report) => {
                        let extra: u64 = report.groups.iter().map(|group| group.extra()).sum();
                        let unread = if report.unreadable > 0 {
                            format!(
                                " {} could not be read.",
                                count_of(report.unreadable, "item", "items")
                            )
                        } else {
                            String::new()
                        };
                        self.dup_note = format!(
                            "{}{} of identical files in {}; keeping one of each frees {}.{unread}",
                            if report.canceled {
                                "Stopped early: "
                            } else if report.incomplete {
                                "Too many files to search them all; from the part searched: "
                            } else {
                                ""
                            },
                            count_of(report.groups.len() as u64, "set", "sets"),
                            report.root,
                            format_bytes(extra),
                        );
                        self.dup_report = Some(report);
                    }
                    Err(err) => {
                        self.dup_note = "The search could not run.".to_string();
                        self.message(&err, MB_ICONWARNING);
                    }
                }
                self.sync_controls();
                self.fill_dups();
            }
            JobResult::Recycled { results } => self.finish_recycle(results),
            JobResult::PrivacyPreview { report } => self.finish_priv_preview(report),
            JobResult::Privacy { result } => {
                self.sync_controls();
                self.finish_privacy(result);
            }
        }
        self.sync_controls();
        self.invalidate();
    }

    /// True only while `redo` is being re-run after the user said Yes to
    /// this exact question for these exact targets. Otherwise the question
    /// is queued for after the handler returns and this returns false, so the
    /// caller backs out as it would on No; on Yes the action runs again.
    fn confirm(&self, text: &str, redo: Redo) -> bool {
        let key = approval_key(text, &self.redo_identity(&redo));
        if lock(&APPROVED).take().as_deref() == Some(key.as_str()) {
            return true;
        }
        lock(&NATIVE).push_back(Native::Confirm {
            text: text.to_string(),
            key,
            redo,
        });
        false
    }

    /// Queue a message box for after the handler returns.
    fn message(&self, text: &str, icon: u32) {
        lock(&NATIVE).push_back(Native::Message {
            text: text.to_string(),
            icon,
        });
    }

    /// What an action would act on right now, so an approval given for one
    /// set of targets is never spent on another.
    fn redo_identity(&self, redo: &Redo) -> String {
        let finding = |finding: &Finding| format!("{}|{:?}", finding.key, finding.value);
        let ticked = |checked: &[bool], index: usize| checked.get(index).copied().unwrap_or(false);
        let parts: Vec<String> = match redo {
            Redo::IgnoreRows(rows) => rows
                .iter()
                .filter_map(|row| self.findings.get(*row))
                .map(finding)
                .collect(),
            Redo::Repair => self
                .findings
                .iter()
                .enumerate()
                .filter(|(index, _)| ticked(&self.checked, *index))
                .map(|(_, item)| finding(item))
                .collect(),
            Redo::ServicesApply => self
                .svc_proposals
                .iter()
                .enumerate()
                .filter(|(index, _)| ticked(&self.svc_checked, *index))
                .map(|(_, change)| format!("{}>{:?}", change.name, change.to))
                .collect(),
            Redo::Startup(rows, _) => rows
                .iter()
                .filter_map(|row| self.startup_items.get(*row))
                .map(|item| format!("{}|{}", item.approved_key, item.name))
                .collect(),
            Redo::Recycle => self.dup_ticked_paths(),
            Redo::Uninstall(row) => self
                .programs
                .get(*row)
                .map(|program| format!("{}|{}", program.key, program.uninstall))
                .into_iter()
                .collect(),
            Redo::PowerRows(rows, _) | Redo::SetRows(rows, _) => rows
                .iter()
                .filter_map(|row| self.services.get(*row))
                .map(|info| info.name.clone())
                .collect(),
            Redo::PrivacyClean => self
                .priv_items
                .iter()
                .enumerate()
                .filter(|(index, _)| ticked(&self.priv_checked, *index))
                .map(|(_, item)| item.id.clone())
                .collect(),
            Redo::Restore(row) => self
                .backups
                .get(*row)
                .map(|backup| backup.path.display().to_string())
                .into_iter()
                .collect(),
        };
        format!("{redo:?}\u{1e}{}", parts.join("\u{1e}"))
    }

    fn redo(&mut self, redo: Redo) {
        match redo {
            Redo::IgnoreRows(rows) => self.ignore_rows(&rows),
            Redo::ServicesApply => self.start_services_apply(),
            Redo::PowerRows(rows, start) => self.power_rows(&rows, start),
            Redo::SetRows(rows, to) => self.set_rows(&rows, to),
            Redo::PrivacyClean => self.start_privacy_clean(),
            Redo::Repair => self.start_repair(),
            Redo::Restore(row) => self.start_restore(row),
            Redo::Startup(rows, enable) => self.toggle_startup(&rows, enable),
            Redo::Uninstall(row) => self.uninstall_program(&[row]),
            Redo::Recycle => self.recycle_ticked(),
        }
    }

    /// The items a popup menu's rows name right now.
    fn menu_identity(&self, kind: MenuKind, rows: &[usize]) -> String {
        match kind {
            MenuKind::Findings => rows
                .iter()
                .filter_map(|row| self.findings.get(*row))
                .map(|finding| format!("{}|{:?}", finding.key, finding.value))
                .collect::<Vec<_>>()
                .join("\u{1e}"),
            MenuKind::Services => rows
                .iter()
                .filter_map(|row| self.services.get(*row))
                .map(|info| info.name.clone())
                .collect::<Vec<_>>()
                .join("\u{1e}"),
        }
    }

    fn menu_picked(&mut self, picked: Picked) {
        if self.busy()
            || picked.rows.is_empty()
            || self.menu_identity(picked.kind, &picked.rows) != picked.identity
        {
            return;
        }
        match picked.kind {
            MenuKind::Findings => self.findings_choice(&picked.rows, picked.choice),
            MenuKind::Services => self.services_choice(&picked.rows, picked.choice),
        }
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
                        place(
                            self.btn_cancel,
                            left,
                            self.s(BODY_Y + 88),
                            self.s(110),
                            button_h,
                        );
                    }
                } else if !self.scanned {
                    visible.push(self.btn_scan);
                    set_text(self.btn_scan, "Start Scan");
                    place(
                        self.btn_scan,
                        left,
                        self.s(BODY_Y + 128),
                        self.s(150),
                        self.s(38),
                    );
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
                        (self.btn_scan, 104),
                        (self.btn_all, 88),
                        (self.btn_none, 98),
                        (self.btn_ignore, 150),
                    ] {
                        place(control, x, button_y, self.s(w), button_h);
                        x += self.s(w + 8);
                    }
                    // Whatever room is left, up to the usual width, so it
                    // never covers Ignore at the minimum window size.
                    let repair_w = (right - x).clamp(self.s(150), self.s(200));
                    place(
                        self.btn_repair,
                        right - repair_w,
                        button_y,
                        repair_w,
                        button_h,
                    );
                    self.size_finding_columns(width);
                }
            }
            Page::Restore => {
                visible.extend([self.backup_list, self.btn_restore, self.btn_open_backups]);
                place(
                    self.backup_list,
                    left,
                    self.s(BODY_Y),
                    width,
                    list_h + list_top - self.s(BODY_Y),
                );
                place(self.btn_restore, left, button_y, self.s(200), button_h);
                place(
                    self.btn_open_backups,
                    left + self.s(208),
                    button_y,
                    self.s(170),
                    button_h,
                );
                let file_w = width - self.s(170 + 300) - self.s(24);
                unsafe {
                    SendMessageW(
                        self.backup_list,
                        LVM_SETCOLUMNWIDTH,
                        0,
                        self.s(170) as isize,
                    );
                    SendMessageW(
                        self.backup_list,
                        LVM_SETCOLUMNWIDTH,
                        1,
                        self.s(300) as isize,
                    );
                    SendMessageW(
                        self.backup_list,
                        LVM_SETCOLUMNWIDTH,
                        2,
                        file_w.max(self.s(120)) as isize,
                    );
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
                visible.push(self.chk_restore_point);
                place(
                    self.chk_restore_point,
                    left,
                    self.s(SETTINGS_RESTORE_POINT_Y),
                    width - self.s(12),
                    self.s(26),
                );
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
                    SendMessageW(
                        self.ignored_list,
                        LVM_SETCOLUMNWIDTH,
                        0,
                        (width - self.s(24)) as isize,
                    );
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
                    place(
                        self.btn_svc_apply,
                        right - apply_w,
                        button_y,
                        apply_w,
                        button_h,
                    );
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
                if matches!(self.job, Job::Cleaning | Job::Previewing) {
                    visible.push(self.progress);
                    place(self.progress, left, self.s(BODY_Y + 16), width, self.s(22));
                    visible.push(self.btn_cancel);
                    place(
                        self.btn_cancel,
                        left,
                        self.s(BODY_Y + 88),
                        self.s(110),
                        button_h,
                    );
                } else {
                    visible.extend([
                        self.priv_list,
                        self.btn_priv_preview,
                        self.btn_priv_all,
                        self.btn_priv_none,
                        self.btn_priv_keep,
                        self.btn_priv_clean,
                    ]);
                    place(self.priv_list, left, list_top, width, list_h);
                    let mut x = left;
                    for (control, w) in [
                        (self.btn_priv_preview, 100),
                        (self.btn_priv_all, 90),
                        (self.btn_priv_none, 100),
                        (self.btn_priv_keep, 136),
                    ] {
                        place(control, x, button_y, self.s(w), button_h);
                        x += self.s(w + 8);
                    }
                    // Whatever room is left, up to the usual width.
                    let clean_w = (right - x).clamp(self.s(140), self.s(220));
                    place(
                        self.btn_priv_clean,
                        right - clean_w,
                        button_y,
                        clean_w,
                        button_h,
                    );
                    self.size_priv_columns(width);
                }
            }
            Page::Startup => {
                visible.extend([
                    self.startup_list,
                    self.btn_su_enable,
                    self.btn_su_disable,
                    self.btn_su_open,
                    self.btn_su_refresh,
                ]);
                let top = self.s(LIST_Y);
                place(
                    self.startup_list,
                    left,
                    top,
                    width,
                    (button_y - self.s(14) - top).max(self.s(80)),
                );
                let mut x = left;
                for (control, w) in [
                    (self.btn_su_enable, 110),
                    (self.btn_su_disable, 110),
                    (self.btn_su_open, 170),
                ] {
                    place(control, x, button_y, self.s(w), button_h);
                    x += self.s(w + 8);
                }
                let refresh_w = self.s(110);
                place(
                    self.btn_su_refresh,
                    right - refresh_w,
                    button_y,
                    refresh_w,
                    button_h,
                );
                let command_w = (width - self.s(220 + 90 + 110 + 26)).max(self.s(160));
                unsafe {
                    SendMessageW(self.startup_list, LVM_SETCOLUMNWIDTH, 3, command_w as isize)
                };
            }
            Page::Programs => {
                visible.extend([
                    self.programs_list,
                    self.btn_pg_uninstall,
                    self.btn_pg_open,
                    self.btn_pg_refresh,
                ]);
                let top = self.s(LIST_Y);
                place(
                    self.programs_list,
                    left,
                    top,
                    width,
                    (button_y - self.s(14) - top).max(self.s(80)),
                );
                place(self.btn_pg_uninstall, left, button_y, self.s(110), button_h);
                place(
                    self.btn_pg_open,
                    left + self.s(118),
                    button_y,
                    self.s(170),
                    button_h,
                );
                let refresh_w = self.s(110);
                place(
                    self.btn_pg_refresh,
                    right - refresh_w,
                    button_y,
                    refresh_w,
                    button_h,
                );
                let name_w = (width - self.s(180 + 95 + 80 + 120 + 26)).max(self.s(160));
                unsafe { SendMessageW(self.programs_list, LVM_SETCOLUMNWIDTH, 0, name_w as isize) };
            }
            Page::DiskSpace => {
                if self.job == Job::Analyzing {
                    visible.push(self.progress);
                    place(self.progress, left, self.s(BODY_Y + 52), width, self.s(22));
                    visible.push(self.btn_cancel);
                    place(
                        self.btn_cancel,
                        left,
                        self.s(BODY_Y + 124),
                        self.s(110),
                        button_h,
                    );
                } else if self.disk_report.is_some() {
                    visible.extend([self.disk_list, self.btn_ds_up, self.btn_ds_open]);
                    let top = self.s(BODY_Y + 44);
                    place(
                        self.disk_list,
                        left,
                        top,
                        width,
                        (button_y - self.s(14) - top).max(self.s(80)),
                    );
                    place(self.btn_ds_up, left, button_y, self.s(130), button_h);
                    place(
                        self.btn_ds_open,
                        left + self.s(138),
                        button_y,
                        self.s(160),
                        button_h,
                    );
                    let name_w = (width - self.s(100 + 80 + 100 + 26)).max(self.s(160));
                    unsafe { SendMessageW(self.disk_list, LVM_SETCOLUMNWIDTH, 0, name_w as isize) };
                    let can_go_up = self.disk_view == DiskView::Folders && self.disk_at != 0;
                    unsafe { EnableWindow(self.btn_ds_up, i32::from(can_go_up)) };
                }
            }
            Page::Duplicates => {
                if matches!(self.job, Job::Finding | Job::Recycling) {
                    visible.push(self.progress);
                    place(self.progress, left, self.s(BODY_Y + 52), width, self.s(22));
                    if self.job == Job::Finding {
                        visible.push(self.btn_cancel);
                        place(
                            self.btn_cancel,
                            left,
                            self.s(BODY_Y + 124),
                            self.s(110),
                            button_h,
                        );
                    }
                } else if self.dup_report.is_some() {
                    visible.extend([
                        self.dup_list,
                        self.btn_dup_extras,
                        self.btn_dup_none,
                        self.btn_dup_recycle,
                        self.btn_dup_open,
                    ]);
                    let top = self.s(BODY_Y + 44);
                    place(
                        self.dup_list,
                        left,
                        top,
                        width,
                        (button_y - self.s(14) - top).max(self.s(80)),
                    );
                    let mut x = left;
                    for (control, w) in [
                        (self.btn_dup_extras, 150),
                        (self.btn_dup_none, 110),
                        (self.btn_dup_open, 120),
                    ] {
                        place(control, x, button_y, self.s(w), button_h);
                        x += self.s(w + 8);
                    }
                    let recycle_w = self.s(250);
                    place(
                        self.btn_dup_recycle,
                        right - recycle_w,
                        button_y,
                        recycle_w,
                        button_h,
                    );
                    let folder_w = (width - self.s(240 + 90 + 70 + 26)).max(self.s(160));
                    unsafe {
                        SendMessageW(self.dup_list, LVM_SETCOLUMNWIDTH, 1, folder_w as isize)
                    };
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
            self.btn_priv_keep,
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
            SendMessageW(
                self.svc_tune_list,
                LVM_SETCOLUMNWIDTH,
                0,
                self.s(240) as isize,
            );
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
            let previous_hover = self
                .hover
                .and_then(|i| self.hotspots.get(i))
                .map(|s| s.rect);
            let focused = self.focused_spot();
            self.hotspots.clear();
            self.texts.borrow_mut().clear();
            fill(mem, rect, BG);
            self.draw_chrome(mem, rect, previous_hover);
            match self.page {
                Page::Status => self.draw_status(mem, rect, previous_hover),
                Page::Scan => self.draw_scan(mem, rect),
                Page::Restore => self.draw_restore(mem, rect),
                Page::Settings => self.draw_settings(mem, rect),
                Page::Services => self.draw_services(mem, rect, previous_hover),
                Page::Startup => self.draw_startup(mem, rect),
                Page::Programs => self.draw_programs(mem, rect),
                Page::DiskSpace => self.draw_disk(mem, rect, previous_hover),
                Page::Duplicates => self.draw_dups(mem, rect, previous_hover),
                Page::Privacy => self.draw_privacy(mem, rect),
                Page::Monitor => self.draw_monitor(mem, rect, previous_hover),
                Page::Tools => self.draw_tools(mem, rect, previous_hover),
                Page::About => self.draw_about(mem, rect),
            }
            if let Some(prev) = previous_hover {
                self.hover = self.hotspots.iter().position(|spot| same(spot.rect, prev));
            }
            // Where the keyboard is: a focus outline around that button.
            if let Some(spot) = focused.and_then(|index| self.hotspots.get(index)) {
                let gap = self.s(3);
                let ring = RECT {
                    left: spot.rect.left - gap,
                    top: spot.rect.top - gap,
                    right: spot.rect.right + gap,
                    bottom: spot.rect.bottom + gap,
                };
                windows_sys::Win32::Graphics::Gdi::DrawFocusRect(mem, &ring);
            }
            BitBlt(hdc, 0, 0, rect.right, rect.bottom, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old);
            DeleteObject(bitmap);
            DeleteDC(mem);
            EndPaint(self.hwnd, &ps);
        }
        self.sync_access();
    }

    fn spot(&mut self, rect: RECT, action: Action, name: &str) {
        self.hotspots.push(HotSpot {
            rect,
            action,
            name: name.to_string(),
        });
    }

    /// Record a drawn status line for screen readers and UI automation.
    fn say(&self, rect: RECT, line: &str) {
        if !line.is_empty() {
            self.texts.borrow_mut().push((rect, line.to_string()));
        }
    }

    /// Point the stand-in controls at what the last paint drew: one button
    /// per hotspot, one static per status line, the rest hidden. Only what
    /// changed is touched, so this settles after one pass.
    fn sync_access(&mut self) {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, GetFocus, SetFocus};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SW_HIDE, SWP_NOACTIVATE, SWP_NOZORDER, SWP_SHOWWINDOW, SetWindowPos, SetWindowTextW,
            ShowWindow,
        };
        let place = |control: HWND, (left, top, right, bottom): Edges| unsafe {
            SetWindowPos(
                control,
                std::ptr::null_mut(),
                left,
                top,
                right - left,
                bottom - top,
                SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW,
            );
        };
        let focus = unsafe { GetFocus() };
        let mut lost_focus = false;
        for (index, &control) in self.access.iter().enumerate() {
            let want = self.hotspots.get(index).map(|spot| {
                let mut name = spot.name.clone();
                if matches!(spot.action, Action::Page(page) if page == self.page) {
                    name.push_str(", current page");
                }
                (name, edges(spot.rect), self.spot_enabled(index))
            });
            if want == self.access_shown[index] {
                continue;
            }
            unsafe {
                match &want {
                    Some((name, rect, enabled)) => {
                        SetWindowTextW(control, wide(name).as_ptr());
                        EnableWindow(control, *enabled as i32);
                        place(control, *rect);
                        lost_focus |= control == focus && !*enabled;
                    }
                    None => {
                        ShowWindow(control, SW_HIDE);
                        lost_focus |= control == focus;
                    }
                }
            }
            self.access_shown[index] = want;
        }
        let texts = self.texts.borrow().clone();
        for (index, &control) in self.text_ctls.iter().enumerate() {
            let want = texts
                .get(index)
                .map(|(rect, line)| (line.clone(), edges(*rect)));
            if want == self.text_shown[index] {
                continue;
            }
            unsafe {
                match &want {
                    Some((line, rect)) => {
                        SetWindowTextW(control, wide(line).as_ptr());
                        place(control, *rect);
                    }
                    None => {
                        ShowWindow(control, SW_HIDE);
                    }
                }
            }
            self.text_shown[index] = want;
        }
        // Focus on a stand-in that went away returns to the window, so the
        // keyboard is never stranded on nothing.
        if lost_focus {
            unsafe { SetFocus(self.hwnd) };
        }
    }

    /// The stand-in button that has keyboard focus, as a hotspot index.
    fn focused_spot(&self) -> Option<usize> {
        let focus = unsafe { windows_sys::Win32::UI::Input::KeyboardAndMouse::GetFocus() };
        self.access.iter().position(|&control| control == focus)
    }

    unsafe fn draw_chrome(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        let header = self.s(HEADER_H);
        // A clean title bar: logo, name, a hairline beneath.
        fill(
            hdc,
            RECT {
                left: 0,
                top: 0,
                right: rect.right,
                bottom: header,
            },
            SURFACE,
        );
        fill(
            hdc,
            RECT {
                left: 0,
                top: header - 1,
                right: rect.right,
                bottom: header,
            },
            BORDER,
        );
        let logo = self.s(30);
        self.draw_icon(hdc, Icon::Logo, self.s(20), (header - logo) / 2, logo);
        text(
            hdc,
            self.fonts.heading,
            INK,
            RECT {
                left: self.s(20) + logo + self.s(12),
                top: 0,
                right: rect.right / 2,
                bottom: header,
            },
            "Hivemend",
            DT_SINGLELINE | DT_VCENTER,
        );
        let help_size = measure(hdc, self.fonts.body, "Help");
        let help = RECT {
            left: rect.right - self.s(24) - help_size.0,
            top: header / 2 - self.s(13),
            right: rect.right - self.s(24),
            bottom: header / 2 + self.s(13),
        };
        let help_lit = lit(hover, help);
        text(
            hdc,
            self.fonts.body,
            if help_lit { ACCENT_GREEN } else { MUTED },
            help,
            "Help",
            DT_SINGLELINE | DT_VCENTER | DT_RIGHT,
        );
        self.spot(help, Action::Page(Page::About), "Help");
        let right_edge = help.left - self.s(20);
        if self.elevated {
            let label = "Administrator";
            let size = measure(hdc, self.fonts.small, label);
            let badge = RECT {
                left: right_edge - size.0 - self.s(20),
                top: header / 2 - self.s(12),
                right: right_edge,
                bottom: header / 2 + self.s(12),
            };
            self.panel(hdc, badge, self.s(12), ACCENT_TINT, ACCENT_TINT, 0, SURFACE);
            text(
                hdc,
                self.fonts.small,
                THEME_INK,
                badge,
                label,
                DT_SINGLELINE | DT_VCENTER | DT_CENTER,
            );
        } else {
            let label = "Run as administrator";
            let size = measure(hdc, self.fonts.body, label);
            let link = RECT {
                left: right_edge - size.0 - self.s(28),
                top: header / 2 - self.s(16),
                right: right_edge,
                bottom: header / 2 + self.s(16),
            };
            let lit = lit(hover, link);
            self.panel(
                hdc,
                link,
                self.s(8),
                if lit { ACCENT_TINT } else { SURFACE },
                ACCENT_GREEN,
                1,
                SURFACE,
            );
            text(
                hdc,
                self.fonts.body,
                ACCENT_GREEN,
                link,
                label,
                DT_SINGLELINE | DT_VCENTER | DT_CENTER,
            );
            self.spot(link, Action::Elevate, label);
        }

        // The navigation rail: icon and label per page; the open page gets
        // a soft green fill and an accent bar.
        let side = RECT {
            left: 0,
            top: header,
            right: self.s(SIDEBAR_W),
            bottom: rect.bottom,
        };
        fill(hdc, side, SIDEBAR_BG);
        fill(
            hdc,
            RECT {
                left: side.right - 1,
                top: header,
                right: side.right,
                bottom: side.bottom,
            },
            BORDER,
        );
        let mut y = header + self.s(14);
        for (label, page, icon) in NAV {
            let item = RECT {
                left: self.s(10),
                top: y,
                right: self.s(SIDEBAR_W - 10),
                bottom: y + self.s(38),
            };
            let selected = self.page == *page;
            let lit = lit(hover, item);
            if selected || lit {
                let tint = if selected { ACCENT_TINT } else { HOVER_TINT };
                self.panel(hdc, item, self.s(8), tint, tint, 0, SIDEBAR_BG);
            }
            if selected {
                let bar_h = self.s(16);
                self.panel(
                    hdc,
                    RECT {
                        left: item.left,
                        top: item.top + (self.s(38) - bar_h) / 2,
                        right: item.left + self.s(4),
                        bottom: item.top + (self.s(38) + bar_h) / 2,
                    },
                    self.s(2),
                    ACCENT_GREEN,
                    ACCENT_GREEN,
                    0,
                    ACCENT_TINT,
                );
            }
            let icon_px = self.s(22);
            self.draw_icon(
                hdc,
                *icon,
                item.left + self.s(14),
                item.top + (self.s(38) - icon_px) / 2,
                icon_px,
            );
            text(
                hdc,
                if selected {
                    self.fonts.body_bold
                } else {
                    self.fonts.body
                },
                if selected { THEME_INK } else { INK },
                RECT {
                    left: item.left + self.s(14) + icon_px + self.s(12),
                    top: item.top,
                    right: item.right - self.s(8),
                    bottom: item.bottom,
                },
                label,
                DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
            );
            self.spot(item, Action::Page(*page), label);
            y += self.s(40);
        }
        if self.busy() {
            let note = match self.job {
                Job::Scanning => "Scanning...",
                Job::Repairing => "Repairing...",
                Job::Restoring => "Restoring...",
                Job::Services => "Working...",
                Job::Cleaning => "Cleaning...",
                Job::Analyzing => "Reading sizes...",
                Job::Finding => "Comparing files...",
                Job::Recycling => "Recycling...",
                Job::Previewing => "Counting...",
                Job::Idle => "",
            };
            text(
                hdc,
                self.fonts.small,
                MUTED,
                RECT {
                    left: self.s(16),
                    top: y + self.s(8),
                    right: self.s(SIDEBAR_W - 16),
                    bottom: y + self.s(30),
                },
                note,
                DT_SINGLELINE | DT_CENTER,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// A rounded box with anti-aliased corners: `fill`, an optional
    /// `border` `width` pixels thick, drawn over a `behind` background.
    unsafe fn panel(
        &mut self,
        hdc: HDC,
        rect: RECT,
        radius: i32,
        fill_color: u32,
        border: u32,
        width: i32,
        behind: u32,
    ) {
        let w = rect.right - rect.left;
        let h = rect.bottom - rect.top;
        let r = radius.min(w / 2).min(h / 2).max(1);
        let key = (r, fill_color, border, width, behind);
        let sprite = *self.corners.entry(key).or_insert_with(|| {
            let part = |c: u32| {
                (
                    (c & 0xff) as u8,
                    ((c >> 8) & 0xff) as u8,
                    ((c >> 16) & 0xff) as u8,
                )
            };
            dib(
                &hive_mend::art::corner_sprite(
                    r as usize,
                    part(fill_color),
                    part(border),
                    width as f32,
                    part(behind),
                ),
                r * 2,
            )
        });
        // Body, then the straight edges, then the four corner quarters.
        fill(
            hdc,
            RECT {
                left: rect.left + r,
                top: rect.top,
                right: rect.right - r,
                bottom: rect.bottom,
            },
            fill_color,
        );
        fill(
            hdc,
            RECT {
                left: rect.left,
                top: rect.top + r,
                right: rect.right,
                bottom: rect.bottom - r,
            },
            fill_color,
        );
        if width > 0 {
            for edge in [
                (rect.left + r, rect.top, rect.right - r, rect.top + width),
                (
                    rect.left + r,
                    rect.bottom - width,
                    rect.right - r,
                    rect.bottom,
                ),
                (rect.left, rect.top + r, rect.left + width, rect.bottom - r),
                (
                    rect.right - width,
                    rect.top + r,
                    rect.right,
                    rect.bottom - r,
                ),
            ] {
                fill(
                    hdc,
                    RECT {
                        left: edge.0,
                        top: edge.1,
                        right: edge.2,
                        bottom: edge.3,
                    },
                    border,
                );
            }
        }
        if sprite.is_null() {
            return;
        }
        let mem = CreateCompatibleDC(hdc);
        let old = SelectObject(mem, sprite);
        for (dx, dy, sx, sy) in [
            (rect.left, rect.top, 0, 0),
            (rect.right - r, rect.top, r, 0),
            (rect.left, rect.bottom - r, 0, r),
            (rect.right - r, rect.bottom - r, r, r),
        ] {
            BitBlt(hdc, dx, dy, r, r, mem, sx, sy, SRCCOPY);
        }
        SelectObject(mem, old);
        DeleteDC(mem);
    }

    unsafe fn heading(&self, hdc: HDC, rect: RECT, title: &str, accent: Option<&str>) {
        let left = self.s(CONTENT_X);
        let top = self.s(TITLE_Y);
        let size = measure(hdc, self.fonts.title, title);
        let spoken = match accent {
            Some(accent) => format!("{title} {accent}"),
            None => title.to_string(),
        };
        self.say(
            RECT {
                left,
                top,
                right: rect.right,
                bottom: top + self.s(40),
            },
            &spoken,
        );
        text(
            hdc,
            self.fonts.title,
            INK,
            RECT {
                left,
                top,
                right: rect.right,
                bottom: top + self.s(40),
            },
            title,
            DT_SINGLELINE,
        );
        if let Some(accent) = accent {
            let x = left + size.0 + self.s(8);
            text(
                hdc,
                self.fonts.title,
                INK,
                RECT {
                    left: x,
                    top,
                    right: rect.right,
                    bottom: top + self.s(40),
                },
                accent,
                DT_SINGLELINE,
            );
        }
    }

    unsafe fn subtitle(&self, hdc: HDC, rect: RECT, line: &str) {
        let left = self.s(CONTENT_X);
        let top = self.s(SUBTITLE_Y);
        self.say(
            RECT {
                left,
                top,
                right: rect.right - self.s(24),
                bottom: top + self.s(26),
            },
            line,
        );
        text(
            hdc,
            self.fonts.body,
            MUTED,
            RECT {
                left,
                top,
                right: rect.right - self.s(24),
                bottom: top + self.s(26),
            },
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

    /// The home page: a status banner with the one primary action, then the
    /// other tools as tiles, then a quiet line of statistics.
    unsafe fn draw_status(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(28);
        let mut y = self.s(TITLE_Y);

        // Status banner.
        let banner = RECT {
            left,
            top: y,
            right,
            bottom: y + self.s(120),
        };
        self.panel(hdc, banner, self.s(10), SURFACE, BORDER, 1, BG);
        let (badge, headline, detail) = self.status_text();
        let badge_px = self.s(72);
        self.draw_icon(
            hdc,
            badge,
            banner.left + self.s(22),
            banner.top + (self.s(120) - badge_px) / 2,
            badge_px,
        );
        let button = RECT {
            left: banner.right - self.s(22) - self.s(150),
            top: banner.top + (self.s(120) - self.s(42)) / 2,
            right: banner.right - self.s(22),
            bottom: banner.top + (self.s(120) + self.s(42)) / 2,
        };
        let text_left = banner.left + self.s(22) + badge_px + self.s(20);
        text(
            hdc,
            self.fonts.title,
            INK,
            RECT {
                left: text_left,
                top: banner.top + self.s(24),
                right: button.left - self.s(16),
                bottom: banner.top + self.s(62),
            },
            &headline,
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        let detail_rect = RECT {
            left: text_left,
            top: banner.top + self.s(64),
            right: button.left - self.s(16),
            bottom: banner.bottom - self.s(12),
        };
        text(
            hdc,
            self.fonts.body,
            MUTED,
            detail_rect,
            &detail,
            DT_WORDBREAK | DT_END_ELLIPSIS,
        );
        // Read as one line: the status, then what it means.
        self.say(
            RECT {
                top: banner.top + self.s(24),
                ..detail_rect
            },
            &format!("{headline}. {detail}"),
        );
        let disabled = self.busy();
        let button_lit = !disabled && lit(hover, button);
        let fill_color = if disabled {
            rgb(160, 176, 166)
        } else if button_lit {
            ACCENT_GREEN_HOVER
        } else {
            ACCENT_GREEN
        };
        self.panel(hdc, button, self.s(8), fill_color, fill_color, 0, SURFACE);
        text(
            hdc,
            self.fonts.body_bold,
            SURFACE,
            button,
            "Scan now",
            DT_SINGLELINE | DT_VCENTER | DT_CENTER,
        );
        self.spot(button, Action::ScanAll, "Scan now");
        y = banner.bottom + self.s(22);

        // Tools grid.
        text(
            hdc,
            self.fonts.heading,
            INK,
            RECT {
                left,
                top: y,
                right,
                bottom: y + self.s(28),
            },
            "Tools",
            DT_SINGLELINE,
        );
        y += self.s(36);
        let tiles = [
            (Icon::Privacy, "Privacy", Action::Page(Page::Privacy)),
            (Icon::Startup, "Startup", Action::Page(Page::Startup)),
            (Icon::Programs, "Programs", Action::Page(Page::Programs)),
            (Icon::DiskSpace, "Disk Space", Action::Page(Page::DiskSpace)),
            (
                Icon::Duplicates,
                "Duplicates",
                Action::Page(Page::Duplicates),
            ),
            (Icon::Optimize, "Services", Action::Page(Page::Services)),
            (Icon::Scan, "Quick Scan", Action::Optimize),
            (Icon::Monitor, "Monitor", Action::Page(Page::Monitor)),
            (Icon::Restore, "Restore", Action::Page(Page::Restore)),
        ];
        let gap = self.s(12);
        let tile_w = (right - left - gap * 2) / 3;
        let tile_h = self.s(84);
        for (index, (icon, label, action)) in tiles.into_iter().enumerate() {
            let column = (index % 3) as i32;
            let row = (index / 3) as i32;
            let tile = RECT {
                left: left + column * (tile_w + gap),
                top: y + row * (tile_h + gap),
                right: left + column * (tile_w + gap) + tile_w,
                bottom: y + row * (tile_h + gap) + tile_h,
            };
            let disabled = action.starts_job() && self.busy();
            let tile_lit = !disabled && lit(hover, tile);
            self.panel(
                hdc,
                tile,
                self.s(10),
                if tile_lit { ACCENT_TINT } else { SURFACE },
                if tile_lit { ACCENT_GREEN } else { BORDER },
                1,
                BG,
            );
            let icon_px = self.s(40);
            self.draw_icon(
                hdc,
                icon,
                tile.left + (tile_w - icon_px) / 2,
                tile.top + self.s(10),
                icon_px,
            );
            text(
                hdc,
                self.fonts.body_bold,
                if disabled { MUTED } else { INK },
                RECT {
                    left: tile.left + self.s(6),
                    top: tile.top + self.s(10) + icon_px + self.s(6),
                    right: tile.right - self.s(6),
                    bottom: tile.bottom - self.s(6),
                },
                label,
                DT_SINGLELINE | DT_CENTER | DT_END_ELLIPSIS,
            );
            self.spot(tile, action, label);
        }
        y += tile_h * 3 + gap * 2 + self.s(18);

        // Statistics, quietly.
        let rows = self.summary_rows();
        let stats = rows
            .iter()
            .filter(|(label, _)| matches!(*label, "Last repair" | "Backups" | "Ignored"))
            .map(|(label, value)| format!("{label}: {value}"))
            .collect::<Vec<_>>()
            .join("   \u{00b7}   ");
        let stats_size = measure(hdc, self.fonts.small, &stats);
        text(
            hdc,
            self.fonts.small,
            MUTED,
            RECT {
                left,
                top: y,
                right,
                bottom: y + self.s(22),
            },
            &stats,
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        let mut x = left + stats_size.0 + self.s(24);
        let mut links: Vec<(&str, Action)> = Vec::new();
        if self.scanned {
            links.push(("View scan results", Action::Page(Page::Scan)));
        }
        links.push(("Reset statistics", Action::ResetStats));
        for (label, action) in links {
            let size = measure(hdc, self.fonts.small, label);
            if x + size.0 > right {
                break;
            }
            let link = RECT {
                left: x,
                top: y,
                right: x + size.0,
                bottom: y + size.1,
            };
            let link_lit = lit(hover, link);
            text(
                hdc,
                self.fonts.small,
                if link_lit { ACCENT_GREEN_HOVER } else { LINK },
                link,
                label,
                DT_SINGLELINE,
            );
            if link_lit {
                fill(
                    hdc,
                    RECT {
                        left: link.left,
                        top: link.bottom - 1,
                        right: link.right,
                        bottom: link.bottom,
                    },
                    ACCENT_GREEN_HOVER,
                );
            }
            self.spot(link, action, label);
            x = link.right + self.s(20);
        }
    }

    /// The home banner's badge, headline, and detail line.
    fn status_text(&self) -> (Icon, String, String) {
        let when = if self.settings.last_scan.is_empty() {
            String::new()
        } else {
            format!(" on {}", self.settings.last_scan)
        };
        if self.job == Job::Scanning {
            return (
                Icon::StatusUnknown,
                "Scanning your registry...".to_string(),
                "Results appear on the Scan page when it finishes.".to_string(),
            );
        }
        match self.settings.last_problems {
            None => (
                Icon::StatusUnknown,
                "No scan yet".to_string(),
                "Scan to find registry entries, shortcuts, and temp files left behind by programs that are no longer installed.".to_string(),
            ),
            Some(0) => (
                Icon::StatusOk,
                "Your registry looks healthy".to_string(),
                if self.last_info > 0 {
                    format!(
                        "The last scan{when} found nothing to fix. {} {} listed on the Scan page for information only.",
                        self.last_info,
                        if self.last_info == 1 { "entry is" } else { "entries are" }
                    )
                } else {
                    format!("The last scan{when} found no stale entries.")
                },
            ),
            Some(count) => (
                Icon::StatusWarn,
                format!(
                    "{count} stale {} found",
                    if count == 1 { "entry" } else { "entries" }
                ),
                format!("From the last scan{when}. Scan again to review and repair them."),
            ),
        }
    }

    unsafe fn draw_privacy(&mut self, hdc: HDC, rect: RECT) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        if self.job == Job::Cleaning {
            self.heading(hdc, rect, "Privacy", None);
            self.subtitle(hdc, rect, "Please keep Hivemend open until it finishes.");
            let text_line = PROGRESS.lock().map(|p| p.text.clone()).unwrap_or_default();
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT {
                    left,
                    top: self.s(BODY_Y + 48),
                    right,
                    bottom: self.s(BODY_Y + 74),
                },
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
            RECT {
                left,
                top: self.s(BODY_Y),
                right,
                bottom: self.s(BODY_Y + 22),
            },
            "Double-click a row for details. Registry entries are backed up first; files are not.",
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    unsafe fn draw_startup(&mut self, hdc: HDC, rect: RECT) {
        self.heading(hdc, rect, "Startup", None);
        let line = if self.startup_note.is_empty() {
            "Programs that start when you sign in to Windows.".to_string()
        } else {
            self.startup_note.clone()
        };
        self.subtitle(hdc, rect, &line);
        text(
            hdc,
            self.fonts.small,
            MUTED,
            RECT {
                left: self.s(CONTENT_X),
                top: self.s(BODY_Y),
                right: rect.right - self.s(24),
                bottom: self.s(BODY_Y + 22),
            },
            "Highlight items, then Enable or Disable. Disabling keeps the program installed, like Task Manager's Startup tab.",
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    unsafe fn draw_programs(&mut self, hdc: HDC, rect: RECT) {
        self.heading(hdc, rect, "Programs", None);
        let line = if self.programs_note.is_empty() {
            "The programs installed on this PC.".to_string()
        } else {
            self.programs_note.clone()
        };
        self.subtitle(hdc, rect, &line);
        text(
            hdc,
            self.fonts.small,
            MUTED,
            RECT {
                left: self.s(CONTENT_X),
                top: self.s(BODY_Y),
                right: rect.right - self.s(24),
                bottom: self.s(BODY_Y + 22),
            },
            "Highlight a program, then Uninstall to start its own uninstaller. Store apps are in Settings > Apps.",
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    unsafe fn draw_disk(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        self.heading(hdc, rect, "Disk Space", None);
        let inside = self
            .disk_report
            .as_ref()
            .filter(|_| self.disk_at != 0 && self.disk_view == DiskView::Folders)
            .map(|report| {
                let node = &report.nodes[self.disk_at];
                format!(
                    "{} holds {} in {}.",
                    report.path_of(self.disk_at),
                    format_bytes(node.bytes),
                    count_of(node.files, "file", "files")
                )
            });
        let line = if self.job == Job::Analyzing {
            "Reading folder sizes. Nothing is changed.".to_string()
        } else if let Some(inside) = inside {
            inside
        } else if !self.disk_note.is_empty() {
            self.disk_note.clone()
        } else {
            "See what takes up space. Hivemend only reads here; it never deletes anything."
                .to_string()
        };
        self.subtitle(hdc, rect, &line);
        // Drive pills on the left; view pills on the right once there is a
        // report.
        let mut x = left;
        let roots = self.disk_roots.clone();
        for (index, (label, _)) in roots.iter().enumerate() {
            let selected = self.disk_root == Some(index);
            x = self.pill(hdc, x, label, selected, hover, Action::DiskRoot(index));
        }
        if self.job == Job::Analyzing {
            let text_line = PROGRESS.lock().map(|p| p.text.clone()).unwrap_or_default();
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT {
                    left,
                    top: self.s(BODY_Y + 84),
                    right,
                    bottom: self.s(BODY_Y + 110),
                },
                &text_line,
                DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX,
            );
            return;
        }
        if self.disk_report.is_none() {
            text(
                hdc,
                self.fonts.body,
                MUTED,
                RECT {
                    left,
                    top: self.s(BODY_Y + 48),
                    right,
                    bottom: self.s(BODY_Y + 120),
                },
                "Pick a drive or your user folder above. Hivemend adds up every folder without following links, then lists the biggest folders, the largest files, and the space by kind of file.",
                DT_WORDBREAK | DT_NOPREFIX,
            );
            return;
        }
        let views = [
            ("Folders", DiskView::Folders),
            ("Largest files", DiskView::Files),
            ("File types", DiskView::Kinds),
        ];
        let widths: i32 = views
            .iter()
            .map(|(label, _)| measure(hdc, self.fonts.body_bold, label).0 + self.s(28 + 8))
            .sum();
        let mut x = (right - widths + self.s(8)).max(x + self.s(16));
        for (label, view) in views {
            let selected = self.disk_view == view;
            x = self.pill(hdc, x, label, selected, hover, Action::DiskView(view));
        }
    }

    unsafe fn draw_dups(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        self.heading(hdc, rect, "Duplicates", None);
        let line = match self.job {
            Job::Finding => "Comparing file contents. Nothing is changed.".to_string(),
            Job::Recycling => "Checking each file again, then moving it.".to_string(),
            _ if !self.dup_note.is_empty() => self.dup_note.clone(),
            _ => "Find identical files of 1 MB or more. Matching is by content, not name."
                .to_string(),
        };
        self.subtitle(hdc, rect, &line);
        let mut x = left;
        let roots = self.disk_roots.clone();
        for (index, (label, _)) in roots.iter().enumerate() {
            let selected = self.dup_root == Some(index);
            x = self.pill(hdc, x, label, selected, hover, Action::DupRoot(index));
        }
        let _ = x;
        if matches!(self.job, Job::Finding | Job::Recycling) {
            let text_line = PROGRESS.lock().map(|p| p.text.clone()).unwrap_or_default();
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT {
                    left,
                    top: self.s(BODY_Y + 84),
                    right,
                    bottom: self.s(BODY_Y + 110),
                },
                &text_line,
                DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX,
            );
            return;
        }
        if self.dup_report.is_none() {
            text(
                hdc,
                self.fonts.body,
                MUTED,
                RECT {
                    left,
                    top: self.s(BODY_Y + 48),
                    right,
                    bottom: self.s(BODY_Y + 140),
                },
                "Pick a drive or your user folder above. The Windows, Program Files, and ProgramData folders are left out, and links and cloud-only files are never read. Ticked copies go to the Recycle Bin, and one copy of every set is always kept.",
                DT_WORDBREAK | DT_NOPREFIX,
            );
        }
    }

    /// A rounded tab-like button; returns where the next one starts.
    unsafe fn pill(
        &mut self,
        hdc: HDC,
        x: i32,
        label: &str,
        selected: bool,
        hover: Option<RECT>,
        action: Action,
    ) -> i32 {
        let size = measure(hdc, self.fonts.body_bold, label);
        let tab = RECT {
            left: x,
            top: self.s(BODY_Y),
            right: x + size.0 + self.s(28),
            bottom: self.s(BODY_Y + 30),
        };
        let lit = lit(hover, tab);
        self.panel(
            hdc,
            tab,
            self.s(14),
            if selected {
                rgb(222, 240, 226)
            } else if lit {
                rgb(240, 247, 241)
            } else {
                rgb(249, 251, 249)
            },
            if selected {
                rgb(46, 130, 76)
            } else {
                rgb(184, 198, 188)
            },
            1,
            BG,
        );
        text(
            hdc,
            self.fonts.body_bold,
            if selected { THEME_INK } else { INK },
            tab,
            label,
            DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX,
        );
        self.spot(tab, action, label);
        tab.right + self.s(8)
    }

    unsafe fn draw_services(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        if self.job == Job::Services {
            self.heading(hdc, rect, "Services", None);
            self.subtitle(hdc, rect, "Please keep Hivemend open until it finishes.");
            let text_line = PROGRESS.lock().map(|p| p.text.clone()).unwrap_or_default();
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT {
                    left,
                    top: self.s(BODY_Y + 48),
                    right,
                    bottom: self.s(BODY_Y + 74),
                },
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
        let tabs = [
            ("Suggested", SvcView::Tuneup),
            ("All services", SvcView::Manage),
        ];
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
            self.panel(
                hdc,
                tab,
                self.s(14),
                if selected {
                    rgb(222, 240, 226)
                } else if lit {
                    rgb(240, 247, 241)
                } else {
                    rgb(249, 251, 249)
                },
                if selected {
                    rgb(46, 130, 76)
                } else {
                    rgb(184, 198, 188)
                },
                1,
                BG,
            );
            text(
                hdc,
                self.fonts.body_bold,
                if selected { THEME_INK } else { INK },
                tab,
                label,
                DT_SINGLELINE | DT_VCENTER | DT_CENTER,
            );
            self.spot(tab, Action::SvcView(view), label);
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
            RECT {
                left: x + self.s(8),
                top: self.s(BODY_Y),
                right,
                bottom: self.s(BODY_Y + 30),
            },
            hint,
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
        );
    }

    unsafe fn draw_scan(&mut self, hdc: HDC, rect: RECT) {
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        match self.job {
            Job::Scanning | Job::Repairing => {
                let title = if self.job == Job::Scanning {
                    "Scanning"
                } else {
                    "Repairing"
                };
                self.heading(hdc, rect, title, None);
                let line = if self.job == Job::Scanning {
                    "Scanning only reads the registry. Nothing is changed."
                } else {
                    "Please keep Hivemend open until the repair finishes."
                };
                self.subtitle(hdc, rect, line);
                let text_line = PROGRESS.lock().map(|p| p.text.clone()).unwrap_or_default();
                text(
                    hdc,
                    self.fonts.body,
                    INK,
                    RECT {
                        left,
                        top: self.s(BODY_Y + 48),
                        right,
                        bottom: self.s(BODY_Y + 74),
                    },
                    &text_line,
                    DT_SINGLELINE | DT_END_ELLIPSIS,
                );
            }
            _ if !self.scanned => {
                self.heading(hdc, rect, "Scan & Repair", None);
                self.subtitle(hdc, rect, "No scan has been run in this session.");
                let width = right.min(left + self.s(720));
                let y = paragraph(
                    hdc,
                    self.fonts.body,
                    INK,
                    left,
                    width,
                    self.s(BODY_Y),
                    "A scan looks for registry entries and shortcuts that point at programs and files that are no longer on this PC. Scanning never changes anything.",
                );
                paragraph(
                    hdc,
                    self.fonts.body,
                    INK,
                    left,
                    width,
                    y + self.s(12),
                    "After the scan you choose what to repair. Every repair saves a backup first, so it can be undone on the Restore page.",
                );
                if !self.scan_note.is_empty() {
                    let note = RECT {
                        left,
                        top: self.s(BODY_Y + 180),
                        right,
                        bottom: self.s(BODY_Y + 206),
                    };
                    text(
                        hdc,
                        self.fonts.body,
                        MUTED,
                        note,
                        &self.scan_note,
                        DT_SINGLELINE,
                    );
                    self.say(note, &self.scan_note);
                }
            }
            _ => {
                self.heading(hdc, rect, "Scan Results", None);
                let line = if self.findings.is_empty() {
                    "Your registry is clean. There is nothing to repair.".to_string()
                } else if self.scan_note.is_empty() {
                    format!("{} problems found.", self.finding_counts().0)
                } else {
                    self.scan_note.clone()
                };
                self.subtitle(hdc, rect, &line);
                let hint = "Ticked rows are repaired. Double-click a row for details, or right-click to ignore it.";
                text(
                    hdc,
                    self.fonts.small,
                    MUTED,
                    RECT {
                        left,
                        top: self.s(BODY_Y - 6),
                        right,
                        bottom: self.s(LIST_Y - 2),
                    },
                    hint,
                    DT_SINGLELINE | DT_END_ELLIPSIS,
                );
            }
        }
    }

    unsafe fn draw_restore(&mut self, hdc: HDC, rect: RECT) {
        self.heading(hdc, rect, "Restore", None);
        // A refresh still reading in the background is not an empty list.
        let reading = BACKUPS.wanted() != self.backups_shown;
        let line = if reading {
            "Reading the backups...".to_string()
        } else if self.backups_failed {
            "The backup folder could not be read. Open this page again to try once more."
                .to_string()
        } else if !self.backup_errors.is_empty() {
            format!(
                "Some backups could not be read and are not listed: {}. Open this page again to try once more.",
                self.backup_errors.first().cloned().unwrap_or_default()
            )
        } else if self.backups.is_empty() {
            "No backups yet. Each repair saves one here before it changes anything.".to_string()
        } else {
            "Each repair saved what it removed. Pick a backup to put those entries back."
                .to_string()
        };
        self.subtitle(hdc, rect, &line);
        if self.job == Job::Restoring {
            text(
                hdc,
                self.fonts.body_bold,
                THEME_INK,
                RECT {
                    left: rect.right - self.s(160),
                    top: self.s(SUBTITLE_Y),
                    right: rect.right - self.s(24),
                    bottom: self.s(SUBTITLE_Y + 24),
                },
                "Restoring...",
                DT_SINGLELINE | DT_RIGHT,
            );
        }
    }

    unsafe fn draw_settings(&mut self, hdc: HDC, rect: RECT) {
        self.heading(hdc, rect, "Settings", None);
        self.subtitle(
            hdc,
            rect,
            if self.elevated {
                "As administrator, Hivemend starts from the defaults, leaves your ignore list out, and forgets changes when it closes. Start Hivemend normally to save them."
            } else {
                "Changes are saved as you make them."
            },
        );
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(24);
        text(
            hdc,
            self.fonts.heading,
            INK,
            RECT {
                left,
                top: self.s(BODY_Y),
                right,
                bottom: self.s(BODY_Y + 28),
            },
            "What Scan Your Registry checks",
            DT_SINGLELINE,
        );
        let top = self.s(SETTINGS_IGNORED_Y);
        text(
            hdc,
            self.fonts.heading,
            INK,
            RECT {
                left,
                top,
                right,
                bottom: top + self.s(28),
            },
            "Ignored entries",
            DT_SINGLELINE,
        );
        text(
            hdc,
            self.fonts.body,
            MUTED,
            RECT {
                left,
                top: top + self.s(30),
                right,
                bottom: top + self.s(56),
            },
            "These never appear in scans, so they are never repaired. To add one, right-click it in the scan results.",
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    unsafe fn draw_monitor(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        self.heading(hdc, rect, "Monitor Your System", None);
        self.subtitle(
            hdc,
            rect,
            "Read when this page paints. Nothing here changes your PC.",
        );
        let snapshot = gather_snapshot();
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(28);
        let label_w = self.s(150);
        let mut y = self.s(BODY_Y);
        for (label, value) in [
            ("Windows", snapshot.os.clone()),
            ("Up time", format_uptime(snapshot.uptime_secs)),
        ] {
            text(
                hdc,
                self.fonts.body_bold,
                INK,
                RECT {
                    left,
                    top: y,
                    right: left + label_w,
                    bottom: y + self.s(24),
                },
                label,
                DT_SINGLELINE,
            );
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT {
                    left: left + label_w,
                    top: y,
                    right,
                    bottom: y + self.s(24),
                },
                &value,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            y += self.s(26);
        }
        y += self.s(4);
        let memory_line = format!(
            "{} of {} in use ({}%)",
            format_bytes(snapshot.memory_used()),
            format_bytes(snapshot.memory_total),
            snapshot.memory_used_percent()
        );
        y = self.meter(
            hdc,
            left,
            right,
            label_w,
            y,
            "Memory",
            &memory_line,
            snapshot.memory_used_percent(),
        );
        let disk_line = format!(
            "{} {} free of {} ({}% used)",
            snapshot.system_drive,
            format_bytes(snapshot.disk_free),
            format_bytes(snapshot.disk_total),
            snapshot.disk_used_percent()
        );
        y = self.meter(
            hdc,
            left,
            right,
            label_w,
            y,
            "System drive",
            &disk_line,
            snapshot.disk_used_percent(),
        );
        y += self.s(14);
        text(
            hdc,
            self.fonts.title,
            INK,
            RECT {
                left,
                top: y,
                right,
                bottom: y + self.s(40),
            },
            "Hivemend Health",
            DT_SINGLELINE,
        );
        y += self.s(46);
        for (label, value) in self.summary_rows() {
            text(
                hdc,
                self.fonts.body_bold,
                INK,
                RECT {
                    left,
                    top: y,
                    right: left + label_w,
                    bottom: y + self.s(24),
                },
                label,
                DT_SINGLELINE,
            );
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT {
                    left: left + label_w,
                    top: y,
                    right,
                    bottom: y + self.s(24),
                },
                &value,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            y += self.s(26);
        }
        y += self.s(10);
        text(
            hdc,
            self.fonts.heading,
            INK,
            RECT {
                left,
                top: y,
                right,
                bottom: y + self.s(26),
            },
            "Registry hives",
            DT_SINGLELINE,
        );
        y += self.s(28);
        let hives = gather_hives();
        if hives.entries.is_empty() {
            text(
                hdc,
                self.fonts.body,
                MUTED,
                RECT {
                    left,
                    top: y,
                    right,
                    bottom: y + self.s(24),
                },
                "The hive list could not be read.",
                DT_SINGLELINE,
            );
            y += self.s(26);
        } else {
            let shown: Vec<&HiveEntry> = hives.entries.iter().take(8).collect();
            let col_w = (right - left) / 2;
            for (index, entry) in shown.iter().enumerate() {
                let x = left + (index % 2) as i32 * col_w;
                let row = y + (index / 2) as i32 * self.s(18);
                let size = entry
                    .bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "unknown".to_string());
                text(
                    hdc,
                    self.fonts.body_bold,
                    INK,
                    RECT {
                        left: x,
                        top: row,
                        right: x + self.s(150),
                        bottom: row + self.s(18),
                    },
                    &hive_label(entry),
                    DT_SINGLELINE | DT_END_ELLIPSIS,
                );
                text(
                    hdc,
                    self.fonts.body,
                    INK,
                    RECT {
                        left: x + self.s(150),
                        top: row,
                        right: x + col_w - self.s(8),
                        bottom: row + self.s(18),
                    },
                    &size,
                    DT_SINGLELINE | DT_END_ELLIPSIS,
                );
            }
            y += shown.len().div_ceil(2) as i32 * self.s(18);
            text(
                hdc,
                self.fonts.body_bold,
                INK,
                RECT {
                    left,
                    top: y,
                    right: left + label_w,
                    bottom: y + self.s(22),
                },
                "Total",
                DT_SINGLELINE,
            );
            let total = if hives.entries.len() > shown.len() {
                format!(
                    "{} in {} hives ({} shown; see hive-mend hives)",
                    format_bytes(hives.total_bytes()),
                    hives.entries.len(),
                    shown.len()
                )
            } else {
                format!(
                    "{} in {} hives",
                    format_bytes(hives.total_bytes()),
                    hives.entries.len()
                )
            };
            text(
                hdc,
                self.fonts.body,
                INK,
                RECT {
                    left: left + label_w,
                    top: y,
                    right,
                    bottom: y + self.s(22),
                },
                &total,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            y += self.s(22);
        }
        text(
            hdc,
            self.fonts.small,
            MUTED,
            RECT {
                left,
                top: y,
                right,
                bottom: y + self.s(18),
            },
            "Sizes only. Windows manages hive space itself; compacting needs a reboot and is not offered.",
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        y += self.s(20);
        y += self.s(6);
        let label = "Refresh readings";
        let size = measure(hdc, self.fonts.body, label);
        let link = RECT {
            left,
            top: y,
            right: left + size.0,
            bottom: y + size.1,
        };
        text(hdc, self.fonts.body, LINK, link, label, DT_SINGLELINE);
        if lit(hover, link) {
            fill(
                hdc,
                RECT {
                    left: link.left,
                    top: link.bottom - 1,
                    right: link.right,
                    bottom: link.bottom,
                },
                LINK,
            );
        }
        self.spot(link, Action::Refresh, label);
    }

    /// Label, value line, and usage bar. Returns the y below the meter.
    #[allow(clippy::too_many_arguments)]
    unsafe fn meter(
        &mut self,
        hdc: HDC,
        left: i32,
        right: i32,
        label_w: i32,
        y: i32,
        label: &str,
        value: &str,
        used: u64,
    ) -> i32 {
        text(
            hdc,
            self.fonts.body_bold,
            INK,
            RECT {
                left,
                top: y,
                right: left + label_w,
                bottom: y + self.s(24),
            },
            label,
            DT_SINGLELINE,
        );
        text(
            hdc,
            self.fonts.body,
            INK,
            RECT {
                left: left + label_w,
                top: y,
                right,
                bottom: y + self.s(24),
            },
            value,
            DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        let bar = RECT {
            left: left + label_w,
            top: y + self.s(28),
            right: (left + label_w + self.s(260)).min(right),
            bottom: y + self.s(40),
        };
        let track = if bar.right - bar.left >= self.s(60) {
            bar
        } else {
            RECT {
                right: bar.left + self.s(60),
                ..bar
            }
        };
        self.panel(
            hdc,
            track,
            self.s(6),
            rgb(236, 242, 238),
            rgb(184, 198, 188),
            1,
            BG,
        );
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
                RECT {
                    left: track.left + self.s(2),
                    top: track.top + self.s(2),
                    right: track.left + self.s(2) + inner,
                    bottom: track.bottom - self.s(2),
                },
                color,
            );
        }
        y + self.s(48)
    }

    unsafe fn draw_tools(&mut self, hdc: HDC, rect: RECT, hover: Option<RECT>) {
        self.heading(hdc, rect, "Windows Tools", None);
        self.subtitle(
            hdc,
            rect,
            "Screens that ship with Windows. Hivemend only opens them.",
        );
        let left = self.s(CONTENT_X);
        let right = rect.right - self.s(28);
        let gap = self.s(12);
        let col_w = (right - left - gap) / 2;
        let rows = WINDOWS_TOOLS.len().div_ceil(2);
        let row_h = self.s(52);
        let step = row_h + self.s(6);
        for (index, tool) in WINDOWS_TOOLS.iter().enumerate() {
            let col = (index / rows) as i32;
            let row = (index % rows) as i32;
            let x = left + col * (col_w + gap);
            let y = self.s(BODY_Y) + row * step;
            let tile = RECT {
                left: x,
                top: y,
                right: x + col_w,
                bottom: y + row_h,
            };
            let lit = lit(hover, tile);
            self.panel(
                hdc,
                tile,
                self.s(10),
                if lit { ACCENT_TINT } else { SURFACE },
                if lit { ACCENT_GREEN } else { BORDER },
                1,
                BG,
            );
            let icon_size = self.s(40);
            self.draw_icon(
                hdc,
                tool.icon,
                tile.left + self.s(8),
                tile.top + (row_h - icon_size) / 2,
                icon_size,
            );
            let text_left = tile.left + self.s(8) + icon_size + self.s(8);
            text(
                hdc,
                self.fonts.body_bold,
                THEME_INK,
                RECT {
                    left: text_left,
                    top: tile.top + self.s(4),
                    right: tile.right - self.s(8),
                    bottom: tile.top + self.s(26),
                },
                tool.name,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            text(
                hdc,
                self.fonts.small,
                MUTED,
                RECT {
                    left: text_left,
                    top: tile.top + self.s(26),
                    right: tile.right - self.s(8),
                    bottom: tile.bottom - self.s(2),
                },
                tool.description,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            self.spot(tile, Action::OpenTool(index), tool.name);
        }
    }

    unsafe fn draw_about(&mut self, hdc: HDC, rect: RECT) {
        self.heading(hdc, rect, "About", None);
        self.subtitle(
            hdc,
            rect,
            &format!(
                "Hivemend {} \u{00b7} a TUIGSE LLC project",
                env!("CARGO_PKG_VERSION")
            ),
        );
        let left = self.s(CONTENT_X);
        let icon_w = self.s(64);
        let right = (rect.right - self.s(24) - icon_w - self.s(24)).max(left + self.s(200));
        self.draw_icon(
            hdc,
            Icon::Logo,
            rect.right - self.s(24) - icon_w,
            self.s(TITLE_Y),
            icon_w,
        );
        // The publisher's emblem beneath the product's logo.
        let emblem_top = self.s(TITLE_Y) + icon_w + self.s(20);
        self.draw_icon(
            hdc,
            Icon::Tuigse,
            rect.right - self.s(24) - icon_w,
            emblem_top,
            icon_w,
        );
        text(
            hdc,
            self.fonts.small,
            MUTED,
            RECT {
                left: rect.right - self.s(24) - icon_w - self.s(20),
                top: emblem_top + icon_w + self.s(4),
                right: rect.right - self.s(4),
                bottom: emblem_top + icon_w + self.s(24),
            },
            "TUIGSE LLC",
            DT_SINGLELINE | DT_CENTER,
        );
        let gap = self.s(10);
        let mut y = self.s(BODY_Y);
        y = paragraph(
            hdc,
            self.fonts.body,
            INK,
            left,
            right,
            y,
            "Hivemend finds registry entries, shortcuts, and old temp files left behind by programs that are no longer installed on Windows 10 or 11, and removes the ones you pick.",
        ) + gap / 2;
        y = paragraph(
            hdc,
            self.fonts.body_bold,
            INK,
            left,
            right,
            y,
            "Use at your own risk: provided as is, without warranty (MIT or Apache-2.0). Notices for the open-source parts it includes are in THIRD-PARTY-NOTICES.txt, shipped with it.",
        ) + gap;
        y = paragraph(
            hdc,
            self.fonts.heading,
            INK,
            left,
            right,
            y,
            "How it keeps your PC safe",
        ) + gap / 2;
        for line in [
            "Scanning only reads. Nothing changes until you choose Repair and confirm.",
            "A file only counts as missing when it is on a local disk that is plugged in. Network, USB, and unreadable paths are left alone.",
            "Before repairing, the ticked entries are checked again. Each registry entry is saved to the backup and removed in one registry transaction, so one that changes meanwhile stays; shortcuts are moved into the backup, and Restore moves them back. Old temporary files are deleted for good and are not backed up.",
            "It never touches Winlogon, default-app choices, the services Windows needs to boot or stay secure, files inside the Windows folder, or built-in protocols such as http.",
            "Services change only on the Services page, one ticked row at a time, with the old start types backed up first.",
            "Privacy cleaning removes only your own history, temp, and cache files; registry entries are backed up first, and thumbnail caches, Prefetch, and Windows system folders are never touched.",
        ] {
            paragraph(
                hdc,
                self.fonts.body,
                THEME_INK,
                left,
                left + self.s(16),
                y,
                "\u{2022}",
            );
            y = paragraph(hdc, self.fonts.body, INK, left + self.s(16), right, y, line) + gap / 2;
        }
        y += gap * 2;
        y = paragraph(
            hdc,
            self.fonts.heading,
            INK,
            left,
            right,
            y,
            "Where things are kept",
        ) + gap / 2;
        for (label, value) in [
            (
                "Backups",
                backups_location()
                    .map(|dir| dir.display().to_string())
                    .unwrap_or_default(),
            ),
            (
                "Settings and ignore list",
                user_dir(&HostFs)
                    .map(|dir| dir.display().to_string())
                    .unwrap_or_default(),
            ),
        ] {
            paragraph(
                hdc,
                self.fonts.body_bold,
                INK,
                left,
                left + self.s(190),
                y,
                label,
            );
            y = paragraph(
                hdc,
                self.fonts.body,
                INK,
                left + self.s(190),
                right,
                y,
                &value,
            ) + gap / 2;
        }
        y += gap / 2;
        paragraph(
            hdc,
            self.fonts.body,
            MUTED,
            left,
            right,
            y,
            "From a terminal, run hivemend --help for the scan, repair, and restore commands.",
        );
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
    format!(
        "{}\\\u{2026}\\{}",
        parts[0],
        parts[parts.len() - tail..].join("\\")
    )
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

/// Why the Restore button does nothing for this backup in this window, if
/// it does nothing. A backup holding only entries a repair never confirmed
/// explains how to recover them by hand instead of offering a restore, in
/// either window. An elevated window restores only machine-wide entries
/// (from the protected store, as checked later); one holding only entries
/// for the account points to a normal window.
fn restore_block(summary: &BackupSummary, path: &Path, elevated: bool) -> Option<String> {
    let restorable = summary.keys + summary.values + summary.files.len();
    if restorable == 0 && !summary.unconfirmed.is_empty() {
        let mut lines: Vec<String> = summary
            .unconfirmed
            .iter()
            .take(10)
            .map(|(entry, key)| format!("entry {entry}: {key}"))
            .collect();
        if summary.unconfirmed.len() > 10 {
            lines.push(format!("...and {} more", summary.unconfirmed.len() - 10));
        }
        return Some(format!(
            "This backup holds only entries the repair never confirmed as removed (it stopped while saving them), so Hivemend does not put them back by itself:\n\n{}\n\nTheir saved data is still in {}. If one is missing from the registry, you can open that file in Notepad, check the entry, and add it back with Registry Editor.",
            lines.join("\n"),
            path.display()
        ));
    }
    // Only the protected store is trusted by an elevated instance. Other
    // folders can be changed by other accounts or by this account's
    // non-elevated programs, so their backups restore only without
    // elevation, which can change only this account's own entries.
    if elevated && !summary.machine_wide {
        return Some(
            "This backup only holds entries for your own account. Restore it from Hivemend started without administrator rights."
                .into(),
        );
    }
    None
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
    if !summary.unconfirmed.is_empty() {
        parts.push(match summary.unconfirmed.len() {
            1 => "1 entry needing manual recovery".to_string(),
            count => format!("{count} entries needing manual recovery"),
        });
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

/// `hive-mend-YYYYMMDD-HHMMSS.reg` in local time, reserved so a name is never
/// reused; `None` when no name could be reserved.
fn next_backup_file() -> Option<hive_mend::BackupWriter> {
    next_backup_file_with("hive-mend")
}

/// `services-YYYYMMDD-HHMMSS.reg` in local time, reserved; `None` on failure.
fn next_services_backup_file() -> Option<hive_mend::BackupWriter> {
    next_backup_file_with("services")
}

/// Backups from every store, newest first, each tagged with its store,
/// with one line per store, entry, or file that could not be read.
fn all_backups(stop: &dyn Fn() -> bool) -> BackupInventory {
    let mut all = BackupInventory::default();
    for (store, dir) in backup_stores() {
        let inventory = list_backups_until(&dir, store, stop);
        all.items.extend(inventory.items);
        all.errors.extend(inventory.errors);
    }
    all.items
        .sort_by_key(|info| std::cmp::Reverse(info.modified));
    all
}

fn next_privacy_backup_file() -> Option<hive_mend::BackupWriter> {
    next_backup_file_with("privacy")
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn next_backup_file_with(prefix: &str) -> Option<hive_mend::BackupWriter> {
    let Ok(dir) = backups_dir() else {
        return None;
    };
    let stamp = unsafe {
        let mut t: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut t);
        format!(
            "{}{:02}{:02}-{:02}{:02}{:02}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
        )
    };
    // Reserved by creating it, and written only through this handle. None
    // when nothing could be reserved, or (as administrator) its signature
    // could not be kept: the caller then changes nothing.
    let mut writer = hive_mend::BackupWriter::reserve(&dir, &format!("{prefix}-{stamp}")).ok()?;
    if hive_mend::sign_protected(&mut writer).is_err() {
        writer.discard();
        return None;
    }
    Some(writer)
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
        CreateFontW(
            -scale(size, dpi),
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            1,
            0,
            0,
            5,
            0,
            wide("Segoe UI").as_ptr(),
        )
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
    for font in [
        fonts.title,
        fonts.heading,
        fonts.body,
        fonts.body_bold,
        fonts.small,
    ] {
        unsafe { DeleteObject(font) };
    }
}

/// A rectangle as comparable numbers: left, top, right, bottom.
type Edges = (i32, i32, i32, i32);

fn edges(rect: RECT) -> Edges {
    (rect.left, rect.top, rect.right, rect.bottom)
}

/// A stand-in control (see [`ID_ACCESS_BASE`]): hidden until placed, and
/// with an empty window region so it never draws or takes mouse input.
fn stand_in(parent: HWND, class: &str, id: u16, button: bool) -> HWND {
    use windows_sys::Win32::Graphics::Gdi::{CreateRectRgn, SetWindowRgn};
    use windows_sys::Win32::UI::WindowsAndMessaging::{BS_NOTIFY, BS_PUSHBUTTON};
    // SS_NOPREFIX: show "&" as itself in a status line.
    const SS_NOPREFIX: u32 = 0x80;
    let style = if button {
        WS_TABSTOP | (BS_PUSHBUTTON | BS_NOTIFY) as u32
    } else {
        SS_NOPREFIX
    };
    unsafe {
        let control = CreateWindowExW(
            0,
            wide(class).as_ptr(),
            std::ptr::null(),
            WS_CHILD | style,
            0,
            0,
            0,
            0,
            parent,
            id as usize as HMENU,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        );
        // The window owns the region from here on.
        SetWindowRgn(control, CreateRectRgn(0, 0, 0, 0), 0);
        control
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

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn hive_label(entry: &HiveEntry) -> String {
    if !entry.file.is_empty() {
        return file_name(&entry.file);
    }
    entry
        .key
        .rsplit('\\')
        .next()
        .unwrap_or(&entry.key)
        .to_string()
}

fn list_view(parent: HWND, id: u16, style: u32, ex_style: u32, columns: &[(&str, i32)]) -> HWND {
    unsafe {
        let list = CreateWindowExW(
            0,
            WC_LISTVIEWW,
            std::ptr::null(),
            WS_CHILD
                | WS_BORDER
                | WS_VSCROLL
                | WS_TABSTOP
                | LVS_REPORT
                | LVS_SHOWSELALWAYS
                | LVS_NOSORTHEADER
                | style,
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
        SendMessageW(
            list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            extended as usize,
            extended as isize,
        );
        SetWindowTheme(list, wide("Explorer").as_ptr(), std::ptr::null());
        for (index, (title, width)) in columns.iter().enumerate() {
            let mut text = wide(title);
            let mut column: LVCOLUMNW = std::mem::zeroed();
            column.mask = LVCF_TEXT | LVCF_WIDTH;
            column.cx = *width;
            column.pszText = text.as_mut_ptr();
            SendMessageW(
                list,
                LVM_INSERTCOLUMNW,
                index,
                &mut column as *mut _ as isize,
            );
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
unsafe fn paragraph(
    hdc: HDC,
    font: HFONT,
    color: u32,
    left: i32,
    right: i32,
    y: i32,
    value: &str,
) -> i32 {
    let old = SelectObject(hdc, font);
    let wide_value = wide(value);
    let mut rect = RECT {
        left,
        top: y,
        right,
        bottom: y,
    };
    DrawTextW(
        hdc,
        wide_value.as_ptr(),
        -1,
        &mut rect,
        DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX,
    );
    SelectObject(hdc, old);
    let height = rect.bottom - rect.top;
    text(
        hdc,
        font,
        color,
        RECT {
            left,
            top: y,
            right,
            bottom: y + height,
        },
        value,
        DT_WORDBREAK,
    );
    y + height
}

unsafe fn measure(hdc: HDC, font: HFONT, value: &str) -> (i32, i32) {
    let old = SelectObject(hdc, font);
    let mut rect = RECT::default();
    let value = wide(value);
    DrawTextW(
        hdc,
        value.as_ptr(),
        -1,
        &mut rect,
        DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX,
    );
    SelectObject(hdc, old);
    (rect.right - rect.left, rect.bottom - rect.top)
}

/// A 32-bit top-down DIB section holding `bgra` (`size` x `size` pixels).
unsafe fn dib(bgra: &[u8], size: i32) -> HBITMAP {
    use windows_sys::Win32::Graphics::Gdi::{
        BITMAPINFO, BITMAPINFOHEADER, CreateDIBSection, DIB_RGB_COLORS,
    };
    let mut info: BITMAPINFO = std::mem::zeroed();
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: size,
        biHeight: -size,
        biPlanes: 1,
        biBitCount: 32,
        ..std::mem::zeroed()
    };
    let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
    let bitmap = CreateDIBSection(
        std::ptr::null_mut(),
        &info,
        DIB_RGB_COLORS,
        &mut bits,
        std::ptr::null_mut(),
        0,
    );
    if bitmap.is_null() || bits.is_null() {
        return std::ptr::null_mut();
    }
    std::ptr::copy_nonoverlapping(bgra.as_ptr(), bits as *mut u8, bgra.len());
    bitmap
}

/// Draw a premultiplied 32-bit bitmap with its alpha channel.
unsafe fn alpha_blit(hdc: HDC, bitmap: HBITMAP, x: i32, y: i32, size: i32) {
    use windows_sys::Win32::Graphics::Gdi::{AC_SRC_ALPHA, AC_SRC_OVER, AlphaBlend, BLENDFUNCTION};
    let mem = CreateCompatibleDC(hdc);
    let old = SelectObject(mem, bitmap);
    let blend = BLENDFUNCTION {
        BlendOp: AC_SRC_OVER as u8,
        BlendFlags: 0,
        SourceConstantAlpha: 255,
        AlphaFormat: AC_SRC_ALPHA as u8,
    };
    AlphaBlend(hdc, x, y, size, size, mem, 0, 0, size, size, blend);
    SelectObject(mem, old);
    DeleteDC(mem);
}

/// The beehive logo as a window icon `size` pixels square.
unsafe fn logo_icon(size: i32) -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
    use windows_sys::Win32::Graphics::Gdi::CreateBitmap;
    use windows_sys::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, ICONINFO};
    let size = size.max(16);
    // Icons take straight (not premultiplied) alpha.
    let rgba = hive_mend::art::render_rgba(Icon::Logo, size as usize);
    let bgra: Vec<u8> = rgba
        .chunks(4)
        .flat_map(|px| [px[2], px[1], px[0], px[3]])
        .collect();
    let color = dib(&bgra, size);
    let mask = CreateBitmap(size, size, 1, 1, std::ptr::null());
    let info = ICONINFO {
        fIcon: 1,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: mask,
        hbmColor: color,
    };
    let icon = CreateIconIndirect(&info);
    DeleteObject(color);
    DeleteObject(mask);
    icon
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
            GlobalFree(memory);
            return;
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), target, data.len());
        GlobalUnlock(memory);
        // The block belongs to the caller until SetClipboardData succeeds.
        if OpenClipboard(hwnd) == 0 {
            GlobalFree(memory);
            return;
        }
        EmptyClipboard();
        if SetClipboardData(CF_UNICODETEXT, memory as HANDLE).is_null() {
            GlobalFree(memory);
        }
        CloseClipboard();
    }
}

/// Queue a shell open for after the handler returns: ShellExecuteW can pump
/// messages (its own error dialog, a DDE or COM wait).
/// When the cookies-to-keep list last changed, or None if there is none.
/// The per-user files Privacy reads: the custom list, the cookies-to-keep
/// list, and the keep list's timestamp.
trait PolicyFiles {
    fn custom(&mut self) -> std::io::Result<Vec<u8>>;
    fn keep(&mut self) -> std::io::Result<String>;
    fn keep_stamp(&mut self) -> Option<std::time::SystemTime>;
}

struct PolicyOnDisk;

impl PolicyFiles for PolicyOnDisk {
    fn custom(&mut self) -> std::io::Result<Vec<u8>> {
        std::fs::read(custom_privacy_file())
    }
    fn keep(&mut self) -> std::io::Result<String> {
        std::fs::read(hive_mend::cookies_keep_file()).map(decode_text_owned)
    }
    fn keep_stamp(&mut self) -> Option<std::time::SystemTime> {
        keep_list_stamp()
    }
}

/// The Privacy page's categories, which are ticked, and the keep list's
/// timestamp. The custom list, the remembered ticks, and the keep list live
/// in the per-user folder, which programs running without elevation can
/// edit: an elevated window touches none of them, not even to see whether
/// they exist. It starts with nothing ticked and says why custom items and
/// browser data are left out.
fn privacy_plan(
    elevated: bool,
    files: &mut dyn PolicyFiles,
    ticked: &[String],
) -> (Vec<PrivacyItem>, Vec<bool>, Option<std::time::SystemTime>) {
    let mut items = build_items();
    if elevated {
        let mut custom = parse_custom("", &HostFs);
        custom.warnings.push(
            "Custom items are not used while Hivemend runs as administrator. Start it without administrator rights to clean them."
                .to_string(),
        );
        items.push(custom);
    } else if let Ok(bytes) = files.custom() {
        let custom = parse_custom(&decode_text_owned(bytes), &HostFs);
        if !custom.targets.is_empty() || !custom.warnings.is_empty() {
            items.push(custom);
        }
    }
    let stamp = if elevated { None } else { files.keep_stamp() };
    if elevated {
        hive_mend::leave_per_user_registry(&mut items);
    }
    let (keep, warnings) = if elevated {
        hive_mend::leave_browsers_alone(&mut items);
        (
            hive_mend::CookieKeep::LeaveAlone(
                "Browser data is cleaned from Hivemend started without administrator rights."
                    .to_string(),
            ),
            Vec::new(),
        )
    } else {
        hive_mend::cookie_keep_choice(files.keep(), false)
    };
    hive_mend::set_cookie_keep(&mut items, &keep);
    for item in items.iter_mut().filter(|item| {
        item.targets
            .iter()
            .any(|target| matches!(target, hive_mend::PrivacyTarget::Cookies { .. }))
    }) {
        item.warnings.extend(
            warnings
                .iter()
                .map(|warning| format!("cookies-keep.txt {warning}")),
        );
    }
    let checked = items
        .iter()
        .map(|item| !elevated && ticked.iter().any(|id| id == &item.id))
        .collect();
    (items, checked, stamp)
}

fn keep_list_stamp() -> Option<std::time::SystemTime> {
    std::fs::metadata(hive_mend::cookies_keep_file())
        .and_then(|meta| meta.modified())
        .ok()
}

/// Duplicates smaller than this are not worth the reading.
const DUP_MIN_BYTES: u64 = 1024 * 1024;

/// `1 file`, `2 files`, `1,000 files`.
fn count_of(count: u64, one: &str, many: &str) -> String {
    format!(
        "{} {}",
        group_digits(count),
        if count == 1 { one } else { many }
    )
}

/// The fixed drives, then the user's own folder, as Disk Space choices.
fn disk_roots() -> Vec<(String, String)> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_FIXED: u32 = 3;
    let mask = unsafe { GetLogicalDrives() };
    let mut roots = Vec::new();
    for letter in 0..26u8 {
        if mask & (1 << letter) == 0 {
            continue;
        }
        let root = format!("{}:\\", (b'A' + letter) as char);
        if unsafe { GetDriveTypeW(wide(&root).as_ptr()) } == DRIVE_FIXED && !is_subst(&root[..2]) {
            roots.push((root[..2].to_string(), root));
        }
    }
    if let Ok(profile) = std::env::var("USERPROFILE")
        && profile.as_bytes().get(1) == Some(&b':')
    {
        roots.push(("Your user folder".to_string(), profile));
    }
    roots
}

/// A SUBST drive: another name for a folder on a real drive, so it is not
/// offered as a drive of its own (it would bypass protected-folder checks
/// spelled for the real drive).
fn is_subst(drive: &str) -> bool {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    let mut target = vec![0u16; 1024];
    let len = unsafe {
        QueryDosDeviceW(
            wide(drive).as_ptr(),
            target.as_mut_ptr(),
            target.len() as u32,
        )
    } as usize;
    len > 0 && String::from_utf16_lossy(&target[..len.min(target.len())]).starts_with(r"\??\")
}

/// Bytes in use on the drive holding `path`, for the progress bar.
fn drive_used_bytes(path: &str) -> u64 {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let Some(drive) = path.get(..2) else {
        return 0;
    };
    let root = wide(&format!("{drive}\\"));
    let (mut caller, mut total, mut free) = (0u64, 0u64, 0u64);
    if unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut caller, &mut total, &mut free) } == 0 {
        return 0;
    }
    total.saturating_sub(free)
}

fn shell_open(_hwnd: HWND, file: &str, args: Option<&str>) {
    // A bare program name would be looked up through folders a normal
    // program can change, which matters most in an administrator window.
    // Windows' own tools (explorer.exe, regedit.exe) live in the Windows
    // folder, so name them there.
    let file = if file.contains(['\\', '/', ':']) {
        file.to_string()
    } else {
        match hive_mend::host_known_dir(hive_mend::KnownDir::Windows) {
            Some(root) => format!(r"{}\{file}", root.trim_end_matches('\\')),
            None => {
                lock(&NATIVE).push_back(Native::Message {
                    text: format!("Could not locate the Windows folder to start {file}."),
                    icon: MB_ICONWARNING,
                });
                return;
            }
        }
    };
    lock(&NATIVE).push_back(Native::Shell {
        file,
        args: args.map(str::to_string),
    });
}

/// Registry Editor opens at its saved `LastKey`, so set that and start it.
/// The setting is written through the link-refusing registry layer, and
/// only from a normal window: an administrator window does not write into
/// the user's own hive, so Registry Editor opens where it last was.
fn open_in_regedit(hwnd: HWND, key: &str, elevated: bool) {
    if !elevated {
        use hive_mend::Registry;
        let _ = WindowsRegistry.set_value(
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit",
            "LastKey",
            &hive_mend::ValueKind::Sz(format!("Computer\\{key}")),
        );
    }
    shell_open(hwnd, "regedit.exe", Some("-m"));
}

/// Start `exe` with `args` without administrator rights, from an
/// administrator window: with a copy of the desktop shell's token, the one
/// every normal window of this account runs with. Refused when the shell
/// belongs to another account or itself runs with administrator rights (User
/// Account Control off), where no such token exists.
fn start_unelevated(exe: &Path, args: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, EqualSid, GetTokenInformation, SecurityImpersonation,
        TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
        TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenPrimary, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessWithTokenW, GetCurrentProcess, OpenProcess, OpenProcessToken,
        PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    let failed = |what: &str| format!("{what} failed ({})", std::io::Error::last_os_error());
    // TOKEN_USER is followed by its SID; 256 bytes hold any SID.
    let user_of = |token: HANDLE| -> Result<Vec<u64>, String> {
        let mut buffer = vec![0u64; 32];
        let mut got = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                &mut got,
            )
        };
        if ok == 0 {
            return Err(failed("GetTokenInformation"));
        }
        Ok(buffer)
    };

    let shell = unsafe { GetShellWindow() };
    let mut pid = 0u32;
    if !shell.is_null() {
        unsafe { GetWindowThreadProcessId(shell, &mut pid) };
    }
    if pid == 0 {
        return Err("the Windows desktop (Explorer) is not running".into());
    }
    let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    if process.0.is_null() {
        return Err(failed("OpenProcess"));
    }
    let mut shell_token = Owned(std::ptr::null_mut());
    if unsafe { OpenProcessToken(process.0, TOKEN_DUPLICATE | TOKEN_QUERY, &mut shell_token.0) }
        == 0
    {
        return Err(failed("OpenProcessToken"));
    }
    let mut own_token = Owned(std::ptr::null_mut());
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own_token.0) } == 0 {
        return Err(failed("OpenProcessToken"));
    }
    let shell_user = user_of(shell_token.0)?;
    let own_user = user_of(own_token.0)?;
    let same = unsafe {
        let shell_sid = (*shell_user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        let own_sid = (*own_user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        EqualSid(shell_sid, own_sid) != 0
    };
    if !same {
        return Err("the Windows desktop belongs to another account".into());
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut got = 0u32;
    if unsafe {
        GetTokenInformation(
            shell_token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut got,
        )
    } == 0
    {
        return Err(failed("GetTokenInformation"));
    }
    if elevation.TokenIsElevated != 0 {
        return Err("Windows runs this account's desktop with administrator rights (User Account Control is off), so there is no way to start a program without them".into());
    }
    let mut token = Owned(std::ptr::null_mut());
    if unsafe {
        DuplicateTokenEx(
            shell_token.0,
            TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut token.0,
        )
    } == 0
    {
        return Err(failed("DuplicateTokenEx"));
    }
    let application = wide(&exe.display().to_string());
    let mut command_line = wide(&format!("\"{}\" {args}", exe.display()));
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut started: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        CreateProcessWithTokenW(
            token.0,
            0,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            0,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut started,
        )
    } == 0
    {
        return Err(failed("CreateProcessWithTokenW"));
    }
    unsafe {
        CloseHandle(started.hThread);
        CloseHandle(started.hProcess);
    }
    Ok(())
}

fn exe_path() -> PathBuf {
    let mut buffer = vec![0u16; 32_768];
    let len = unsafe {
        GetModuleFileNameW(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    buffer.truncate(len as usize);
    PathBuf::from(String::from_utf16_lossy(&buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts every look at the per-user files and gives fixed contents.
    #[derive(Default)]
    struct Watched {
        looks: usize,
    }

    impl PolicyFiles for Watched {
        fn custom(&mut self) -> std::io::Result<Vec<u8>> {
            self.looks += 1;
            Ok(b"file=%TEMP%\\x.tmp\r\n".to_vec())
        }
        fn keep(&mut self) -> std::io::Result<String> {
            self.looks += 1;
            Ok("github.com\r\n".into())
        }
        fn keep_stamp(&mut self) -> Option<std::time::SystemTime> {
            self.looks += 1;
            Some(std::time::SystemTime::now())
        }
    }

    #[test]
    fn a_backup_of_only_unconfirmed_entries_explains_manual_recovery() {
        let text = format!(
            "Windows Registry Editor Version 5.00\r\n\r\n; Hive Mend backup.\r\n{}\r\n\r\n; entry 1\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\HmStale]\r\n\"x\"=\"1\"\r\n",
            hive_mend::FORMAT_2
        );
        let summary = BackupSummary::parse(&text);
        assert_eq!(summary.unconfirmed.len(), 1);
        let path = Path::new(r"C:\ProgramData\HiveMend\backups\hive-mend-1.reg");
        for elevated in [true, false] {
            let text = restore_block(&summary, path, elevated).expect("explained");
            assert!(text.contains("never confirmed"), "{text}");
            assert!(
                text.contains(r"HKEY_LOCAL_MACHINE\SOFTWARE\HmStale"),
                "{text}"
            );
            assert!(text.contains("hive-mend-1.reg"), "{text}");
            assert!(!text.contains("your own account"), "wrong scope: {text}");
        }
        assert!(contents(&summary).contains("manual recovery"));
        // A per-user backup in an elevated window still points elsewhere.
        let user = BackupSummary::parse(
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\X]\r\n\"x\"=\"1\"\r\n",
        );
        assert!(
            restore_block(&user, path, true)
                .unwrap()
                .contains("your own account")
        );
        assert!(restore_block(&user, path, false).is_none());
    }

    #[test]
    fn an_administrator_privacy_page_never_looks_at_per_user_files() {
        let mut files = Watched::default();
        let ticked = vec!["user-temp".to_string(), "chrome-data".to_string()];
        let (items, checked, stamp) = privacy_plan(true, &mut files, &ticked);
        assert_eq!(files.looks, 0, "a per-user file was read or checked");
        assert!(stamp.is_none());
        assert!(checked.iter().all(|on| !on), "remembered ticks were used");
        let custom = items.iter().find(|item| item.id == "custom").unwrap();
        assert!(custom.targets.is_empty());
        // The same plan whatever those files hold: a normal window reads them.
        let mut normal = Watched::default();
        let (_, checked, _) = privacy_plan(false, &mut normal, &ticked);
        assert!(normal.looks >= 3);
        assert!(checked.iter().any(|on| *on));
    }
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        WM_ENTERSIZEMOVE, WM_EXITSIZEMOVE, WM_MOVING, WM_NCLBUTTONDOWN, WM_SIZING, WM_SYSCOMMAND,
    };

    #[test]
    fn the_native_queue_is_unlocked_while_an_item_is_shown() {
        // Stands in for a handler that runs inside a message box and queues
        // another message: it must be able to take the lock.
        lock(&NATIVE).push_back(Native::Message {
            text: "first".into(),
            icon: 0,
        });
        let item = pop_native();
        assert!(item.is_some());
        assert!(NATIVE.try_lock().is_ok(), "the lock outlived the pop");
        lock(&NATIVE).clear();
    }

    #[test]
    fn modal_loop_starters_never_take_the_guard() {
        // Dragging the title bar or a frame edge runs DefWindowProcW's modal
        // loop from these. If they took the guard, every message that loop
        // dispatches (a job finishing, WM_CLOSE, WM_SIZE) would be nested.
        for msg in [
            WM_NCLBUTTONDOWN,
            WM_SYSCOMMAND,
            WM_ENTERSIZEMOVE,
            WM_EXITSIZEMOVE,
            WM_MOVING,
            WM_SIZING,
        ] {
            assert!(!app_handles(msg), "message {msg:#x} must stay default-only");
        }
        for msg in [WM_JOB_DONE, WM_JOB_PROGRESS, WM_CLOSE, WM_SIZE, WM_RELAYOUT] {
            assert!(app_handles(msg), "message {msg:#x} must reach App");
        }
    }

    #[test]
    fn a_progress_tick_cannot_overwrite_a_parked_completion() {
        // Completion, then a late progress tick, then close and a resize, all
        // while a modal pump holds the guard: every one must be redelivered.
        let mut bits = 0;
        for msg in [WM_JOB_DONE, WM_JOB_PROGRESS, WM_CLOSE, WM_SIZE, WM_PAINT] {
            bits |= nested_reply(msg).0;
        }
        assert_eq!(
            deferred_messages(bits),
            vec![WM_RELAYOUT, WM_JOB_PROGRESS, WM_JOB_DONE, WM_CLOSE]
        );
        assert_ne!(bits & DEFER_PAINT, 0);
    }

    #[test]
    fn an_approval_covers_only_the_same_question_and_targets() {
        let approved = approval_key("Repair 2 entries?", "Repair|HKCU\\A|HKCU\\B");
        assert_eq!(
            approved,
            approval_key("Repair 2 entries?", "Repair|HKCU\\A|HKCU\\B")
        );
        // Same question, different entries ticked by the time it re-runs.
        assert_ne!(
            approved,
            approval_key("Repair 2 entries?", "Repair|HKCU\\A|HKCU\\C")
        );
        // Same entries, but the question now says something else.
        assert_ne!(
            approved,
            approval_key(
                "Repair 2 entries? 1 is machine-wide.",
                "Repair|HKCU\\A|HKCU\\B"
            )
        );
    }

    #[test]
    fn redo_and_menu_messages_reach_app() {
        assert!(app_handles(WM_REDO));
        assert!(app_handles(WM_MENU_PICKED));
    }

    #[test]
    fn nested_close_and_job_messages_skip_the_default_handler() {
        // DefWindowProcW's WM_CLOSE destroys the window behind our cleanup.
        assert_eq!(nested_reply(WM_CLOSE).1, NestedReply::Handled);
        assert_eq!(nested_reply(WM_JOB_DONE).1, NestedReply::Handled);
        assert_eq!(nested_reply(WM_SIZE).1, NestedReply::Default);
        assert_eq!(nested_reply(WM_SYSCOMMAND), (0, NestedReply::Default));
    }
}
