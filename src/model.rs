/// Scanner ids shared with the classic `rmscan.xml` rule files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScannerId {
    SoftwareLocations,
    RegistryIntegrity,
    WindowsFonts,
    HelpResources,
    SharedDlls,
    StartupPrograms,
    AddRemovePrograms,
    VirtualDevices,
    FileExtensions,
    TempShortcuts,
    CustomControls,
    DeepScan,
}

impl ScannerId {
    pub const ALL: [ScannerId; 12] = [
        Self::SoftwareLocations,
        Self::RegistryIntegrity,
        Self::WindowsFonts,
        Self::HelpResources,
        Self::SharedDlls,
        Self::StartupPrograms,
        Self::AddRemovePrograms,
        Self::VirtualDevices,
        Self::FileExtensions,
        Self::TempShortcuts,
        Self::CustomControls,
        Self::DeepScan,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Self::SoftwareLocations => "SL",
            Self::RegistryIntegrity => "RI",
            Self::WindowsFonts => "WF",
            Self::HelpResources => "HR",
            Self::SharedDlls => "SP",
            Self::StartupPrograms => "SUP",
            Self::AddRemovePrograms => "ARP",
            Self::VirtualDevices => "VD",
            Self::FileExtensions => "FX",
            Self::TempShortcuts => "PS",
            Self::CustomControls => "CC",
            Self::DeepScan => "DEEP",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_uppercase().as_str() {
            "SL" | "SOFTWARE LOCATIONS" => Some(Self::SoftwareLocations),
            "RI" | "REGISTRY INTEGRITY" => Some(Self::RegistryIntegrity),
            "WF" | "WINDOWS FONTS" => Some(Self::WindowsFonts),
            "HR" | "HELP AND RESOURCES" => Some(Self::HelpResources),
            "SP" | "SHARED DLLS" => Some(Self::SharedDlls),
            "SUP" | "STARTUP PROGRAMS" => Some(Self::StartupPrograms),
            "ARP" | "ADD/REMOVE PROGRAMS" => Some(Self::AddRemovePrograms),
            "VD" | "VIRTUAL DEVICES" => Some(Self::VirtualDevices),
            "FX" | "FILE EXTENSIONS" => Some(Self::FileExtensions),
            "PS" | "TEMP FILES / SHORTCUTS" => Some(Self::TempShortcuts),
            "CC" | "CUSTOM CONTROLS" => Some(Self::CustomControls),
            "DEEP" | "DEEP SCAN" => Some(Self::DeepScan),
            _ => None,
        }
    }
}

/// How a rule path is interpreted. `Inherited` is the scanner's original job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    Inherited,
    /// The value name is a filesystem path.
    ValueNamePath,
    /// MuiCache names are `path.FriendlyAppName` or `path.ApplicationCompany`.
    MuiCache,
    /// Task Manager enable/disable blobs whose startup entry is gone.
    StartupApproved,
    /// `ApplicationAssociationToasts` value names.
    AssociationToast,
    /// `shell\<verb>\command` entries.
    ShellCommand,
    /// `shellex` handler keys whose default value is a CLSID.
    ShellHandler,
    /// Subkey names are CLSIDs, as with Browser Helper Objects.
    ClsidKey,
    /// Legacy Internet Explorer toolbar buttons.
    IeExtension,
    /// `TypeLib\{guid}\<version>\<lcid>\win32|win64` paths.
    TypeLib,
    /// `\<class>\DefaultIcon` values.
    DefaultIcon,
    /// `Applications\<program.exe>\shell\open\command` and `DefaultIcon`.
    Applications,
    /// `AppEvents\Schemes\Apps\<app>\<event>\.Current` wave files.
    SoundEvent,
    /// Add/Remove cache subkeys whose uninstall key is already gone.
    ArpCache,
    /// `Clients\StartMenuInternet\<browser>` when its exe is gone.
    StartMenuClient,
    /// ROT13 program paths under `Explorer\UserAssist`.
    UserAssist,
    /// String values on the key that are filesystem paths.
    PathValue,
    /// Per-user URL protocols whose open command is gone.
    UrlProtocol,
    /// Value names or data that are CLSIDs, as in ShellExecuteHooks and preview handlers.
    ClsidValue,
    /// AutoPlay handler whose icon or program file is gone.
    Autoplay,
    /// `Drivers32` codec values.
    Codec,
    /// `AppInit_DLLs` when every listed file is gone.
    AppInit,
    /// `Command Processor\Autorun` when its program is gone.
    CommandAutorun,
    /// Windows Installer `InstallSource` / `LocalPackage` values.
    InstallerSource,
    /// Firewall rule whose `App=` path is gone.
    FirewallRule,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulePath {
    pub path: String,
    pub kind: PathKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannerDef {
    pub id: ScannerId,
    pub name: String,
    pub paths: Vec<RulePath>,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueKind {
    Sz(String),
    ExpandSz(String),
    Dword(u32),
    MultiSz(Vec<String>),
    Binary(Vec<u8>),
    Other { kind: u32, bytes: Vec<u8> },
}

impl ValueKind {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Sz(text) | Self::ExpandSz(text) => Some(text),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegValue {
    /// Empty string is the key's default value.
    pub name: String,
    pub data: ValueKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Repair {
    None,
    DeleteValue {
        key: String,
        name: String,
    },
    DeleteKey {
        key: String,
    },
    /// `keep_copy` is false for bulky temp files. The path is still logged.
    DeleteFile {
        path: String,
        keep_copy: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub scanner: ScannerId,
    pub scanner_name: String,
    pub key: String,
    pub value: Option<String>,
    pub detail: String,
    pub repair: Repair,
}

impl Finding {
    /// A registry repair in a hive the signed-in user can write, which an
    /// administrator window leaves to a normal window.
    pub fn per_user(&self) -> bool {
        match &self.repair {
            Repair::DeleteValue { key, .. } | Repair::DeleteKey { key } => {
                crate::pathutil::per_user_key(key)
            }
            Repair::None | Repair::DeleteFile { .. } => false,
        }
    }

    pub fn repairable(&self) -> bool {
        !matches!(self.repair, Repair::None)
    }

    /// Deleting this cannot be undone from a backup.
    pub fn permanent(&self) -> bool {
        matches!(
            self.repair,
            Repair::DeleteFile {
                keep_copy: false,
                ..
            }
        )
    }

    /// The repair writes to a machine-wide key or shared folder.
    pub fn needs_admin(&self) -> bool {
        match &self.repair {
            Repair::None => false,
            Repair::DeleteValue { key, .. } | Repair::DeleteKey { key } => {
                crate::pathutil::needs_admin(key)
            }
            Repair::DeleteFile { path, .. } => crate::pathutil::needs_admin(path),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// Empty means every enabled scanner.
    pub only: Vec<ScannerId>,
    pub include_deep: bool,
    /// Also walk `WOW6432Node` mirrors of `HKLM\SOFTWARE` rules.
    pub wow64: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            only: Vec::new(),
            include_deep: false,
            wow64: true,
        }
    }
}

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}
