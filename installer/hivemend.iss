; Inno Setup script for the Hivemend installer, built by the release workflow:
;   iscc /DAppVersion=0.1.0 installer\hivemend.iss
; SourceDir (default ..\package) holds the same files as the release zip.

#ifndef AppVersion
  #error Pass the version with /DAppVersion=x.y.z
#endif
#ifndef SourceDir
  #define SourceDir "..\package"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
; The AppId identifies the install across upgrades; never change it.
AppId={{6F1C2A4E-8B3D-4E7A-9C51-2D8E0B7F4A93}
AppName=Hivemend
AppVersion={#AppVersion}
AppVerName=Hivemend {#AppVersion}
AppPublisher=TUIGSE LLC
AppPublisherURL=https://github.com/Tuigse-oss/HiveMend
AppSupportURL=https://github.com/Tuigse-oss/HiveMend/issues
AppUpdatesURL=https://github.com/Tuigse-oss/HiveMend/releases
DefaultDirName={autopf}\Hivemend
DefaultGroupName=Hivemend
DisableProgramGroupPage=yes
; The exe runs asInvoker, so a per-user install needs no administrator
; rights; the dialog, or /ALLUSERS for a silent install (winget,
; Chocolatey), installs for all users instead.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline dialog
; An upgrade without /ALLUSERS or /CURRENTUSER keeps the previous install's
; mode, so it replaces that install instead of adding a second one.
UsePreviousPrivileges=yes
UsePreviousAppDir=yes
; Upgrades ask a running Hivemend to close (it refuses while a repair,
; restore, or cleanup is running, and Setup then stops without changing
; anything). It is not restarted: Setup may run as administrator (Chocolatey,
; winget machine scope), and Hivemend must not come back elevated.
CloseApplications=yes
RestartApplications=no
; One Setup at a time, so two package managers cannot upgrade at once.
SetupMutex=HivemendSetup,Global\HivemendSetup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
UninstallDisplayIcon={app}\Hivemend.exe
UninstallDisplayName=Hivemend
VersionInfoVersion={#AppVersion}
LicenseFile={#SourceDir}\LICENSE-MIT
OutputDir={#OutputDir}
OutputBaseFilename=Hivemend-v{#AppVersion}-x86_64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\Hivemend.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "validate-theme-store.ps1"; Flags: dontcopy
Source: "{#SourceDir}\LICENSE-MIT"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE-APACHE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Hivemend"; Filename: "{app}\Hivemend.exe"
Name: "{autodesktop}\Hivemend"; Filename: "{app}\Hivemend.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Hivemend.exe"; Description: "{cm:LaunchProgram,Hivemend}"; Flags: nowait postinstall skipifsilent

; Uninstalling leaves %LOCALAPPDATA%\HiveMend and the administrator backup
; store alone: they hold the registry backups a restore needs.

[Registry]
; Establishes the protected theme store when a /Theme switch is given:
; administrators and SYSTEM hold full control, standard users read. This
; runs before the post-install value write below. Permissions are only
; granted, never scrubbed: a pre-existing hostile grant is left alone
; here and refused at runtime instead. No unins flags, so the key (and
; the default) survives uninstall, as the installer matrix verifies.
Root: HKLM64; Subkey: "SOFTWARE\TUIGSE\Hivemend"; ValueType: none; Permissions: admins-full system-full users-read; Check: ThemeStoreEntryAllowed

[Code]
const
  ThemeKey = 'SOFTWARE\TUIGSE\Hivemend';
  ThemeValue = 'Theme';

{ A /Theme= switch seeds the machine theme default Hivemend starts from:
  /Theme=Light, /Theme=System, or /Theme=Dark (any letter case). With no
  switch Setup writes nothing, so an upgrade keeps the previous machine
  default and a fresh install follows Windows. The per-user settings file
  is never touched here; an in-app Appearance pick always wins over this
  default, and uninstalling leaves both alone. }
function ValidTheme(const S: String): Boolean;
begin
  Result :=
    (CompareText(S, 'light') = 0) or
    (CompareText(S, 'system') = 0) or
    (CompareText(S, 'dark') = 0);
end;

// Presence comes from the raw command line, not from a sentinel default:
// {param} cannot tell an absent switch from one whose value equals the
// default, so any marker literal collides with an explicitly supplied
// value. Every supplied value below is validated; only a genuinely
// absent switch preserves the default.
function ThemeSupplied(): Boolean;
var
  I: Integer;
  Arg: String;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    Arg := ParamStr(I);
    if (CompareText(Copy(Arg, 1, 7), '/Theme=') = 0) or
        (CompareText(Copy(Arg, 1, 7), '/Theme:') = 0) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

{ Rejections happen in InitializeSetup, before anything is installed: a
  late abort (for example in CurStepChanged under /VERYSILENT with
  /SUPPRESSMSGBOXES) can still report exit code 0, which would look like
  success to a package manager. An early refusal installs nothing, so the
  installer checks below verify rejection by its effects, not its exit. }
var
  ThemeStoreVerdict: String;

{ Runs installer/validate-theme-store.ps1 once and caches its verdict
  (ABSENT|... or PROTECTED|...). Anything else, including a validation
  that could not run, refuses the install before any permissions or
  value mutation: Inno Permissions only grant rights and cannot scrub
  an existing hostile grant, so the store must be verified first. }
{ Runs one validation engine. The caller tries pwsh first: some hosts
  cannot load the Security module under Windows PowerShell 5.1, while
  pwsh is absent on others, so launch failure (not a verdict) falls
  through to the other engine. }
function RunValidationEngine(const Engine, Script, VerdictFile: String; var Code: Integer): Boolean;
begin
  Result := Exec(Engine,
    '-NoProfile -ExecutionPolicy Bypass -File "' + Script + '" -OutFile "' + VerdictFile + '"',
    '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function ThemeStoreReady(var Detail: String): Boolean;
var
  Script, VerdictFile: String;
  Loaded: AnsiString;
  Code: Integer;
  Ran: Boolean;
begin
  if ThemeStoreVerdict <> '' then
  begin
    Detail := ThemeStoreVerdict;
  end
  else begin
    Detail := 'validation did not run';
    ExtractTemporaryFile('validate-theme-store.ps1');
    Script := ExpandConstant('{tmp}\validate-theme-store.ps1');
    VerdictFile := ExpandConstant('{tmp}\theme-store-verdict.txt');
    Ran := RunValidationEngine('pwsh.exe', Script, VerdictFile, Code);
    if not Ran then
      Ran := RunValidationEngine('powershell.exe', Script, VerdictFile, Code);
    if Ran and (Code = 0) and LoadStringFromFile(VerdictFile, Loaded) then
      ThemeStoreVerdict := Trim(Loaded)
    else
      ThemeStoreVerdict := 'UNKNOWN|validation did not run';
    Detail := ThemeStoreVerdict;
  end;
  Result := (Copy(Detail, 1, 7) = 'ABSENT|') or (Copy(Detail, 1, 10) = 'PROTECTED|');
end;

{ The [Registry] lock entry and the value write below only run for a
  validated store. InitializeSetup already refuses anything else, so
  this is a second lock on the same cached verdict, never a new check
  with new dialogs. }
function ThemeStoreEntryAllowed(): Boolean;
var
  Detail: String;
begin
  Result := ThemeSupplied() and ThemeStoreReady(Detail);
end;

function InitializeSetup(): Boolean;
var
  Choice, Detail: String;
begin
  Result := True;
  if not ThemeSupplied() then
    Exit;
  Choice := ExpandConstant('{param:Theme|}');
  // An explicitly empty switch lands here as '' and is rejected below,
  // exactly like any other invalid value.
  { A silent refusal shows no dialog: there is nobody to click it, and a
    stuck Setup would hang a package manager (or CI) forever. The refusal
    still installs nothing, which the installer checks verify by effects. }
  if not ValidTheme(Choice) then
  begin
    if not WizardSilent() then
      MsgBox(
        'Invalid /Theme=' + Choice + '. Use /Theme=Light, /Theme=System, or /Theme=Dark.',
        mbError, MB_OK);
    Result := False;
    Exit;
  end;
  { HKLM is administrator-only, which is also why a per-user install cannot
    set a machine default: it says so instead of silently ignoring it. }
  if not IsAdminInstallMode() then
  begin
    if not WizardSilent() then
      MsgBox(
        '/Theme=' + Choice + ' needs an all-users (/ALLUSERS) install, which can write the machine default. ' +
        'Install without /Theme and pick the theme in the app under Settings > Appearance instead.',
        mbError, MB_OK);
    Result := False;
    Exit;
  end;
  { A hostile or uncheckable existing store refuses the whole install:
    writing a value (or adding grants) into a store an untrusted
    principal controls is pointless, and the app would ignore it. }
  if not ThemeStoreReady(Detail) then
  begin
    if not WizardSilent() then
      MsgBox(
        'The machine theme store failed validation, so Setup changed nothing: ' + Detail + '. ' +
        'Remove the untrusted permissions first, then install again.',
        mbError, MB_OK);
    Result := False;
    Exit;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Choice: String;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Choice := ExpandConstant('{param:Theme|}');
  if (Choice <> '') and ValidTheme(Choice) and IsAdminInstallMode() and ThemeStoreEntryAllowed() then
    if not RegWriteStringValue(HKLM64, ThemeKey, ThemeValue, Lowercase(Choice)) then
      RaiseException(
        'Could not save the machine theme default. An all-users install needs administrator rights.');
end;
