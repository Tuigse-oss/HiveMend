use std::time::Duration;

use crate::fs::MemoryFs;
use crate::lnk::sample_lnk;
use crate::registry::MemoryRegistry;

pub struct Sample {
    pub reg: MemoryRegistry,
    pub fs: MemoryFs,
}

pub fn sample_world() -> Sample {
    let mut fs = MemoryFs::new();
    fs.set_var("SystemRoot", r"C:\Windows");
    fs.set_var("ProgramFiles", r"C:\Program Files");
    fs.set_var("ProgramFiles(x86)", r"C:\Program Files (x86)");
    fs.set_var("APPDATA", r"C:\Users\Ada\AppData\Roaming");
    fs.set_var("LOCALAPPDATA", r"C:\Users\Ada\AppData\Local");
    fs.set_var("ProgramData", r"C:\ProgramData");
    fs.set_var("USERPROFILE", r"C:\Users\Ada");
    fs.set_var("TEMP", r"C:\Users\Ada\AppData\Local\Temp");
    fs.set_var("PATH", r"C:\Windows\System32");
    fs.add_file(r"C:\Windows\System32\cmd.exe");
    fs.add_file(r"C:\Windows\SysWOW64\comctl32.dll");
    fs.add_file(r"C:\Windows\Fonts\arial.ttf");
    fs.add_file(r"C:\Program Files\Keep\keep.exe");
    fs.add_dir(r"C:\Program Files\Keep");
    fs.add_dir(r"C:\Users\Ada\Desktop");
    fs.add_file(
        r"C:\Users\Ada\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\keep.lnk",
    );
    fs.add_file_bytes(
        r"C:\Users\Ada\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\broken.lnk",
        sample_lnk(r"C:\Missing\old.exe"),
        None,
    );
    fs.add_file_bytes(
        r"C:\Users\Ada\AppData\Local\Temp\old.tmp",
        Vec::new(),
        Some(Duration::from_secs(3 * 86_400)),
    );
    fs.add_file_bytes(
        r"C:\Users\Ada\AppData\Local\Temp\fresh.tmp",
        Vec::new(),
        Some(Duration::from_secs(10)),
    );
    fs.add_file(r"C:\Users\Ada\AppData\Local\Temp\desktop.ini");

    let mut reg = MemoryRegistry::new();
    reg.set_sz(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\keep.exe",
        "",
        r"C:\Program Files\Keep\keep.exe",
    );
    reg.set_sz(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\gone.exe",
        "",
        r"C:\Missing\gone.exe",
    );
    let run = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    reg.set_sz(run, "Keep", r"C:\Program Files\Keep\keep.exe");
    reg.set_sz(run, "Old", r#""C:\Missing\old.exe" --x"#);
    reg.set_sz(run, "Cmd", r"C:\Windows\System32\cmd.exe");
    reg.set_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
        r"C:\Missing\shared.dll",
        1,
    );
    reg.set_dword(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
        r"C:\Windows\System32\cmd.exe",
        1,
    );
    reg.set_sz(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts",
        "Arial",
        "arial.ttf",
    );
    reg.set_sz(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts",
        "MissingFont",
        "missing.ttf",
    );
    reg.set_sz(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "Desktop",
        r"C:\Users\Ada\Desktop",
    );
    reg.set_sz(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "Personal",
        r"C:\Missing\Documents",
    );
    let keep = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Keep";
    reg.set_sz(
        keep,
        "UninstallString",
        r"C:\Program Files\Keep\keep.exe /uninstall",
    );
    reg.set_sz(keep, "InstallLocation", r"C:\Program Files\Keep");
    let gone = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Gone";
    reg.set_sz(gone, "UninstallString", r"C:\Missing\gone.exe /uninstall");
    reg.set_sz(gone, "InstallLocation", r"C:\Missing\Gone");
    reg.set_sz(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KB123456",
        "UninstallString",
        r"C:\Missing\kb.exe",
    );
    let component = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Component";
    reg.set_sz(component, "UninstallString", r"C:\Missing\comp.exe");
    reg.set_dword(component, "SystemComponent", 1);
    reg.set_sz(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
        r"C:\Missing\Gone",
        "",
    );
    reg.set_sz(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
        r"C:\Program Files\Keep",
        "",
    );
    reg.set_sz(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithList",
        "a",
        "gone.exe",
    );
    reg.set_sz(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithList",
        "MRUList",
        "a",
    );
    reg.set_sz(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice",
        "ProgId",
        "txtfile",
    );
    reg.set_sz(r"HKCU\Software\Classes\.demo", "", "Demo.File");
    reg.set_sz(
        r"HKCU\Software\Classes\Demo.File\shell\open\command",
        "",
        r"C:\Missing\demo.exe %1",
    );
    reg.set_sz(
        r"HKLM\SOFTWARE\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\InprocServer32",
        "",
        r"C:\Missing\ctl.ocx",
    );
    reg.set_sz(
        r"HKLM\SOFTWARE\Classes\CLSID\{22222222-2222-2222-2222-222222222222}\InprocServer32",
        "",
        r"C:\Windows\System32\comctl32.dll",
    );
    reg.set_sz(
        r"HKLM\SYSTEM\CurrentControlSet\Services\VxD\OldDrv",
        "StaticVxD",
        r"C:\Missing\old.vxd",
    );
    reg.set_sz(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Shell",
        r"C:\Missing\should-not-delete.exe",
    );

    Sample { reg, fs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Engine, repair, scan};
    use crate::model::{Repair, ScanOptions, ScannerId};
    use crate::registry::Registry;

    #[test]
    fn sample_scan_matches_the_ported_jobs() {
        let sample = sample_world();
        let report = scan(
            &Engine::try_builtin().unwrap(),
            &sample.reg,
            &sample.fs,
            &ScanOptions::default(),
        );
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        let of = |id| -> Vec<_> {
            report
                .findings
                .iter()
                .filter(|finding| finding.scanner == id)
                .map(|finding| finding.detail.clone())
                .collect()
        };
        assert_eq!(of(ScannerId::SoftwareLocations).len(), 1);
        assert_eq!(of(ScannerId::StartupPrograms).len(), 1);
        assert_eq!(of(ScannerId::SharedDlls).len(), 1);
        assert_eq!(of(ScannerId::WindowsFonts).len(), 1);
        assert_eq!(of(ScannerId::RegistryIntegrity).len(), 1);
        assert!(matches!(
            report
                .findings
                .iter()
                .find(|finding| finding.scanner == ScannerId::RegistryIntegrity)
                .unwrap()
                .repair,
            Repair::None
        ));
        assert_eq!(of(ScannerId::AddRemovePrograms).len(), 2);
        assert_eq!(of(ScannerId::FileExtensions).len(), 2);
        assert_eq!(of(ScannerId::CustomControls).len(), 1);
        assert_eq!(of(ScannerId::TempShortcuts).len(), 2);
        assert_eq!(of(ScannerId::VirtualDevices).len(), 1);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.key.to_ascii_lowercase().contains("winlogon"))
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.key.to_ascii_lowercase().contains("userchoice"))
        );
    }

    #[test]
    fn repair_removes_a_startup_value_and_refuses_winlogon() {
        let mut sample = sample_world();
        let report = scan(
            &Engine::try_builtin().unwrap(),
            &sample.reg,
            &sample.fs,
            &ScanOptions::default(),
        );
        let startup = report
            .findings
            .iter()
            .find(|finding| finding.scanner == ScannerId::StartupPrograms)
            .unwrap()
            .clone();
        let mut planted = startup.clone();
        planted.key =
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon".into();
        planted.repair = Repair::DeleteValue {
            key: planted.key.clone(),
            name: "Shell".into(),
        };
        let mut backup = crate::backup::test_writer("hive-mend-test-backup");
        let outcome = repair(
            &mut sample.reg,
            &mut sample.fs,
            &[startup, planted],
            &mut backup,
        )
        .unwrap();
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.refused, 1);
        assert_eq!(outcome.resolved.len(), 1);
        let run = sample
            .reg
            .values(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
            .unwrap();
        assert!(run.iter().all(|value| value.name != "Old"));
        assert!(run.iter().any(|value| value.name == "Keep"));
        let winlogon = sample
            .reg
            .values(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
            .unwrap();
        assert!(winlogon.iter().any(|value| value.name == "Shell"));
        let saved = std::fs::read(backup.path()).unwrap();
        assert_eq!(&saved[..2], &[0xFF, 0xFE]);
        let _ = std::fs::remove_file(backup.path());
    }
}
