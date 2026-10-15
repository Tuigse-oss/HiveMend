#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use hive_mend::{Engine, Exclusions, Repair, ScanOptions, ScannerId, scan};

#[cfg(windows)]
mod gui;

#[cfg(windows)]
use hive_mend::{HostFs, WindowsRegistry, repair};
#[cfg(windows)]
use std::time::SystemTime;

#[derive(Parser)]
#[command(
    name = "hivemend",
    version,
    about = "Scan and repair stale registry entries on Windows 10 and 11"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the scanner jobs.
    Scanners(DataArgs),
    /// Report stale entries. Does not change the registry.
    Scan(ScanArgs),
    /// Back up matching entries, then remove them.
    Repair(RepairArgs),
    /// Merge a backup written by repair and put back its shortcut copies.
    Restore {
        /// The .reg file in the backup folder.
        file: PathBuf,
    },
    /// List the registry hive files and their sizes. Reads only.
    Hives,
    /// Run the built-in sample hive. Useful off Windows.
    Demo,
}

#[derive(Args)]
struct DataArgs {
    /// Extracted legacy cleaner app folder. Loads its scan rules and ignore lists.
    #[arg(long)]
    data: Option<PathBuf>,
    /// Rules XML. Replaces the built-in Windows 10/11 paths before --data is merged.
    #[arg(long)]
    rules: Option<PathBuf>,
}

#[derive(Args)]
struct ScanArgs {
    #[command(flatten)]
    data: DataArgs,
    /// Comma-separated scanner ids, for example SL,SUP,ARP.
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Also run Deep Scan.
    #[arg(long)]
    include_deep: bool,
    /// Stay on the native registry view.
    #[arg(long)]
    no_wow64: bool,
    /// Only keep findings whose location contains this text (case-insensitive).
    #[arg(long = "match")]
    matching: Option<String>,
    /// Also report entries on the ignore list (%LOCALAPPDATA%\HiveMend\ignore.txt).
    #[arg(long)]
    no_ignore_list: bool,
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Args)]
struct RepairArgs {
    #[command(flatten)]
    scan: ScanArgs,
    /// Directory for the UTF-16 .reg backup. Defaults to this account's
    /// backup folder, or the protected store when run as administrator, the
    /// only place an elevated restore reads from.
    #[arg(long)]
    backup_dir: Option<PathBuf>,
    /// Apply the backup's deletions. Without this, repair only prints the plan.
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    hive_mend::adopt_legacy_settings();
    #[cfg(windows)]
    if std::env::args().len() <= 1 {
        return gui::run();
    }
    #[cfg(windows)]
    attach_parent_console();
    match real_main() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("hivemend: {err}");
            ExitCode::from(1)
        }
    }
}

#[cfg(windows)]
fn attach_parent_console() {
    unsafe {
        windows_sys::Win32::System::Console::AttachConsole(0xFFFFFFFF);
    }
}

fn real_main() -> Result<ExitCode, hive_mend::Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scanners(args) => {
            let engine = Engine::load(args.rules.as_deref(), args.data.as_deref())?;
            for scanner in &engine.rules.scanners {
                let state = if scanner.enabled { "on" } else { "off" };
                println!(
                    "{:<5} {:<24} {state:<4} {} paths",
                    scanner.id.code(),
                    scanner.name,
                    scanner.paths.len()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Demo => {
            let sample = hive_mend::sample_world();
            let engine = Engine::try_builtin()?;
            let report = scan(&engine, &sample.reg, &sample.fs, &ScanOptions::default());
            print_text(&report, &[]);
            Ok(if report.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::Restore { file } => restore_live(&file),
        Command::Hives => hives_live(),
        Command::Scan(args) => {
            let engine = load_engine(&args.data)?;
            let opts = options(&args)?;
            let (report, notes) = scan_live(&engine, &opts, &args)?;
            emit(&report, &notes, args.format);
            Ok(scan_exit(&report))
        }
        Command::Repair(args) => {
            let engine = load_engine(&args.scan.data)?;
            let opts = options(&args.scan)?;
            if !args.yes {
                let (report, notes) = scan_live(&engine, &opts, &args.scan)?;
                emit(&report, &notes, args.scan.format);
                let repairable = report
                    .findings
                    .iter()
                    .filter(|finding| finding.repairable())
                    .count();
                // stderr, so JSON on stdout stays one document.
                eprintln!(
                    "{repairable} entries can be repaired. Re-run with --yes to write a backup and apply it."
                );
                return Ok(scan_exit(&report));
            }
            let protected = hive_mend::backups_dir().map_err(hive_mend::Error)?;
            let backup_dir = match &args.backup_dir {
                // As administrator, the backup must go to the protected
                // store: a folder a normal program can change could redirect
                // the write, and an elevated restore reads only that store.
                Some(dir) if hive_mend::elevated() && !same_dir(dir, &protected) => {
                    return Err(hive_mend::Error(format!(
                        "--backup-dir cannot be used as administrator; backups go to {}",
                        protected.display()
                    )));
                }
                Some(dir) => dir.clone(),
                None => protected,
            };
            repair_live(&engine, &opts, &args.scan, &backup_dir)
        }
    }
}

fn load_engine(args: &DataArgs) -> Result<Engine, hive_mend::Error> {
    Engine::load(args.rules.as_deref(), args.data.as_deref())
}

fn options(args: &ScanArgs) -> Result<ScanOptions, hive_mend::Error> {
    let mut only = Vec::new();
    for name in &args.only {
        let id = ScannerId::parse(name).ok_or_else(|| {
            hive_mend::Error(format!(
                "unknown scanner '{name}'. Try: SL, RI, WF, HR, SP, SUP, ARP, VD, FX, PS, CC, DEEP"
            ))
        })?;
        only.push(id);
    }
    Ok(ScanOptions {
        only,
        include_deep: args.include_deep,
        wow64: !args.no_wow64,
    })
}

/// Exit status: 0 for a complete scan with nothing found, 2 when there are
/// findings, 3 when the scan could not read everything (or was stopped)
/// and found nothing, so it cannot be called clean.
fn scan_exit(report: &hive_mend::ScanReport) -> ExitCode {
    if !report.findings.is_empty() {
        ExitCode::from(2)
    } else if scan_complete(report) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}

fn scan_complete(report: &hive_mend::ScanReport) -> bool {
    report.warnings.is_empty() && !report.canceled
}

fn same_dir(a: &std::path::Path, b: &std::path::Path) -> bool {
    let a = a.display().to_string();
    let b = b.display().to_string();
    a.trim_end_matches(['\\', '/'])
        .eq_ignore_ascii_case(b.trim_end_matches(['\\', '/']))
}

/// Drop ignored entries and anything outside `--match`. Returns notes for
/// the reader, which are not scan problems.
fn narrow(report: &mut hive_mend::ScanReport, args: &ScanArgs) -> Vec<String> {
    let mut notes = Vec::new();
    if !args.no_ignore_list {
        let ignored = Exclusions::load(&hive_mend::exclusions_file()).filter(&mut report.findings);
        if ignored > 0 {
            notes.push(format!(
                "{ignored} ignored entries hidden (see --no-ignore-list)"
            ));
        }
    }
    if let Some(text) = &args.matching {
        let needle = text.to_ascii_lowercase();
        report.findings.retain(|finding| {
            finding.key.to_ascii_lowercase().contains(&needle)
                || finding
                    .value
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains(&needle))
        });
    }
    notes
}

fn scan_live(
    engine: &Engine,
    opts: &ScanOptions,
    args: &ScanArgs,
) -> Result<(hive_mend::ScanReport, Vec<String>), hive_mend::Error> {
    #[cfg(windows)]
    {
        let reg = WindowsRegistry;
        let mut report = scan(engine, &reg, &HostFs, opts);
        let notes = narrow(&mut report, args);
        Ok((report, notes))
    }
    #[cfg(not(windows))]
    {
        let _ = (engine, opts, args, narrow);
        Err(hive_mend::Error(
            "live registry scan needs Windows. Use `hivemend demo` on this machine, or build with --target x86_64-pc-windows-msvc".into(),
        ))
    }
}

fn repair_live(
    engine: &Engine,
    opts: &ScanOptions,
    args: &ScanArgs,
    backup_dir: &std::path::Path,
) -> Result<ExitCode, hive_mend::Error> {
    #[cfg(windows)]
    {
        let mut reg = WindowsRegistry;
        let mut report = scan(engine, &reg, &HostFs, opts);
        let mut notes = narrow(&mut report, args);
        // As administrator, per-user registry entries are left for a normal
        // window: a program running without elevation can redirect them.
        if hive_mend::elevated() {
            let before = report.findings.len();
            report.findings.retain(|finding| !finding.per_user());
            let left = before - report.findings.len();
            if left > 0 {
                notes.push(format!(
                    "{left} per-user entries left alone; repair them without administrator rights"
                ));
            }
        }
        let json = matches!(args.format, Format::Json);
        if !json {
            print_text(&report, &notes);
        }
        // Reserve a unique, already-created backup file so a second repair in
        // the same second cannot overwrite this one's recovery record.
        let mut backup = hive_mend::reserve_backup(backup_dir, SystemTime::now())?;
        let mut fs = HostFs;
        let outcome = repair(&mut reg, &mut fs, &report.findings, &mut backup)?;
        if json {
            let errors: Vec<String> = outcome
                .errors
                .iter()
                .map(|err| format!("\"{}\"", escape_json(err)))
                .collect();
            println!(
                "{{\"backup\":\"{}\",\"removed\":{},\"already_gone\":{},\"left_alone\":{},\"needs_admin\":{},\"errors\":[{}]}}",
                escape_json(&outcome.backup_file.display().to_string()),
                outcome.applied,
                outcome.already_gone,
                outcome.refused + outcome.not_backed_up,
                outcome.denied,
                errors.join(",")
            );
        } else {
            println!(
                "backup {}  removed {}  already gone {}  left alone {}  errors {}",
                outcome.backup_file.display(),
                outcome.applied,
                outcome.already_gone,
                outcome.refused + outcome.not_backed_up,
                outcome.errors.len()
            );
        }
        if outcome.denied > 0 {
            eprintln!(
                "hivemend: {} entries need an elevated (Run as administrator) prompt",
                outcome.denied
            );
        }
        for err in &outcome.errors {
            eprintln!("hivemend: {err}");
        }
        Ok(if outcome.errors.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (engine, opts, args, backup_dir);
        Err(hive_mend::Error(
            "repair of a live registry needs Windows".into(),
        ))
    }
}

fn restore_live(file: &std::path::Path) -> Result<ExitCode, hive_mend::Error> {
    #[cfg(windows)]
    {
        let (summary, files, errors) = hive_mend::restore_backup(file).map_err(hive_mend::Error)?;
        println!(
            "restored {} keys, {} values, {files} files from {}",
            summary.keys,
            summary.values,
            file.display()
        );
        for err in &errors {
            eprintln!("hivemend: {err}");
        }
        Ok(if errors.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        })
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Err(hive_mend::Error(
            "restoring a registry backup needs Windows".into(),
        ))
    }
}

fn hives_live() -> Result<ExitCode, hive_mend::Error> {
    #[cfg(windows)]
    {
        let inventory = hive_mend::gather_hives();
        for entry in &inventory.entries {
            let size = entry
                .bytes
                .map(hive_mend::format_bytes)
                .unwrap_or_else(|| "unknown".into());
            let file = if entry.file.is_empty() {
                "(no file)"
            } else {
                &entry.file
            };
            println!("{}  {}  {}", entry.key, size, file);
        }
        println!(
            "{} hives, {} total",
            inventory.entries.len(),
            hive_mend::format_bytes(inventory.total_bytes())
        );
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(not(windows))]
    {
        Err(hive_mend::Error(
            "reading the hive list needs Windows".into(),
        ))
    }
}

fn emit(report: &hive_mend::ScanReport, notes: &[String], format: Format) {
    match format {
        Format::Text => print_text(report, notes),
        Format::Json => println!("{}", report_json(report, notes)),
    }
}

fn print_text(report: &hive_mend::ScanReport, notes: &[String]) {
    if report.findings.is_empty() {
        println!("No stale entries.");
    }
    for finding in &report.findings {
        let value = finding
            .value
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or("(default)");
        let action = match &finding.repair {
            Repair::None => "report",
            Repair::DeleteValue { .. } => "delete value",
            Repair::DeleteKey { .. } => "delete key",
            Repair::DeleteFile { .. } => "delete file",
        };
        println!(
            "[{}] {}  {}  {}  {}  {}",
            finding.scanner.code(),
            finding.scanner_name,
            finding.key,
            value,
            finding.detail,
            action
        );
    }
    println!("{} findings", report.findings.len());
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    if !scan_complete(report) {
        eprintln!("warning: the scan could not read everything, so it is incomplete");
    }
    for note in notes {
        eprintln!("note: {note}");
    }
}

/// One JSON document: whether the scan was complete, the findings, the
/// scan's warnings, and notes.
fn report_json(report: &hive_mend::ScanReport, notes: &[String]) -> String {
    let strings = |items: &[String]| {
        items
            .iter()
            .map(|item| format!("\"{}\"", escape_json(item)))
            .collect::<Vec<_>>()
            .join(",")
    };
    let findings: Vec<String> = report
        .findings
        .iter()
        .map(|finding| {
            let repair = match &finding.repair {
                Repair::None => "none",
                Repair::DeleteValue { .. } => "delete-value",
                Repair::DeleteKey { .. } => "delete-key",
                Repair::DeleteFile { .. } => "delete-file",
            };
            format!(
                "{{\"scanner\":\"{}\",\"name\":\"{}\",\"key\":\"{}\",\"value\":\"{}\",\"detail\":\"{}\",\"repair\":\"{repair}\"}}",
                finding.scanner.code(),
                escape_json(&finding.scanner_name),
                escape_json(&finding.key),
                escape_json(finding.value.as_deref().unwrap_or("")),
                escape_json(&finding.detail),
            )
        })
        .collect();
    format!(
        "{{\"complete\":{},\"findings\":[{}],\"warnings\":[{}],\"notes\":[{}]}}",
        scan_complete(report),
        findings.join(","),
        strings(&report.warnings),
        strings(notes)
    )
}

/// A JSON string body: quotes, backslashes, and every control character
/// escaped.
fn escape_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_strings_escape_every_control_character() {
        let text = "tab\there\nnew \"quoted\" back\\slash \u{1} bell\u{7} é";
        let escaped = escape_json(text);
        assert!(escaped.chars().all(|ch| (ch as u32) >= 0x20));
        assert_eq!(
            escaped,
            "tab\\there\\nnew \\\"quoted\\\" back\\\\slash \\u0001 bell\\u0007 é"
        );
    }

    #[test]
    fn an_incomplete_scan_is_not_reported_as_clean() {
        let clean = hive_mend::ScanReport {
            findings: Vec::new(),
            warnings: Vec::new(),
            canceled: false,
        };
        assert!(scan_complete(&clean));
        assert!(report_json(&clean, &[]).starts_with("{\"complete\":true,"));
        let unread = hive_mend::ScanReport {
            findings: Vec::new(),
            warnings: vec!["HKLM\\SOFTWARE\\X: access denied".into()],
            canceled: false,
        };
        assert!(!scan_complete(&unread));
        let json = report_json(&unread, &["1 ignored entries hidden".into()]);
        assert!(json.starts_with("{\"complete\":false,"));
        assert!(json.contains("\"warnings\":[\"HKLM\\\\SOFTWARE\\\\X: access denied\"]"));
        assert!(json.contains("\"notes\":[\"1 ignored entries hidden\"]"));
    }
}
