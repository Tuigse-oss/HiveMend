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
    name = "hive-mend",
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
    /// Overwrite files so they cannot be recovered, then delete them. Cannot be undone.
    Shred(ShredArgs),
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

#[derive(Args)]
struct ShredArgs {
    /// Files or folders to shred. Shredding cannot be undone.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Overwrite passes: 1, 3, or 7.
    #[arg(long, default_value_t = 3)]
    passes: u8,
    /// Shred without asking. Without this, shred only prints the plan.
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
            eprintln!("hive-mend: {err}");
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
            print_text(&report);
            Ok(if report.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::Restore { file } => restore_live(&file),
        Command::Shred(args) => shred_live(&args),
        Command::Hives => hives_live(),
        Command::Scan(args) => {
            let engine = load_engine(&args.data)?;
            let opts = options(&args)?;
            let report = scan_live(&engine, &opts, &args)?;
            emit(&report, args.format);
            Ok(if report.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::Repair(args) => {
            let engine = load_engine(&args.scan.data)?;
            let opts = options(&args.scan)?;
            if !args.yes {
                let report = scan_live(&engine, &opts, &args.scan)?;
                emit(&report, args.scan.format);
                let repairable = report
                    .findings
                    .iter()
                    .filter(|finding| finding.repairable())
                    .count();
                println!(
                    "{repairable} entries can be repaired. Re-run with --yes to write a backup and apply it."
                );
                return Ok(if report.findings.is_empty() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                });
            }
            let backup_dir = match &args.backup_dir {
                Some(dir) => dir.clone(),
                None => hive_mend::backups_dir().map_err(hive_mend::Error)?,
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

/// Drop ignored entries and anything outside `--match`.
fn narrow(report: &mut hive_mend::ScanReport, args: &ScanArgs) {
    if !args.no_ignore_list {
        let ignored = Exclusions::load(&hive_mend::exclusions_file()).filter(&mut report.findings);
        if ignored > 0 {
            report.warnings.push(format!(
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
}

fn scan_live(
    engine: &Engine,
    opts: &ScanOptions,
    args: &ScanArgs,
) -> Result<hive_mend::ScanReport, hive_mend::Error> {
    #[cfg(windows)]
    {
        let reg = WindowsRegistry;
        let mut report = scan(engine, &reg, &HostFs, opts);
        narrow(&mut report, args);
        Ok(report)
    }
    #[cfg(not(windows))]
    {
        let _ = (engine, opts, args, narrow);
        Err(hive_mend::Error(
            "live registry scan needs Windows. Use `hive-mend demo` on this machine, or build with --target x86_64-pc-windows-msvc".into(),
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
        narrow(&mut report, args);
        print_text(&report);
        // Reserve a unique, already-created backup file so a second repair in
        // the same second cannot overwrite this one's recovery record.
        let backup_file = hive_mend::reserve_backup_path(backup_dir, SystemTime::now())?;
        let mut fs = HostFs;
        let outcome = repair(&mut reg, &mut fs, &report.findings, &backup_file)?;
        println!(
            "backup {}  removed {}  already gone {}  left alone {}  errors {}",
            outcome.backup_file.display(),
            outcome.applied,
            outcome.already_gone,
            outcome.refused + outcome.not_backed_up,
            outcome.errors.len()
        );
        if outcome.denied > 0 {
            eprintln!(
                "hive-mend: {} entries need an elevated (Run as administrator) prompt",
                outcome.denied
            );
        }
        for err in &outcome.errors {
            eprintln!("hive-mend: {err}");
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
            eprintln!("hive-mend: {err}");
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

fn shred_live(args: &ShredArgs) -> Result<ExitCode, hive_mend::Error> {
    use hive_mend::{
        FileView, HostFs, ItemKind, ShredMethod, ShredOptions, ShredTarget, format_bytes,
        shred_allowed, shred_paths,
    };
    let method = ShredMethod::from_passes(args.passes).ok_or_else(|| {
        hive_mend::Error(format!("--passes must be 1, 3, or 7, not {}", args.passes))
    })?;
    let mut targets = Vec::new();
    let mut refused = Vec::new();
    for path in &args.paths {
        let text = path.display().to_string();
        match shred_allowed(&HostFs, &text) {
            Ok(()) => targets.push(ShredTarget {
                path: text.clone(),
                is_dir: HostFs.kind_of(&text) == ItemKind::Dir,
            }),
            Err(reason) => refused.push(reason),
        }
    }
    #[cfg(windows)]
    {
        let mut drives: Vec<String> = Vec::new();
        for target in &targets {
            let bytes = target.path.trim().as_bytes();
            if bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                let drive = format!("{}:", bytes[0].to_ascii_uppercase() as char);
                if !drives.contains(&drive) {
                    drives.push(drive);
                }
            }
        }
        for drive in drives {
            match hive_mend::volume_ssd(&drive) {
                Some(true) => eprintln!(
                    "warning: {drive} is a solid-state drive: shredded data may survive in spare blocks"
                ),
                None => eprintln!("warning: could not tell whether {drive} is solid-state"),
                Some(false) => {}
            }
        }
    }
    if !args.yes {
        for target in &targets {
            println!(
                "{}  {}",
                if target.is_dir { "folder" } else { "file" },
                target.path
            );
        }
        for reason in &refused {
            println!("refused  {reason}");
        }
        println!(
            "{} items would be shredded with {} (cannot be undone). Re-run with --yes to shred.",
            targets.len(),
            method.label()
        );
        return Ok(if targets.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        });
    }
    let opts = ShredOptions {
        method,
        rename: true,
    };
    let outcome = shred_paths(
        &mut HostFs,
        &targets,
        &opts,
        hive_mend::random_seed(),
        &mut |_, _, _| true,
    );
    println!(
        "shredded {} files ({})",
        outcome.shredded,
        format_bytes(outcome.bytes)
    );
    for reason in refused.iter().chain(outcome.refused.iter()) {
        eprintln!("hive-mend: refused: {reason}");
    }
    for err in &outcome.errors {
        eprintln!("hive-mend: {err}");
    }
    Ok(if outcome.errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
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

fn emit(report: &hive_mend::ScanReport, format: Format) {
    match format {
        Format::Text => print_text(report),
        Format::Json => print_json(report),
    }
}

fn print_text(report: &hive_mend::ScanReport) {
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
}

fn print_json(report: &hive_mend::ScanReport) {
    println!("[");
    for (index, finding) in report.findings.iter().enumerate() {
        let comma = if index + 1 == report.findings.len() {
            ""
        } else {
            ","
        };
        let repair = match &finding.repair {
            Repair::None => "none",
            Repair::DeleteValue { .. } => "delete-value",
            Repair::DeleteKey { .. } => "delete-key",
            Repair::DeleteFile { .. } => "delete-file",
        };
        println!(
            "  {{\"scanner\":\"{}\",\"name\":\"{}\",\"key\":\"{}\",\"value\":\"{}\",\"detail\":\"{}\",\"repair\":\"{repair}\"}}{comma}",
            finding.scanner.code(),
            escape_json(&finding.scanner_name),
            escape_json(&finding.key),
            escape_json(finding.value.as_deref().unwrap_or("")),
            escape_json(&finding.detail),
        );
    }
    println!("]");
}

fn escape_json(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}
