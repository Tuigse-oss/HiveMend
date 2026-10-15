# Hivemend

Hivemend scans a Windows 10 or 11 registry for stale entries and can remove them after writing a backup.

> **Use at your own risk.** Hivemend changes the Windows registry and can permanently delete files. It writes a backup before registry changes, but cleaned temp, cache, and Recycle Bin files cannot be recovered. It is provided as is, without warranty of any kind; see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

It covers twelve scanner jobs:

| Id | Job |
| --- | --- |
| SL | App Paths, compatibility leftovers, MuiCache, taskbar usage, UserAssist, and wallpaper or lock-screen paths whose file is gone |
| RI | Shell folders that point at a missing directory (report only) |
| WF | Font registrations whose font file is gone |
| HR | Help-file registrations and sound-event files that are gone |
| SP | Shared DLL values whose file is gone, and AppInit_DLLs lists whose files are all gone |
| SUP | Startup commands, Task Manager StartupApproved orphans, and Command Processor Autorun commands whose program is gone |
| ARP | Uninstall entries, installer sources, ARP cache orphans, mail and media clients, and firewall rules whose program is gone |
| VD | Leftover virtual-device entries |
| FX | Broken Open With lists and progids, open commands, association toasts, and per-user URL protocols |
| PS | Broken shortcuts in the Start Menu and on the Desktop, and temp files older than a day |
| CC | COM controls, type libraries, default icons, shell hooks, preview handlers, autoplay handlers, codecs, context menus, and legacy browser extensions whose file is gone |
| DEEP | Optional wider pass over path-shaped values |

The built-in paths cover the Windows 10 and 11 layout, including per-user uninstall keys and the 32-bit `WOW6432Node` view. There is no self-updater and no license client. In the window, Deep Scan is part of every full scan by default (Settings can leave it out); from the command line it runs only with `--include-deep` or `--only DEEP`.

Shell folders, `UserChoice` file associations, Winlogon, services, files inside the Windows directory, and built-in protocols such as `http` and `ms-settings` are not deleted.

## Build

Rust 1.99.0 is pinned in `rust-toolchain.toml`.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --target x86_64-pc-windows-msvc
```

The MSVC target needs the Microsoft linker, so the release build is meant to run on Windows. From this tree, `cargo test` checks the engine with an in-memory hive.

CI runs the same checks on Linux and Windows for every pull request: formatting, Clippy with warnings denied, and the tests, including live Win32 tests on the Windows runner. It also audits `Cargo.lock` against the [RustSec](https://rustsec.org) advisory database on every change and once a week.

## Use

```bash
hivemend scanners
hivemend scan
hivemend scan --only SL,SUP,ARP
hivemend repair
hivemend repair --yes
hivemend hives
```

`scan` never changes the registry. `repair` without `--yes` prints the plan. With `--yes` it writes a UTF-16 `.reg` backup first, then deletes only the entries that backup describes, and only while each still reads exactly as the backup recorded it: anything added or changed since is left alone.

`--format json` prints one JSON document: `complete`, `findings`, `warnings`, and `notes` for a scan, or the outcome of `repair --yes`. Exit codes: 0 when a complete scan found nothing, 2 when there are findings, 3 when the scan could not read everything (or was stopped) and found nothing, so it cannot be called clean, and 1 on an error.

Run as administrator, `repair` leaves entries in your own part of the registry (HKCU, HKEY_USERS, and HKCR) for a normal window, and `--backup-dir` is refused unless it is the protected store.

### Where data is kept

Settings, the ignore list, custom privacy items, and backups made
without administrator rights live in `%LOCALAPPDATA%\HiveMend`, which only
your account can change. Backups made as administrator go to
`%ProgramData%\HiveMend\backups`, a folder Hivemend creates owned by
Administrators and writable only by SYSTEM and Administrators; if that
folder already exists with any other owner or permissions, Hivemend
refuses to use it rather than repair it. Running as administrator,
Hivemend restores only from that protected folder.

Restore accepts only `.reg` files carrying Hivemend's backup marker
line. The marker only guards against restoring the wrong file by
accident; anyone can write it, so it does not prove where a file came
from. What protects a restore run as administrator is where the file
is: the protected folder, which only administrators can write.

Older versions kept everything in `C:\HiveMend`, which every account on
the PC can change. Hivemend never moves or deletes that folder. Its
backups are still listed, marked as the old shared folder, and can be
restored only from Hivemend started without administrator rights, which
can put back only your own (HKCU) entries. Settings found there are copied
once into the per-user folder.

If you still have an extracted legacy cleaner `app` folder, its original rules and ignore lists can be merged in:

```bash
hivemend scan --data "C:\Path\To\Extracted\app"
```

That reads `Data/rmscan.xml`, `Data/keys.dat`, `Data/values.dat`, and `Data/map.dat` when they are present. Those files are not part of this repository.

`hivemend demo` runs the sample hive on any operating system.

`hivemend hives` lists the registry hive files and their sizes. It only reads. Offline compaction is deliberately not offered: swapping hives at reboot would silently discard everything written after the save, and Windows manages hive space itself.

## Window

Double-clicking the exe opens the window. The left rail lists Home, Scan,
Restore, Privacy, Startup, Programs, Disk Space, Duplicates, Services,
Monitor, Tools, Settings, and About.

- Home leads with the registry's status (healthy, stale entries found, or
  not scanned yet) and a Scan now button, then tiles for Privacy,
  Startup, Programs, Disk Space, Duplicates, Services, Quick Scan (a fast
  startup, uninstall, shared-DLL, and COM pass), Monitor, and Restore,
  and a line of statistics with a reset link.
- Repairs run as administrator first ask Windows for a System Restore
  point ("Hivemend repair"), on top of Hivemend's own `.reg` backup. It
  needs System Protection turned on for the system drive, and Windows
  makes at most one a day; if none is made, or Windows does not confirm
  it, the repair still proceeds and says so. Settings can turn this off
  in a normal window.
- A window run as administrator acts only on what programs running
  without elevation cannot redirect. It leaves registry entries in your
  own part of the registry (HKCU, HKEY_USERS, HKCR) to a normal window,
  restores only the machine-wide part of a backup, starts no
  uninstallers, changes no startup items for your account, removes no
  duplicates, edits no cookie database, and does not read or save your
  settings: it starts from the built-in defaults (restore points on) and
  forgets changes when it closes. The ignore list is read but not
  changed.
- Services has a Suggested tab (safe Automatic services you may tick to
  set to Manual) and an All services tab (start, stop, or change the
  startup type of a highlighted row). Changing a startup type writes a
  `services-*.reg` backup first and can be undone on the Restore page;
  starting or stopping a service is transient and is not backed up.
  Boot drivers and the services Windows needs to boot, update, or stay
  secure are always refused (including the firewall's filtering engine,
  BFE, and UAC's Appinfo). Listing is read-only; changing anything needs
  administrator rights. A backup records an absent delayed-start flag as
  absent, and if a change's second step fails, the first is put back.
- Privacy lists cleanable categories (history lists, temp files,
  clipboard, Recycle Bin, browser caches, application histories, and
  custom items). Preview counts what each holds, tick what to
  clean, then Clean. Registry entries are saved to a `privacy-*.reg`
  backup first and can be undone on the Restore page; files are deleted
  for good. The built-in history and cookie cleaning waits for a closed
  browser (checked again just before each category runs) and never
  touches saved logins, saved addresses or cards, or bookmarks. For
  Chrome and Edge it clears browsing history and cookies; for Firefox it
  clears cookies and saved form entries, and leaves browsing history and
  bookmarks (they share one file). A Temp file listed for being older
  than two days is left alone if it was written to since. Custom
  items you add can name any allowed Temp or browser-profile file, so add
  only paths you understand. The built-in categories are user-scope, and
  no administrator rights are needed. There is no free-space wipe:
  overwriting a drive's empty space does not reliably erase anything on
  SSD or NVMe drives and only adds wear. For the same reason there is no
  file shredder: on solid-state drives a normal delete is cleared by the
  drive itself (TRIM), and BitLocker or Device Encryption is what keeps
  deleted data unreadable.
- Startup lists the programs that start at sign-in, as Task Manager's
  Startup tab does: the `Run` keys (your account, all users, and 32-bit)
  and both Startup folders. Disable and Enable flip the same
  `StartupApproved` switch Task Manager uses, so nothing is deleted and
  the two always agree. The previous switches are saved to a
  `startup-*.reg` backup first and can be undone on the Restore page.
  Items that start for all users need administrator rights, and items
  for your account are changed from a normal window. A flag that cannot
  be read is left alone rather than recorded as absent.
- Programs lists installed programs as Programs and Features does
  (name, publisher, install date, size, version) and starts a program's
  own uninstaller; Hivemend never removes program files itself. The
  registered command is resolved to one existing `.exe` (a bare tool name
  such as `MsiExec.exe` only from System32, an app alias such as
  `winget.exe` only from your WindowsApps folder) or refused. A window
  run as administrator starts no uninstallers: from a normal window, the
  uninstaller asks for administrator rights itself if it needs them.
- Disk Space adds up a fixed drive or your user folder and lists the
  biggest folders (double-click or Enter to go in, Backspace to go up),
  the 100 largest files, and the space by kind of file. Sizes are file
  sizes. Junctions and symbolic links are never followed, so nothing is
  counted twice. It only reads; Open in Explorer is the only action.
- Duplicates finds identical files of 1 MB or more in a fixed drive or
  your user folder, matching by content (size, then a hash of the first
  64 KB, then of the whole file), never by name. The Windows, Program
  Files, and ProgramData folders are left out; links, junctions, and
  cloud-only files are never followed or read, and a hard link is not
  counted as a copy. Tick Extra Copies ticks all but the first copy of
  each set. Ticked files go to the Recycle Bin (Windows warns first if a
  file would be deleted for good instead). One copy of every set is
  always kept and held open so it cannot change or go away meanwhile.
  Each file to move is held open against writes from its checks until
  it is moved: its real location must be outside the protected folders
  (a SUBST drive or junction cannot hide it), it must have no extra data
  streams besides the download marker, and its bytes must still match
  the kept copy. Removing is only done without administrator rights.
- Monitor shows live memory, system-drive, and uptime readings with
  usage bars, plus the Hivemend health summary and a read-only
  registry-hive inventory with sizes. It only reads.
- Tools opens screens that ship with Windows (Device Manager, Services,
  System Restore, Windows Update, and the rest). Hivemend only
  launches them.
- The header Help link opens About, which explains the safety rules.

The artwork is original and drawn in code (`src/art.rs`): Celtic and
Scottish symbols for each tool, in the same green and gold as the window,
rendered at the screen's own scale. Nothing is loaded from image files.
`cargo run --example icon_sheet -- icons.png` writes a preview sheet.

Cookies to keep live in `%LOCALAPPDATA%\HiveMend\cookies-keep.txt`, one site
per line (`github.com` keeps its subdomains too); the Cookies to Keep button
on the Privacy page opens it in Notepad. With an empty list, cleaning a
browser's history and cookies deletes its cookie database (for Chrome and
Edge, `Network\Cookies`). With sites listed, Hivemend edits the database
instead, only while the browser is closed: it copies the database, removes
every other cookie in one SQLite transaction, checks the database, and puts
the copy back if anything fails. The copy is deleted after a good edit, so
no spare set of cookies is left behind. A window running as administrator
leaves cookies alone when the list has sites.

Custom privacy items live in `%LOCALAPPDATA%\HiveMend\privacy-custom.ini`, one
per line (`#` starts a comment). Only Temp folders, browser profiles,
and your own history keys are allowed; anything else is refused with a
reason shown on the Custom row. Hivemend running as administrator leaves
the custom list out and starts with no privacy category ticked, because
programs running without administrator rights can edit those per-user
files; clean custom items from a window started normally.

```ini
file=%TEMP%\myapp\session.log
files=%TEMP%\myapp|*.log
files-rec=%TMP%\myapp|*.tmp
value=HKCU\Software\MyApp\Settings|RecentFile1
```

## Releases

Releases are built by CI from a version tag after a RustSec audit, Clippy, and the tests pass. Each one is a zip holding `Hivemend.exe`, the MIT and Apache-2.0 license files, `THIRD-PARTY-NOTICES.txt` (the license and copyright notices of the crates built into the program and of the Rust standard library), and this README, with `SHA256SUMS.txt` beside it. The exe embeds its dependency list so it can be audited after download, and once the repository is public each build also carries a GitHub build provenance attestation:

```bash
gh attestation verify Hivemend-v0.1.0-x86_64-windows.zip --repo bradwilliamson/HiveMend
cargo audit bin Hivemend.exe
```

After changing `Cargo.lock`, regenerate the notices with `python3 scripts/third-party-notices.py`; a test fails until they cover every linked crate.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Made by TUIGSE LLC

<img src="docs/tuigse-emblem.png" width="96" alt="TUIGSE LLC emblem">

Hivemend is a TUIGSE LLC project.

## License

Licensed under either of the MIT license ([LICENSE-MIT](LICENSE-MIT)) or
the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) at your
option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project is licensed the same way.

The TUIGSE LLC name and emblem (`assets/tuigse-emblem-256.bgra`,
`docs/tuigse-emblem.png`) are TUIGSE LLC's marks. They are not licensed under
MIT or Apache-2.0; forks should remove or replace them.
