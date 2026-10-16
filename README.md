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

`scan` never changes the registry. `repair` without `--yes` prints the plan. With `--yes` each entry is removed inside its own registry transaction (Windows' Kernel Transaction Manager): the entry is read from that transaction, recorded in the UTF-16 `.reg` backup, and the backup flushed to disk before the deletion commits. Before anything is removed, the entry's section is read back with the restore's own parser, and a key removal deletes exactly the keys it recorded: a key that appears meanwhile stops it. Only after the commit is `; entry N removed` written, and a restore puts back only entries confirmed that way, so a run that stops part way never offers back something that was not removed (such entries are listed instead, and their data stays in the file). If another program changes the entry meanwhile, or any step fails, the transaction is rolled back and the entry stays. Where Windows cannot open a registry transaction, nothing is removed. If the backup cannot be written, the repair stops; an entry whose backup would pass the 64 MB a restore accepts is left alone. A shortcut is never deleted: it is held so nothing can write, rename, or delete it, and then moved, by that same hold and with all its data, into the backup's files folder, so an interruption leaves it either where it was or in the backup. One whose backup folder is on another drive is left alone, and so is one with any named data stream (the download marker included). Restore moves the saved shortcut back the same way: one rename by its own handle, with all its data and at any size, into its old place (its folders made again if they went away), never over anything already there. It is then no longer in the backup; running the restore again finds it already back.

`--format json` prints one JSON document: `complete`, `findings`, `warnings`, and `notes` for a scan; for `repair --yes`, `complete`, `backup`, `removed`, `already_gone`, `left_alone` (asked for but not done: refused, not backed up, changed meanwhile, or left for a normal window), `per_user_left`, `report_only`, `needs_admin`, `errors`, `warnings`, and `notes`. Scan exit codes: 0 when a complete scan found nothing, 2 when there are findings, 3 when the scan could not read everything (or was stopped) and found nothing, so it cannot be called clean, and 1 on an error. Repair exit codes: 0 when everything asked for was done, 3 when the scan was incomplete or something asked for was left undone, and 1 on errors.

Run as administrator, `repair` leaves entries in your own part of the registry (HKCU, HKEY_USERS, and HKCR) for a normal window, leaves alone any machine-wide key that accounts other than SYSTEM, Administrators, TrustedInstaller, or Windows' service accounts can change, and says which. That includes keys whose default security lets Windows' TERMINAL SERVER USER group write (App Paths, Uninstall, and SharedDLLs among them), so most machine-wide entries are reported but not repaired; does not read your ignore list, and `--backup-dir` is refused unless it is the protected store.

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
line, reads them with Hivemend's own parser (anything it does not
recognise refuses the whole file), and writes them in one registry
transaction through the same link-refusing layer repair uses: all of it,
or nothing. The Restore list's counts come from that same parser. A
normal window restores only the `HKEY_CURRENT_USER` part of a backup
and an administrator window only the machine-wide part, and only into
keys that standard accounts cannot change (for a key it creates, the
nearest existing key above); each says what it left for the other.

In a normal window the marker only guards against restoring the wrong
file by accident: anyone can write it. Backups made as administrator are
also signed: `<backup>.reg.sig` beside each one gains a line after every
save, holding the backup's length so far and an HMAC-SHA256 of exactly
those bytes, under a key in `%ProgramData%\HiveMend\backup.key` that
only SYSTEM and Administrators can read. Earlier lines are never
rewritten. Hivemend running as administrator restores a backup only from
the protected folder and only the longest part a line signs, so a file it
did not write, or one changed since, is refused, and a save cut off part
way costs only that last save. Administrator backups made by versions before this
had no signature and are refused too; open one in Registry Editor if
you trust it.

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
  leaves alone machine-wide keys that standard accounts can change,
  restores only the machine-wide part of a backup (and only a signed
  one), starts no uninstallers, changes no startup items for your
  account, removes no duplicates, leaves browser history and cookies
  alone, and reads neither the ignore list nor the cookies-to-keep list.
  It does not read or save your settings either: it starts from the
  built-in defaults (restore points on) and forgets changes when it
  closes.
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
  custom items). Preview counts what each holds (Cancel stops it, and
  a stopped preview does not count: Clean needs a finished one), tick
  what to clean, then Clean. Registry entries are saved to a `privacy-*.reg`
  backup first and can be undone on the Restore page; files are deleted
  for good. The browser categories only remove cookies, and only while
  the browser is closed (checked again just before each category runs
  and before each database): cookies are removed from inside the cookie
  database by SQLite, never by deleting the database, because a database
  and its journal cannot be deleted together all or nothing. Browsing
  history, saved logins, form entries, addresses, cards, and bookmarks
  are not touched. A Temp file listed for being older
  than two days is opened so that nothing else can write to it and its
  age is read again: one written to since, or held open by another
  program, is left alone. One folder walk looks through at most 100,000
  folders (and a bounded amount of path text), goes at most 64 folders
  deep, looks at no more than 1,000 browser profiles, and removes at most
  100,000 files, and says when any of these left something out or the
  rest for another clean. Cancel stops a clean part way through a
  category, too. Custom
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
  counted twice. Cancel works even inside one huge folder, and a walk
  stops at a million folders (or 256 MB of folder names) and says its
  totals are partial. It only
  reads; Open in Explorer is the only action.
- Duplicates finds identical files of 1 MB or more in a fixed drive or
  your user folder, matching by content (size, then a hash of the first
  64 KB, then of the whole file), never by name. The Windows, Program
  Files, and ProgramData folders are left out; links, junctions, and
  cloud-only files are never followed or read, and a hard link is not
  counted as a copy. Tick Extra Copies ticks all but the first copy of
  each set. One copy of every set is always kept and held open so it
  cannot change, move, or go away meanwhile. Each file to remove is held
  open from its checks until it is moved, so nothing can write, rename,
  or delete it: its real location must be outside the protected folders
  (a SUBST drive or junction cannot hide it), it must have no extra data
  streams besides the download marker, and its bytes, read through both
  held files, must still match the kept copy. Hivemend then moves that
  same open file into your Recycle Bin folder on its drive itself, with
  the record Explorer uses to list it and put it back, so the file that
  goes is exactly the one compared. A drive without a Recycle Bin is
  refused: nothing is ever deleted for good. A search keeps at most a
  million candidate files (or 256 MB of their paths) and says when it
  compared only part of the drive. Removing is only done without administrator rights.
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
on the Privacy page opens it in Notepad. Cleaning a browser's cookies
edits its cookie database (for Chrome and Edge, `Network\Cookies`), only
while the browser is closed: with an empty list every cookie is removed,
with sites listed every other one. The database and each of its
SQLite side files must be a plain file with one name at its own path,
and Hivemend holds each of them (making the journal or log SQLite will
write, if it is missing) so none can be moved or replaced. SQLite then
opens files only through a layer that checks, through SQLite's own
handle, that each is the exact file Hivemend verified, and refuses
anything else or any attempt to delete one; the journal is emptied
rather than deleted, and every side file must be empty afterwards.
SQLite takes the database alone for the whole edit, so no other program
can read or write it meanwhile. A copy is taken in memory under that lock, every other cookie
is removed in one transaction (with SQLite's secure delete, so removed
values are overwritten), and the database is checked. If anything
fails after the edit, the copy is put back through the same locked
connection; only if that fails is it saved beside the database, written
through the handle that created the new file, and Hivemend says where (it then leaves that database alone until the copy
is gone). No other copy of the cookies is ever written to disk. A window
running as administrator leaves browser cookies alone.

Custom privacy items live in `%LOCALAPPDATA%\HiveMend\privacy-custom.ini`, one
per line (`#` starts a comment). Only Temp folders, browser profiles,
and your own history keys are allowed; anything else is refused with a
reason shown on the Custom row. Hivemend running as administrator leaves
the custom list out and starts with no privacy category ticked, without
even checking whether those files exist, because programs running
without administrator rights can edit them; clean custom items from a
window started normally.

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
