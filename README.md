# Registry Master

Registry Master scans a Windows 10 or 11 registry for stale entries and can remove them after writing a backup. It covers twelve scanner jobs:

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
| PS | Broken shortcuts in the Start Menu and on the Desktop, and temp files older than an hour |
| CC | COM controls, type libraries, default icons, shell hooks, preview handlers, autoplay handlers, codecs, context menus, and legacy browser extensions whose file is gone |
| DEEP | Optional wider pass over path-shaped values |

The built-in paths cover the Windows 10 and 11 layout, including per-user uninstall keys and the 32-bit `WOW6432Node` view. There is no self-updater and no license client. Deep scan stays off unless you pass `--include-deep` or `--only DEEP`.

Shell folders, `UserChoice` file associations, Winlogon, services, files inside the Windows directory, and built-in protocols such as `http` and `ms-settings` are not deleted.

## Build

Rust 1.99.0 is pinned in `rust-toolchain.toml`.

```bash
cargo test
cargo build --release --target x86_64-pc-windows-msvc
```

The MSVC target needs the Microsoft linker, so the release build is meant to run on Windows. From this tree, `cargo test` checks the engine with an in-memory hive.

## Use

```bash
registry-master scanners
registry-master scan
registry-master scan --only SL,SUP,ARP
registry-master repair --backup-dir C:\RegistryMaster\backups
registry-master repair --backup-dir C:\RegistryMaster\backups --yes
```

`scan` never writes. `repair` without `--yes` prints the plan. With `--yes` it writes a UTF-16 `.reg` backup first, then deletes only the entries that backup describes.

If you still have an extracted legacy cleaner `app` folder, its original rules and ignore lists can be merged in:

```bash
registry-master scan --data "C:\Path\To\Extracted\app"
```

That reads `Data/rmscan.xml`, `Data/keys.dat`, `Data/values.dat`, and `Data/map.dat` when they are present. Those files are not part of this repository.

`registry-master demo` runs the sample hive on any operating system.

## Window

Double-clicking the exe opens the window: Status, Start Scan, Restore,
Settings, Monitor, Tools, and About.

- Status shows Scan Your Registry, Optimize Your System (a quick
  startup, uninstall, shared-DLL, and COM pass), and Monitor Your System
  cards, plus the last scan result and a statistics reset link.
- Monitor shows live memory, system-drive, and uptime readings with
  usage bars, plus the Registry Master health summary. It only reads.
- Tools opens screens that ship with Windows (Device Manager, Services,
  System Restore, Windows Update, and the rest). Registry Master only
  launches them.
- The header Help link opens About, which explains the safety rules.

Card and tile icons load from `C:\registrymasterimages` when that folder
exists, next to a copy of the exe otherwise. The artwork is not part of
this repository.
