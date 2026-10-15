#!/usr/bin/env python3
"""Write THIRD-PARTY-NOTICES.txt: the license and copyright notices of the
crates linked into Hivemend.exe and of the Rust standard library.

Run from the repository root after changing Cargo.lock:

    python3 scripts/third-party-notices.py

Reads Cargo.lock, the crate sources in Cargo's registry (fetched with
`cargo fetch`), and the toolchain's documentation (`rustc --print sysroot`).
The test `the_notices_cover_every_linked_crate` fails until it is rerun.
"""
import html
import os
import re
import subprocess
import sys
from pathlib import Path

# Crates that only run while building (code generators, build scripts),
# so none of their code is in the program.
BUILD_ONLY = {
    "cc", "clap_derive", "find-msvc-tools", "heck", "hive-mend", "pkg-config",
    "proc-macro2", "quote", "shlex", "syn", "unicode-ident", "vcpkg",
}


def locked_packages():
    text = Path("Cargo.lock").read_text()
    return re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', text)


def crate_dir(name, version):
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for index in sorted((home / "registry" / "src").glob("*")):
        path = index / f"{name}-{version}"
        if path.is_dir():
            return path
    sys.exit(f"{name} {version} is not in Cargo's registry; run `cargo fetch` first")


def mit_text(path):
    files = {f.name.lower(): f for f in path.iterdir() if f.is_file()}
    for want in ("license-mit", "license-mit.md", "license"):
        if want in files:
            return files[want].read_text(errors="replace").strip()
    sys.exit(f"no MIT license text in {path}")


def license_of(path):
    match = re.search(r'^license\s*=\s*"([^"]+)"', (path / "Cargo.toml").read_text(), re.M)
    return match.group(1) if match else "unknown"


def main():
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    docs = sysroot / "share" / "doc" / "rust"
    out = [
        "Third-party notices for Hivemend",
        "",
        "Hivemend includes the open-source software below. Each is used under the",
        "MIT license (several offer MIT or Apache-2.0; MIT is chosen), and its",
        "copyright and license notice is reproduced here as that license requires.",
        "SQLite, bundled through libsqlite3-sys, is in the public domain.",
        "",
    ]
    for name, version in sorted(locked_packages(), key=lambda p: p[0]):
        if name in BUILD_ONLY:
            continue
        path = crate_dir(name, version)
        lic = license_of(path)
        if "MIT" not in lic:
            sys.exit(f"{name} {version} is not available under MIT ({lic}); review it by hand")
        out += ["=" * 76, f"{name} {version} (license: {lic}; used under MIT)", "=" * 76, "",
                mit_text(path), ""]
    copyright = (docs / "COPYRIGHT-library.html").read_text()
    copyright = html.unescape(re.sub(r"<[^>]+>", "", copyright))
    copyright = "\n".join(line.rstrip() for line in copyright.splitlines() if line.strip())
    out += ["=" * 76, "The Rust Standard Library", "=" * 76, "", copyright, ""]
    for license_file in ("MIT.txt", "Unicode-3.0.txt"):
        out += ["-" * 76, license_file, "-" * 76, "",
                (docs / "licenses" / license_file).read_text().strip(), ""]
    Path("THIRD-PARTY-NOTICES.txt").write_text("\n".join(out) + "\n")
    print("wrote THIRD-PARTY-NOTICES.txt")


if __name__ == "__main__":
    main()
