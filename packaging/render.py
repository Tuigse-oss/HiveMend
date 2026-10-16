#!/usr/bin/env python3
"""Render the Scoop, winget, and Chocolatey manifests for one release.

    python3 packaging/render.py 0.1.0 SHA256SUMS.txt out/

reads the release's SHA256SUMS.txt and writes:

    out/scoop/hivemend.json
    out/winget/TUIGSE.Hivemend*.yaml
    out/chocolatey/  (ready for `choco pack`)

The templates sit next to this script; {{VERSION}}, {{ZIP_URL}},
{{ZIP_SHA256}}, {{SETUP_URL}}, and {{SETUP_SHA256}} are filled in.
"""

import shutil
import sys
from pathlib import Path

REPO = "https://github.com/Tuigse-oss/HiveMend"
HERE = Path(__file__).resolve().parent


def main() -> None:
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    version, sums_path, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    tag = f"v{version}"
    zip_name = f"Hivemend-{tag}-x86_64-windows.zip"
    setup_name = f"Hivemend-{tag}-x86_64-setup.exe"

    sums = {}
    for line in sums_path.read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        sums[name.lstrip("*")] = digest.lower()
    for name in (zip_name, setup_name):
        if name not in sums:
            sys.exit(f"{sums_path} has no checksum for {name}")

    values = {
        "{{VERSION}}": version,
        "{{ZIP_URL}}": f"{REPO}/releases/download/{tag}/{zip_name}",
        "{{ZIP_SHA256}}": sums[zip_name],
        "{{SETUP_URL}}": f"{REPO}/releases/download/{tag}/{setup_name}",
        "{{SETUP_SHA256}}": sums[setup_name],
    }

    for channel in ("scoop", "winget", "chocolatey"):
        dest = out / channel
        if dest.exists():
            shutil.rmtree(dest)
        for src in (HERE / channel).rglob("*"):
            if src.is_dir():
                continue
            target = dest / src.relative_to(HERE / channel)
            target.parent.mkdir(parents=True, exist_ok=True)
            text = src.read_text()
            for key, value in values.items():
                text = text.replace(key, value)
            if "{{" in text:
                sys.exit(f"{src} has a placeholder this script does not fill")
            target.write_text(text)
            print(target)


if __name__ == "__main__":
    main()
