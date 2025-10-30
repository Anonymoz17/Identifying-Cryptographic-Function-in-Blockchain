"""Helper to download and extract Ghidra for local development.

This script downloads a Ghidra release zip from the official GitHub releases
and extracts it under `tools/ghidra/`. It does not modify your PATH or
environment variables; after running you should set `GHIDRA_INSTALL_DIR`
or add the `support` directory to your PATH.

Usage (PowerShell example):
  python tools/install_ghidra.py --version 10.1.5 --dest tools/ghidra

Notes:
 - The script performs a best-effort download. If your environment blocks
   outbound HTTP, download the Ghidra release manually from
   https://github.com/NationalSecurityAgency/ghidra/releases and extract it
   under the same destination.
 - Running this script requires Python with urllib and zipfile (stdlib).
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.request import urlopen


def download_and_extract(url: str, dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    print(f"Downloading Ghidra from {url} ...")
    with urlopen(url) as resp:
        if resp.status != 200:
            raise SystemExit(f"Download failed: HTTP {resp.status}")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            shutil.copyfileobj(resp, tmp)
            tmp_path = Path(tmp.name)
    print("Extracting...")
    with zipfile.ZipFile(tmp_path, "r") as z:
        z.extractall(dest)
    tmp_path.unlink()
    print(f"Extracted to {dest}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--version", default="10.1.5", help="Ghidra version (major.minor.patch)"
    )
    ap.add_argument("--dest", default="tools/ghidra", help="Destination directory")
    ap.add_argument(
        "--platform", choices=["linux", "macos", "windows"], help="Platform override"
    )
    ns = ap.parse_args()

    version = ns.version
    dest = Path(ns.dest)
    platform = ns.platform

    # Determine platform string used by Ghidra release assets
    if not platform:
        if sys.platform.startswith("win"):
            platform = "windows"
        elif sys.platform.startswith("darwin"):
            platform = "macos"
        else:
            platform = "linux"

    # construct asset filename pattern used by Ghidra releases
    # e.g. ghidra_10.1.5_PUBLIC_20230101_windows.zip (date varies per release)
    # We attempt the common public download URL without the date component by
    # falling back to the GitHub releases index would be more robust but
    # requires parsing the HTML/API. For convenience, we try a few known
    # patterns, and if they fail we instruct the user to download manually.
    base = "https://github.com/NationalSecurityAgency/ghidra/releases/download"

    candidates = [
        f"{base}/Ghidra_{version}/ghidra_{version}_PUBLIC_{platform}.zip",
        f"{base}/Ghidra_{version}/ghidra_{version}_PUBLIC.zip",
    ]

    for url in candidates:
        try:
            download_and_extract(url, dest)
            print("Ghidra installed to", dest)
            print(
                "Please set GHIDRA_INSTALL_DIR to the extracted folder or add its 'support' directory to PATH."
            )
            return
        except Exception as e:
            print("Attempt failed:", e)

    print(
        "Failed to download Ghidra automatically. Please download the appropriate release from:"
    )
    print("https://github.com/NationalSecurityAgency/ghidra/releases")
    print(f"Then extract it under {dest} and set GHIDRA_INSTALL_DIR accordingly.")


if __name__ == "__main__":
    main()
