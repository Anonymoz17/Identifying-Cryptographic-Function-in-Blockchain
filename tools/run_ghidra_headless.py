"""Wrapper to build and optionally run Ghidra analyzeHeadless commands for a case.

This script is a convenience helper. It does NOT bundle Ghidra. You must have
Ghidra installed and `analyzeHeadless` available (set GHIDRA_INSTALL_DIR or
put analyzeHeadless on PATH). The script iterates over `preproc/*/input.bin`
under a case workspace and emits commands that run `ExportFunctions.py` to
produce JSON function exports under `artifacts/ghidra_exports/<sha>/`.

Usage:
  python tools/run_ghidra_headless.py --case tools/case_demo/CASE-001 [--run]

If `--run` is not given the script prints commands for manual review.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


def find_analyze_headless():
    """Try to locate the analyzeHeadless executable.

    Strategy:
    - check PATH via shutil.which
    - check GHIDRA_INSTALL_DIR environment variable
    - probe a few common install prefixes on Windows/macOS/Linux
    """
    cmd = shutil.which("analyzeHeadless")
    if cmd:
        return cmd

    gh = os.environ.get("GHIDRA_INSTALL_DIR")
    if gh:
        cand = (
            Path(gh)
            / "support"
            / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        )
        if cand.exists():
            return str(cand)

    # common locations (best-effort)
    candidates = []
    if os.name == "nt":
        # Program Files or root ghidra directory patterns
        candidates += list(Path("C:/Program Files").glob("ghidra*"))
        candidates += list(Path("C:/").glob("ghidra*"))
        for base in candidates:
            cand = base / "support" / "analyzeHeadless.bat"
            if cand.exists():
                return str(cand)
    else:
        # Linux / macOS common locations
        candidates += list(Path("/opt").glob("ghidra*"))
        candidates += list(Path.home().glob("ghidra*"))
        for base in candidates:
            cand = base / "support" / "analyzeHeadless"
            if cand.exists():
                return str(cand)

    return None


def build_commands(case_dir: Path):
    cmds = []
    preproc_dir = case_dir / "preproc"
    for input_bin in preproc_dir.glob("*/input.bin"):
        sha = input_bin.parent.name
        out_dir = case_dir / "artifacts" / "ghidra_exports" / sha
        out_dir.mkdir(parents=True, exist_ok=True)
        # Build a project dir per-run under .ghidra_projects (safe workspace)
        proj_dir = case_dir / ".ghidra_projects" / sha
        proj_dir.mkdir(parents=True, exist_ok=True)
        # analyzeHeadless <projectDir> <file> -postScript ExportFunctions.py -scriptPath <scriptPath> <out_dir>
        script_path = str((Path(__file__).resolve().parent / "ghidra").resolve())
        cmd = [
            "analyzeHeadless",
            str(proj_dir),
            str(input_bin),
            "-postScript",
            "ExportFunctions.py",
            "-scriptPath",
            script_path,
            str(out_dir),
        ]
        cmds.append((cmd, input_bin, out_dir))
    return cmds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--run", action="store_true", help="Actually run the commands")
    ns = ap.parse_args()

    case_dir = Path(ns.case)
    if not case_dir.exists():
        raise SystemExit("case dir not found: %s" % case_dir)

    cmds = build_commands(case_dir)
    if not cmds:
        print("No preproc inputs found under", case_dir / "preproc")
        return

    analyze = find_analyze_headless()
    if not analyze:
        print(
            "analyzeHeadless not found. Set GHIDRA_INSTALL_DIR or add analyzeHeadless to PATH."
        )
        print("Commands to run (copy/paste into a shell once Ghidra is available):")
        for cmd, _inp, _out in cmds:
            print(" ".join(map(str, cmd)))
        return

    if not ns.run:
        print("analyzeHeadless found at:", analyze)
        print("Dry run. To execute, re-run with --run")
        for cmd, _inp, _out in cmds:
            print(" ".join(map(str, cmd)))
        return

    # actually run
    for cmd, inp, _out in cmds:
        cmd[0] = analyze
        print("Running:", " ".join(map(str, cmd)))
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            print("Failed for", inp, e)


if __name__ == "__main__":
    main()
