"""Launch the GUI and open the Results page for a case workspace.

Usage:
  python tools/open_results.py --case PATH [--run]

If --case is omitted the script will prompt you to choose a directory.
If --run is passed (or the user confirms) the script will run the detectors
CLI (`tools/run_detectors.py`) to produce NDJSON output and then generate the
summary JSON before launching the GUI showing the Results page.

This helper sets PYTHONPATH to the repository root when invoking detector
subprocesses so the `src` package is importable.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tkinter as tk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
from pathlib import Path
from typing import List


def choose_case_via_dialog() -> Path | None:
    root = tk.Tk()
    root.withdraw()
    d = fd.askdirectory(title="Select case/workspace directory")
    try:
        root.destroy()
    except Exception:
        pass
    if not d:
        return None
    return Path(d)


def run_detectors_cli(manifest: Path, out_ndjson: Path) -> None:
    env = os.environ.copy()
    # ensure repo root is importable as 'src'
    env["PYTHONPATH"] = env.get("PYTHONPATH", "")
    if env["PYTHONPATH"]:
        env["PYTHONPATH"] = "." + os.pathsep + env["PYTHONPATH"]
    else:
        env["PYTHONPATH"] = "."

    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parents[1] / "run_detectors.py"),
        str(manifest),
        str(out_ndjson),
    ]
    print("Running detectors CLI:", " ".join(cmd))
    subprocess.check_call(cmd, env=env)


def generate_summary_from_ndjson(ndjson_path: Path, out_dir: Path) -> None:
    # import lazily so this script still works even if optional deps are missing
    from src.detectors.adapter import Detection
    from src.detectors.runner import generate_summary

    dets = []
    txt = ndjson_path.read_text(encoding="utf-8")
    for line in txt.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        dets.append(
            Detection(
                path=obj.get("path"),
                offset=obj.get("offset"),
                rule=obj.get("rule"),
                details=obj.get("details") or {},
                engine=obj.get("engine"),
            )
        )

    generate_summary(dets, out_dir, out_dir.parent, adapters=[])


def launch_gui_and_open_results(case_dir: Path) -> None:
    # Lazy import of GUI app to avoid pulling GUI deps for CLI-only usage
    from src.app import App

    app = App()
    # set the current scan meta so the Results page knows where to look
    app.current_scan_meta = {"workdir": str(case_dir), "case_id": case_dir.name}
    try:
        app.switch_page("results")
    except Exception:
        pass
    app.mainloop()


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", help="Path to case workspace (folder)")
    ap.add_argument(
        "--run", action="store_true", help="Run detectors before opening results"
    )
    ns = ap.parse_args(argv)

    case_dir = Path(ns.case) if ns.case else None
    if case_dir and not case_dir.exists():
        print("Case directory not found:", case_dir)
        return 2

    if not case_dir:
        case_dir = choose_case_via_dialog()
        if not case_dir:
            print("No case selected; exiting")
            return 1

    out_dir = case_dir / "detector_output"
    out_dir.mkdir(parents=True, exist_ok=True)
    ndjson_path = out_dir / "detector_results.ndjson"
    summary_path = out_dir / "detector_results.summary.json"
    manifest = case_dir / "inputs.manifest.ndjson"

    need_run = ns.run
    if not need_run and not summary_path.exists():
        # ask the user whether to run detectors
        root = tk.Tk()
        root.withdraw()
        answer = mb.askyesno(
            "Run detectors?", "No summary found for this case. Run detectors now?"
        )
        try:
            root.destroy()
        except Exception:
            pass
        need_run = bool(answer)

    if need_run:
        if not manifest.exists():
            print("Manifest file not found at", manifest)
            return 3
        try:
            run_detectors_cli(manifest, ndjson_path)
        except subprocess.CalledProcessError as e:
            print("Detectors CLI failed:", e)
            return 4
        # generate summary from ndjson
        try:
            generate_summary_from_ndjson(ndjson_path, out_dir)
        except Exception as e:
            print("Failed to generate summary:", e)

    # Launch GUI and open Results page
    try:
        launch_gui_and_open_results(case_dir)
    except Exception as e:
        print("Failed to launch GUI:", e)
        return 5

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
