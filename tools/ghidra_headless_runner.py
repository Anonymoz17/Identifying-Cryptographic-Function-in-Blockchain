"""Simple wrapper to run Ghidra's analyzeHeadless on prepared inputs.

This script expects `artifacts/ghidra_inputs/<id>/` directories prepared by preproc
and will write JSON exports to `artifacts/ghidra_exports/<id>.json`.

This is a minimal runner; adapt paths and script names for your environment.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ghidra", help="path to ghidra analyzeHeadless", required=True)
    p.add_argument("--workspace", help="case/workdir", required=True)
    p.add_argument(
        "--script", help="analysis script to run inside ghidra", required=True
    )
    args = p.parse_args()

    wd = Path(args.workspace)
    inputs = wd / "artifacts" / "ghidra_inputs"
    exports = wd / "artifacts" / "ghidra_exports"
    exports.mkdir(parents=True, exist_ok=True)

    # iterate input directories
    for d in inputs.iterdir():
        if not d.is_dir():
            continue
        out_json = exports / f"{d.name}.json"
        # Example analyzeHeadless invocation; adjust project name and script args as needed
        cmd = [
            args.ghidra,
            str(d),
            "-import",
            str(d / "input.bin"),
            "-postScript",
            args.script,
            str(d),
        ]
        try:
            subprocess.check_call(cmd)
        except Exception:
            # best-effort: write an empty placeholder so adapter can proceed
            out_json.write_text(json.dumps({"error": "ghidra_failed"}))


if __name__ == "__main__":
    raise SystemExit(main())
