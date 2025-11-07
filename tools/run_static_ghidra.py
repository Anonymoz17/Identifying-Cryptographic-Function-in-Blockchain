"""Helper script to run static detection with optional Ghidra headless export.

Usage: invoke with Python from repository root. It reads these environment
variables to control behavior:

- GHIDRA_INSTALL_DIR: path to Ghidra install containing support/analyzeHeadless
- GHIDRA_SAMPLE_BIN: path to the input binary to analyze (preproc style input)
- GHIDRA_FORCE: if set to '1' will force regeneration of Ghidra export
- GHIDRA_TIMEOUT: optional headless run timeout in seconds

This script is a lightweight convenience for local developers to exercise the
end-to-end flow. It does not replace the production orchestration but is
useful for debugging and reproducing integration test runs.
"""
import os
import sys
import json
from pathlib import Path

# Make repo importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from auditor.detectors.static_detection.runner import StaticRunner
from auditor.detectors.static_detection.context import RunContext


def main():
    gh_install = os.environ.get("GHIDRA_INSTALL_DIR")
    sample_bin = os.environ.get("GHIDRA_SAMPLE_BIN")
    if not sample_bin:
        print("Set GHIDRA_SAMPLE_BIN to a preproc-style input.bin path (or full binary path)")
        return 2

    # Build a minimal preproc-like folder under tmp for this run
    # If the provided sample_bin already looks like a preproc/input.bin path, reuse
    sample_path = Path(sample_bin)
    if not sample_path.exists():
        print(f"Sample binary not found: {sample_bin}")
        return 2

    # For convenience, create an ephemeral preproc folder expected by runner
    tmp_preproc = Path("tmp_run_preproc").resolve()
    tmp_preproc.mkdir(exist_ok=True)
    input_dest = tmp_preproc / "input.bin"
    # Copy sample into tmp preproc path if not already the same
    if sample_path.resolve() != input_dest.resolve():
        try:
            import shutil
            shutil.copy2(str(sample_path), str(input_dest))
        except Exception as e:
            print("Failed to copy sample to tmp preproc:", e)
            return 2

    # write a minimal metadata.json only if one doesn't already exist
    meta_path = tmp_preproc / "metadata.json"
    if not meta_path.exists():
        metadata = {"schema_version": "1.0", "file_hash": ""}
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh)

    # Build RunContext
    ctx = RunContext(
        file_hash="",
        preproc_dir=str(tmp_preproc),
        analysis_base=str(Path(".").resolve()),
        profile="quick",
        force=False,
        ghidra_options={
            "install_dir": gh_install,
            "timeout": int(os.environ.get("GHIDRA_TIMEOUT", "600")),
            "force": os.environ.get("GHIDRA_FORCE") == "1",
        },
    )

    runner = StaticRunner()
    res = runner.run(ctx)
    print("Run summary:")
    print(json.dumps(res.summary or {}, indent=2))
    print("hints:", res.hints_path)
    print("static_results:", res.static_results_path)
    if res.errors:
        print("errors:", res.errors)
    return 0


if __name__ == "__main__":
    sys.exit(main())
