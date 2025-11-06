"""Ghidra headless adapter (PR1->PR2).

This module locates `analyzeHeadless`, composes conservative commands, and
provides a safe `ensure_ghidra_export` flow that is unit-testable. Heavy
integration runs are opt-in; unit tests should monkeypatch `run_headless_export`
to simulate an export being produced.
"""
from typing import Optional, List, Tuple, Dict
import os
import shutil
import subprocess
import json
from datetime import datetime, timezone


DEFAULT_TIMEOUT = 600


def find_analyze_headless(options: Dict = None) -> Optional[str]:
    """Locate analyzeHeadless executable.

    Search order:
      1) options.get('ghidra_install_dir') -> check known locations
      2) environment variable GHIDRA_INSTALL_DIR
      3) PATH via shutil.which

    Returns absolute path to executable or None if not found.
    """
    opts = options or {}
    candidates = []

    install = opts.get("ghidra_install_dir") or os.environ.get("GHIDRA_INSTALL_DIR")
    if install:
        candidates.append(os.path.join(install, "support", "analyzeHeadless"))
        candidates.append(os.path.join(install, "analyzeHeadless"))

    exe_names = ["analyzeHeadless"]
    if os.name == "nt":
        exe_names.extend(["analyzeHeadless.exe", "analyzeHeadless.bat"])

    for base in candidates:
        for name in exe_names:
            p = base if os.path.isabs(base) and base.endswith(name) else os.path.join(base, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return os.path.abspath(p)

    which = shutil.which("analyzeHeadless")
    if which:
        return os.path.abspath(which)

    return None


def build_headless_cmd(analyze_path: str, project_dir: str, script_path: str, input_path: str, out_dir: str, extra_args: Dict = None) -> List[str]:
    """Compose a conservative analyzeHeadless command.

    The exact command varies by Ghidra version. Keep this simple and testable.
    """
    args = [analyze_path]
    # project_dir is used as the headless project location (we reuse out_dir)
    args.extend([project_dir, "-import", input_path])
    if script_path:
        args.extend(["-postScript", os.path.basename(script_path), "-scriptPath", os.path.dirname(script_path)])
    if extra_args:
        for k, v in (extra_args.items() if isinstance(extra_args, dict) else []):
            args.append(str(k))
            if v is not None:
                args.append(str(v))
    return args


def run_headless_export(cmd: List[str], timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, str, str]:
    """Run the headless command and return (exitcode, stdout, stderr).

    Unit tests should patch this function to avoid invoking a real Ghidra.
    """
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)
        stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired as ex:
        raise TimeoutError(str(ex))


def _write_ghidra_meta(out_dir: str, ghidra_path: Optional[str]):
    try:
        meta = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ghidra_path": ghidra_path,
        }
        with open(os.path.join(out_dir, ".ghidra_export_meta.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
    except Exception:
        # best-effort only
        pass


def ensure_ghidra_export(input_path: str, out_dir: str, file_hash: str, options: Dict = None) -> Optional[str]:
    """Ensure a Ghidra export exists for the given file_hash under out_dir.

    Behavior:
      - If <out_dir>/<file_hash>-functions.json exists and not forced, return it.
      - If analyzeHeadless is not found, return None.
      - Otherwise build command, run headless, write logs/meta, and return path if produced.

    Unit tests should monkeypatch `run_headless_export` (and optionally
    `find_analyze_headless`) to simulate successful exports without Ghidra.
    """
    opts = options or {}
    os.makedirs(out_dir, exist_ok=True)
    export_path = os.path.join(out_dir, f"{file_hash}-functions.json")

    # If an export already exists and force is not requested, return it.
    if os.path.isfile(export_path) and not opts.get("force"):
        return export_path

    analyze = find_analyze_headless(opts)
    if not analyze:
        # Ghidra not available in environment; nothing to do
        return None

    # If caller did not provide a script, write the bundled exporter to out_dir
    script_path = opts.get("script_path") or ""
    if not script_path:
        try:
            # import the bundled exporter string and write it to disk
            from .ghidra_exporter import EXPORTER_SCRIPT
            bundled_path = os.path.join(out_dir, "ghidra_exporter.py")
            with open(bundled_path, "w", encoding="utf-8") as fh:
                fh.write(EXPORTER_SCRIPT)
            script_path = bundled_path
        except Exception:
            # if writing fails, fall back to empty and rely on provided script_path
            script_path = ""
    cmd = build_headless_cmd(analyze, out_dir, script_path, input_path, out_dir, extra_args=opts.get("extra_args"))
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))

    try:
        code, out, err = run_headless_export(cmd, timeout=timeout)
    except TimeoutError:
        # timeout
        try:
            with open(os.path.join(out_dir, "ghidra-export.log"), "w", encoding="utf-8") as fh:
                fh.write("TIMEOUT")
        except Exception:
            pass
        return None

    # Persist logs for troubleshooting (best-effort)
    try:
        with open(os.path.join(out_dir, "ghidra-export.log"), "w", encoding="utf-8") as fh:
            fh.write("STDOUT:\n")
            fh.write(out or "")
            fh.write("\nSTDERR:\n")
            fh.write(err or "")
    except Exception:
        pass

    # If run succeeded, write a tiny meta file and return export path if present
    if code == 0:
        _write_ghidra_meta(out_dir, analyze)
        if os.path.isfile(export_path):
            return export_path
    return None


def read_ghidra_functions(export_path: str) -> List[dict]:
    """Read the JSON functions export and return a list of normalized dicts.

    If file is missing or malformed, returns an empty list.
    """
    if not export_path or not os.path.isfile(export_path):
        return []
    try:
        with open(export_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        out = []
        for f in data:
            out.append({
                "name": f.get("name"),
                "address": f.get("address"),
                "size": f.get("size"),
                "prototype": f.get("prototype"),
                "disasm": f.get("disasm"),
            })
        return out
    except Exception:
        return []
