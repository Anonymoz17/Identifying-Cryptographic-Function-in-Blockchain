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
import sys
from . import config as _config


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


def resolve_ghidra(options: Dict = None) -> Optional[str]:
    """Resolve an analyzeHeadless executable path using precedence:
    1) options.get('install_dir')
    2) persisted config value
    3) GHIDRA_INSTALL_DIR env var
    4) PATH (shutil.which)

    Returns absolute path to analyzeHeadless or None.
    """
    opts = options or {}
    # 1) explicit install_dir in options (higher precedence)
    install_dir = opts.get("install_dir") or opts.get("ghidra_install_dir")
    if install_dir:
        p = os.path.join(install_dir, "support", "analyzeHeadless")
        if os.name == "nt":
            # allow analyzeHeadless.exe or bat
            for name in ("analyzeHeadless.exe", "analyzeHeadless.bat", "analyzeHeadless"):
                cand = os.path.join(install_dir, "support", name)
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return os.path.abspath(cand)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return os.path.abspath(p)

    # 2) persisted config
    try:
        persisted = _config.get_ghidra_install_dir()
        if persisted:
            for name in ("analyzeHeadless", "analyzeHeadless.exe", "analyzeHeadless.bat"):
                cand = os.path.join(persisted, "support", name)
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return os.path.abspath(cand)
    except Exception:
        pass

    # 3) environment
    env_install = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_install:
        for name in ("analyzeHeadless", "analyzeHeadless.exe", "analyzeHeadless.bat"):
            cand = os.path.join(env_install, "support", name)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return os.path.abspath(cand)

    # 4) PATH lookup
    which = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat") or shutil.which("analyzeHeadless.exe")
    if which:
        return os.path.abspath(which)

    return None


def verify_ghidra(analyze_path: str, timeout: int = 5) -> Optional[str]:
    """Run a short verification against analyzeHeadless to obtain a version
    or confirm executable works. Returns a short string describing the
    binary on success, or None on failure.
    """
    if not analyze_path or not os.path.isfile(analyze_path):
        return None
    try:
        # try `-version` first; fallback to `-help` if -version not supported
        for flag in ("-version", "-help"):
            try:
                proc = subprocess.run([analyze_path, flag], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)
                out = (proc.stdout or b"").decode("utf-8", errors="replace")
                if out:
                    first = out.splitlines()[0] if out.splitlines() else out
                    return str(first).strip()
            except subprocess.TimeoutExpired:
                return None
    except Exception:
        return None
    return None


def build_headless_cmd(analyze_path: str, project_dir: str, script_path: str, input_path: str, out_dir: str, export_path: Optional[str] = None, extra_args: Dict = None) -> List[str]:
    """Compose a conservative analyzeHeadless command.

    We construct a minimal, widely compatible invocation. The exporter script
    will be invoked via `-postScript <script>` and the exporter output path
    is passed as the script's final argument.
    """
    args = [analyze_path]
    # project_dir is used as the headless project location (we reuse out_dir)
    args.append(os.path.abspath(project_dir))
    # import the input file
    args.extend(["-import", os.path.abspath(input_path)])

    # supply the script via -scriptPath / -postScript when provided
    if script_path:
        script_dir = os.path.dirname(os.path.abspath(script_path)) or "."
        script_name = os.path.basename(script_path)
        args.extend(["-scriptPath", script_dir, "-postScript", script_name])
        # pass the exporter target path as the script argument
        if export_path:
            args.append(os.path.abspath(export_path))

    # Allow callers to pass extra key/value style args (best-effort)
    if extra_args and isinstance(extra_args, dict):
        for k, v in extra_args.items():
            # include bare flags (value None) or key+value pairs
            args.append(str(k))
            if v is not None:
                args.append(str(v))

    # Some headless runs benefit from -overwrite to avoid project conflicts
    args.append("-overwrite")
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
    # compute expected export path (file_hash-functions.json)
    export_path = os.path.join(out_dir, f"{file_hash}-functions.json")
    cmd = build_headless_cmd(analyze, out_dir, script_path, input_path, out_dir, export_path=export_path, extra_args=opts.get("extra_args"))
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
                "parameters": f.get("parameters"),
                "calling_convention": f.get("calling_convention"),
                "disasm": f.get("disasm"),
                "function_hash": f.get("function_hash"),
            })
        return out
    except Exception:
        return []
