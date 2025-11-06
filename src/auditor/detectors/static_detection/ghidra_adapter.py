"""Ghidra adapter (skeleton).

Real implementation should locate `analyzeHeadless`, run the headless
export script, and provide functions to read exports. These are heavy and
integration-only. The stubs below allow local unit tests to import the
module safely.
"""
from typing import Dict
import os


def ensure_ghidra_export(preproc_input: str, out_dir: str, file_hash: str, options: Dict = None) -> str:
    """Ensure a ghidra export exists in out_dir and return the export path.

    This is a no-op stub that creates the directory and returns a path where
    a real ghidra export would be written.
    """
    os.makedirs(out_dir, exist_ok=True)
    export_path = os.path.join(out_dir, f"{file_hash}-functions.json")
    # Do not write heavy exports in the stub.
    return export_path


def read_ghidra_functions(path: str) -> Dict:
    """Read a ghidra-export functions JSON and return a dict.

    Stub: return empty dict if file missing.
    """
    if not os.path.isfile(path):
        return {}
    import json
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
