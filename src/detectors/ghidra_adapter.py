from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .adapter import BaseAdapter, Detection


class GhidraExportAdapter(BaseAdapter):
    """Reads JSON files under `artifacts/ghidra_exports/<id>.json` produced by
    the headless Ghidra job and yields Detection objects.
    """

    def __init__(self):
        pass

    def scan_files(self, files: Iterable[str]):
        files_list = list(files)
        for f in files_list:
            p = Path(f)
            if "preproc" in p.parts:
                try:
                    sha = p.parts[p.parts.index("preproc") + 1]
                    export_path = (
                        p.parents[2] / "artifacts" / "ghidra_exports" / f"{sha}.json"
                    )
                except Exception:
                    export_path = None
            else:
                export_path = None

            if export_path and export_path.exists():
                try:
                    js = json.loads(export_path.read_text(encoding="utf-8"))
                except Exception:
                    js = None
                if js and isinstance(js, dict):
                    # exports are expected to include a 'functions' array with summaries
                    for fn in js.get("functions", []):
                        details = {"summary": fn}
                        yield Detection(
                            path=str(f),
                            offset=fn.get("address"),
                            rule=fn.get("match_id", "ghidra_func"),
                            details=details,
                            engine="ghidra",
                        )
