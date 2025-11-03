from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from .adapter import BaseAdapter, Detection


class GhidraAdapter(BaseAdapter):
    """Adapter that reads Ghidra-exported function JSON from
    `artifacts/ghidra_exports/<sha>/<prog>_functions.json` and yields detections
    for likely crypto-related functions (by name heuristics).

    This adapter is inexpensive and works offline against the exported JSON.
    """

    def __init__(
        self, exports_root: str | None = None, patterns: Iterable[str] | None = None
    ):
        self.exports_root = (
            Path(exports_root) if exports_root else Path("artifacts/ghidra_exports")
        )
        # default patterns match common crypto function names
        patt = (
            list(patterns)
            if patterns
            else [
                r"sha\d*",
                r"md5",
                r"aes",
                r"keccak",
                r"encrypt",
                r"decrypt",
                r"hmac",
                r"ecdsa",
                r"rsa",
            ]
        )
        self.regex = re.compile(r"(" + r"|".join(patt) + r")", re.IGNORECASE)

    def scan_files(self, files: Iterable[str]):
        # files are canonical preproc input paths; map to sha and look for exports
        for p in files:
            try:
                sp = Path(p)
                parts = sp.parts
                # find 'preproc' in path and next segment is sha
                if "preproc" in parts:
                    idx = parts.index("preproc")
                    sha = parts[idx + 1] if idx + 1 < len(parts) else None
                else:
                    sha = None
                if not sha:
                    continue
                export_dir = self.exports_root / sha
                if not export_dir.exists():
                    continue
                # look for any *_functions.json files
                for f in export_dir.glob("*_functions.json"):
                    try:
                        obj = json.loads(f.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    funcs = obj.get("functions") or []
                    for fn in funcs:
                        name = (fn.get("name") or "").strip()
                        if not name:
                            continue
                        if self.regex.search(name):
                            try:
                                rel = str(f.relative_to(Path.cwd()))
                            except Exception:
                                rel = str(f)
                            yield Detection(
                                path=str(sp),
                                offset=None,
                                rule="ghidra_fn_name",
                                details={
                                    "function": name,
                                    "entry": fn.get("entry"),
                                    "signature": fn.get("signature"),
                                    "export_file": rel,
                                },
                                engine="ghidra",
                            )
            except Exception:
                continue
