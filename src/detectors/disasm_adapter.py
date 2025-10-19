from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .adapter import BaseAdapter, BinaryRegexAdapter, Detection


class DisasmJsonAdapter(BaseAdapter):
    """Adapter that consumes `artifacts/disasm/<sha>.json` files and yields
    instruction-level detections. When no disasm JSON is present, it can fall
    back to a BinaryRegexAdapter if provided.
    """

    def __init__(self, fallback_rules: dict | None = None):
        self.fallback_rules = fallback_rules

    def _read_disasm_file(self, path: str):
        try:
            j = json.loads(Path(path).read_text(encoding="utf-8"))
            return j
        except Exception:
            return None

    def scan_files(self, files: Iterable[str]):
        files_list = list(files)
        for f in files_list:
            # expect path like preproc/<sha>/input.bin -> artifacts/disasm/<sha>.json
            p = Path(f)
            if "preproc" in p.parts:
                try:
                    sha = p.parts[p.parts.index("preproc") + 1]
                    dis_path = p.parents[2] / "artifacts" / "disasm" / f"{sha}.json"
                except Exception:
                    dis_path = None
            else:
                dis_path = None

            if dis_path and dis_path and dis_path.exists():
                js = self._read_disasm_file(str(dis_path))
                if js and isinstance(js, dict):
                    # Expect a list of functions or instructions under 'instructions'
                    instrs = js.get("instructions") or js.get("disasm") or []
                    for ins in instrs:
                        addr = ins.get("address")
                        text = ins.get("text") or ins.get("instruction")
                        # lightweight signature matching may be rule-driven; we emit a generic detection for now
                        if text and ("xor" in text.lower() or "add" in text.lower()):
                            details = {"snippet": text, "instr": text}
                            yield Detection(
                                path=str(f),
                                offset=addr,
                                rule="instr_pattern",
                                details=details,
                                engine="disasm",
                            )
                    continue

        # fallback: if no disasm produced, and fallback rules provided, run binary regex on files
        if self.fallback_rules:
            delegate = BinaryRegexAdapter(self.fallback_rules)
            for d in delegate.scan_files(files_list):
                d.engine = d.engine or "disasm-fallback"
                yield d
