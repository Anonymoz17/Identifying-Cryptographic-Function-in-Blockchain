from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from .adapter import BaseAdapter, BinaryRegexAdapter, Detection


class DisasmJsonAdapter(BaseAdapter):
    """Adapter that consumes `artifacts/disasm/<sha>.json` files and yields
    instruction-level detections. It can take a `rules_path` to a JSON file
    describing regex-based instruction patterns.
    When no disasm JSON is present, it can fall back to a BinaryRegexAdapter if provided.

    Rules file format: a JSON array of objects with keys `id`, `pattern`, `description`, `confidence`.
    """

    def __init__(
        self, rules_path: str | None = None, fallback_rules: dict | None = None
    ):
        self.fallback_rules = fallback_rules
        self.rules = []
        if rules_path:
            try:
                self.rules = json.loads(Path(rules_path).read_text(encoding="utf-8"))
            except Exception:
                self.rules = []

        # compile regex patterns for speed
        for r in self.rules:
            try:
                r["_re"] = re.compile(r["pattern"], flags=re.IGNORECASE)
            except Exception:
                r["_re"] = None

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
                    # Expect a list of instructions under 'instructions' or 'disasm'
                    instrs = js.get("instructions") or js.get("disasm") or []
                    # build mapping dict if present
                    mapping = {}
                    for m in js.get("mappings") or []:
                        try:
                            mapping[int(m.get("address"))] = int(m.get("offset"))
                        except Exception:
                            try:
                                mapping[m.get("address")] = m.get("offset")
                            except Exception:
                                pass

                    for ins in instrs:
                        # normalize address fields: support 'addr' or 'address'
                        raw_addr = (
                            ins.get("addr")
                            if ins.get("addr") is not None
                            else ins.get("address")
                        )
                        # prefer mapped offset when available
                        try:
                            a_key = int(raw_addr)
                        except Exception:
                            a_key = raw_addr
                        addr = mapping.get(a_key, raw_addr)
                        # normalize text: prefer full text if present, otherwise join mnemonic+op_str
                        text = ins.get("text") or ins.get("instruction")
                        if not text:
                            mnem = ins.get("mnemonic") or ""
                            op = ins.get("op_str") or ins.get("operands") or ""
                            text = f"{mnem} {op}".strip()
                        if not text:
                            continue

                        # apply rule regexes
                        for r in self.rules:
                            # support simple 'pattern' regexs and optional 'mnemonics' sequence
                            matched = False
                            if r.get("_re") and r["_re"].search(text):
                                matched = True
                            # support mnemonic sequence match: rule provides ['push','mov','call']
                            seq = r.get("mnemonics")
                            if seq and isinstance(seq, list):
                                # compare current instruction mnemonic only (single-instr rules)
                                cur_m = (ins.get("mnemonic") or "").lower()
                                if cur_m and cur_m in [s.lower() for s in seq]:
                                    matched = True

                            if matched:
                                details = {
                                    "snippet": text,
                                    "instr": text,
                                    "rule_id": r.get("id"),
                                    "address": addr,
                                }
                                # attempt to surface offset mapping later; adapter contract uses 'offset'
                                yield Detection(
                                    path=str(f),
                                    offset=addr,
                                    rule=f"disasm:{r.get('id')}",
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
