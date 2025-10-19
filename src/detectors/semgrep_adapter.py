from __future__ import annotations

import json
import shutil
import subprocess
from typing import Iterable, List, Optional

from .adapter import BaseAdapter, Detection, RegexAdapter


class SemgrepCliAdapter(BaseAdapter):
    """Adapter that invokes the `semgrep` CLI and converts JSON output to Detection objects.

    If `semgrep` is not on PATH, this adapter falls back to the existing
    `SimpleSemgrepAdapter` behavior by accepting a `fallback_rules` mapping.
    """

    def __init__(
        self, rules_dir: Optional[str] = None, fallback_rules: Optional[dict] = None
    ):
        self.rules_dir = rules_dir
        self.fallback_rules = fallback_rules or {}
        self._has_semgrep = shutil.which("semgrep") is not None
        if not self._has_semgrep and not self.fallback_rules:
            raise ValueError("Semgrep CLI not available and no fallback_rules provided")

    def _run_semgrep(self, files: List[str]) -> List[dict]:
        cmd = ["semgrep", "--json"]
        if self.rules_dir:
            cmd += ["--config", self.rules_dir]
        cmd += files
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            parsed = json.loads(out.decode("utf-8"))
            # semgrep JSON has 'results' array
            return parsed.get("results", [])
        except Exception:
            return []

    def scan_files(self, files: Iterable[str]):
        files_list = list(files)
        if self._has_semgrep:
            results = self._run_semgrep(files_list)
            for r in results:
                path = r.get("path")
                check_id = r.get("check_id") or r.get("extra", {}).get("id")
                extra = r.get("extra", {})
                start = r.get("start") or {}
                line = start.get("line")
                snippet = r.get("extra", {}).get("lines") or r.get("extra", {}).get(
                    "message"
                )
                details = {"snippet": snippet, "meta": extra}
                yield Detection(
                    path=path,
                    offset=line,
                    rule=check_id or "semgrep",
                    details=details,
                    engine="semgrep",
                )
            return

        # fallback to a simple substring search per-file using RegexAdapter
        delegate = RegexAdapter(self.fallback_rules)
        for d in delegate.scan_files(files_list):
            d.engine = d.engine or "semgrep-fallback"
            yield d
