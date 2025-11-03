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
            # semgrep JSON commonly has a top-level dict with 'results' list
            # but some versions or wrapped outputs can be a list directly.
            if isinstance(parsed, dict):
                # Prefer 'results' key, fallback to 'matches' or to empty list
                if "results" in parsed and isinstance(parsed["results"], list):
                    return parsed["results"]
                if "matches" in parsed and isinstance(parsed["matches"], list):
                    return parsed["matches"]
                # Some semgrep outputs include results under 'results'->'results'
                for k in ("results", "matches"):
                    v = parsed.get(k)
                    if isinstance(v, dict) and isinstance(v.get("results"), list):
                        return v.get("results", [])
                return []
            elif isinstance(parsed, list):
                return parsed
            else:
                return []
        except Exception:
            return []

    def scan_files(self, files: Iterable[str]):
        files_list = list(files)
        if self._has_semgrep:
            # For large file lists, run semgrep per-file (streaming) to avoid
            # excessive memory usage. For small batches, run once for speed.
            results = []
            if len(files_list) > 50:
                for f in files_list:
                    results.extend(self._run_semgrep([f]))
            else:
                results = self._run_semgrep(files_list)

            for r in results:
                # Normalize common fields across semgrep versions
                path = (
                    r.get("path") or r.get("location", {}).get("path")
                    if isinstance(r.get("location"), dict)
                    else r.get("path")
                )
                check_id = (
                    r.get("check_id")
                    or r.get("check_id")
                    or r.get("extra", {}).get("id")
                    or r.get("rule_id")
                )
                extra = r.get("extra", {}) or {}
                start = r.get("start") or r.get("location", {}).get("start", {}) or {}
                line = start.get("line") or start.get("row") or None
                # snippet may be under extra.lines (string/list) or extra.message
                snippet = None
                if isinstance(extra.get("lines"), (list, tuple)):
                    snippet = "\n".join(extra.get("lines"))
                else:
                    snippet = (
                        extra.get("lines")
                        or extra.get("message")
                        or r.get("extra", {}).get("message")
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
