from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


@dataclass
class Detection:
    path: str
    offset: Optional[int]
    rule: str
    details: Dict[str, Any]
    engine: Optional[str] = None


class BaseAdapter:
    """Base detector adapter contract.

    Implementations should provide `scan_files` which takes a list of
    paths (strings or Path objects) and yields Detection objects.
    """

    def scan_files(self, files: Iterable[str]) -> Iterable[Detection]:
        raise NotImplementedError()


class RegexAdapter(BaseAdapter):
    """A simple YARA-like regex adapter: rules is a mapping name->regex."""

    def __init__(self, rules: Dict[str, str]):
        self.rules = {k: re.compile(v) for k, v in rules.items()}

    def scan_files(self, files: Iterable[str]):
        for p in files:
            try:
                text = Path(p).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for name, rx in self.rules.items():
                for m in rx.finditer(text):
                    yield Detection(
                        path=str(p),
                        offset=m.start(),
                        rule=name,
                        details={"match": m.group(0)},
                        engine="regex",
                    )


class SimpleSemgrepAdapter(BaseAdapter):
    """A minimal Semgrep-like adapter that checks for simple substrings per-language.

    rules: mapping of name -> substring to search for.
    """

    def __init__(self, rules: Dict[str, str]):
        self.rules = rules

    def scan_files(self, files: Iterable[str]):
        for p in files:
            try:
                text = Path(p).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for name, substr in self.rules.items():
                idx = text.find(substr)
                if idx >= 0:
                    yield Detection(
                        path=str(p),
                        offset=idx,
                        rule=name,
                        details={"snippet": substr},
                        engine="semgrep-lite",
                    )


class YaraAdapter(BaseAdapter):
    """Adapter that uses the python `yara` bindings when available.

    Initialization options:
    - rules_map: a mapping of rule name -> simple pattern (regular expression string). Used as a fallback
      when the `yara` module is not installed.
    - rules_path: path to a .yar rules file. Only used when the `yara` module is available.

    Behavior:
    - If `yara` is importable and a rules_path is provided, the adapter compiles the rules and
      scans files as raw bytes, yielding detections for each match (including offsets).
    - Otherwise, if a `rules_map` is provided, the adapter delegates to the existing
      `RegexAdapter` implementation (text-based).
    - If neither is provided, initialization raises ValueError.
    """

    def __init__(
        self,
        rules_map: Optional[dict] = None,
        rules_path: Optional[str] = None,
        rules_dir: Optional[str] = None,
        rules_str: Optional[str] = None,
    ):
        self.rules_map = rules_map
        self.rules_path = rules_path
        self.rules_dir = rules_dir
        self.rules_str = rules_str
        self._yara = None
        self._compiled = None
        try:
            import yara as _yara  # type: ignore

            self._yara = _yara
        except Exception:
            self._yara = None

        # Try compiling from provided sources in order: rules_path, rules_dir, rules_str
        if self._yara:
            try:
                if self.rules_path:
                    self._compiled = self._yara.compile(filepath=self.rules_path)
                elif self.rules_dir:
                    # compile a directory of .yar files
                    self._compiled = self._yara.compile(
                        filepaths={
                            p.name: str(p)
                            for p in Path(self.rules_dir).glob("**/*.yar")
                        }
                    )
                elif self.rules_str:
                    # compile from a raw string
                    self._compiled = self._yara.compile(source=self.rules_str)
            except Exception:
                self._compiled = None

        # Fallback delegate when yara not available or compilation failed
        if not self._compiled and self.rules_map:
            self._delegate = RegexAdapter(self.rules_map)
        else:
            self._delegate = None

        if not self._compiled and not self._delegate:
            raise ValueError(
                "YaraAdapter requires either an available yara runtime + rules_path or a rules_map fallback"
            )

    def scan_files(self, files: Iterable[str]):
        # If we have a compiled yara ruleset, scan files as bytes and yield detailed matches
        if self._compiled:
            for p in files:
                try:
                    data = Path(p).read_bytes()
                except Exception:
                    continue
                try:
                    matches = self._compiled.match(data=data)
                except Exception:
                    # if match fails (timeout or otherwise) skip
                    continue
                for m in matches:
                    # m.strings is iterable of (offset, id, data)
                    for s in getattr(m, "strings", []):
                        try:
                            off = int(s[0])
                        except Exception:
                            off = None
                        detail = {
                            "string_id": s[1],
                            "data": (
                                s[2].decode("utf-8", errors="ignore")
                                if isinstance(s[2], (bytes, bytearray))
                                else s[2]
                            ),
                        }
                        # enrich with rule metadata if available
                        meta = getattr(m, "meta", None)
                        tags = getattr(m, "tags", None)
                        if meta:
                            detail["meta"] = meta
                        if tags:
                            detail["tags"] = tags
                        # also attach rule filename if yara provides it
                        filename = getattr(m, "filename", None)
                        if filename:
                            detail["rule_file"] = filename
                        yield Detection(
                            path=str(p),
                            offset=off,
                            rule=m.rule,
                            details=detail,
                            engine="yara",
                        )
            return

        # Otherwise delegate to RegexAdapter (text-based fallback)
        if self._delegate:
            for d in self._delegate.scan_files(files):
                # annotate fallback engine as yara-fallback to keep provenance
                d.engine = d.engine or "yara-fallback"
                yield d


class BinaryRegexAdapter(BaseAdapter):
    """Search raw bytes for regex-like byte patterns.

    rules: mapping of name -> pattern. Patterns should be provided as bytes or strings.
    If strings, they're compiled as regex against bytes (using re.compile(pattern.encode())).
    """

    def __init__(self, rules: Dict[str, bytes | str]):
        compiled = {}
        for k, v in rules.items():
            if isinstance(v, str):
                pat = v.encode("utf-8")
            else:
                pat = v
            # use the regex engine on bytes
            compiled[k] = re.compile(pat)
        self.rules = compiled

    def scan_files(self, files: Iterable[str]):
        for p in files:
            try:
                data = Path(p).read_bytes()
            except Exception:
                continue
            for name, rx in self.rules.items():
                for m in rx.finditer(data):
                    off = m.start()
                    match_bytes = m.group(0)
                    # decode human-readable when possible
                    try:
                        match_text = match_bytes.decode("utf-8")
                    except Exception:
                        match_text = None
                    details = {
                        "match_bytes": match_bytes.hex(),
                        "match_text": match_text,
                    }
                    yield Detection(
                        path=str(p),
                        offset=off,
                        rule=name,
                        details=details,
                        engine="binary-regex",
                    )
