from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .adapter import BaseAdapter, Detection


def load_manifest_paths(manifest_path: str) -> List[str]:
    p = Path(manifest_path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            # prefer artifact_dir + input.bin if present else path
            if obj.get("artifact_dir"):
                base = Path(p.parent) / obj.get("artifact_dir")
                cand = base / "input.bin"
                if cand.exists():
                    out.append(str(cand))
                    continue
            out.append(obj.get("path"))
        except Exception:
            continue
    return out


def run_adapters(
    adapters: Iterable[BaseAdapter], files: Iterable[str]
) -> Iterable[Detection]:
    for adapter in adapters:
        for d in adapter.scan_files(files):
            yield d


def write_ndjson_detections(detections: Iterable[Detection], out_path: str) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for d in detections:
            obj = {
                "path": d.path,
                "offset": d.offset,
                "rule": d.rule,
                "details": d.details,
            }
            if getattr(d, "engine", None):
                obj["engine"] = d.engine
            # lift common yara metadata fields to top-level for easier filtering
            try:
                if isinstance(d.details, dict):
                    if "tags" in d.details:
                        obj["tags"] = d.details.get("tags")
                    if "meta" in d.details:
                        obj["meta"] = d.details.get("meta")
            except Exception:
                # don't fail writes if details are non-dict or have unexpected types
                pass
            # lift rule filename/namespace if present
            try:
                if isinstance(d.details, dict):
                    if "rule_file" in d.details:
                        obj["rule_file"] = d.details.get("rule_file")
                    if "namespace" in d.details:
                        obj["rule_namespace"] = d.details.get("namespace")
            except Exception:
                pass

            # compute a confidence score: adapter may provide 'confidence' in details; otherwise use engine defaults
            engine_defaults = {
                "yara": 0.9,
                "yara-fallback": 0.5,
                "binary-regex": 0.65,
                "regex": 0.5,
                "semgrep-lite": 0.6,
            }
            try:
                conf = None
                if isinstance(d.details, dict) and "confidence" in d.details:
                    conf = float(d.details.get("confidence"))
                else:
                    conf = engine_defaults.get(getattr(d, "engine", None), 0.5)
                obj["confidence"] = conf
            except Exception:
                obj["confidence"] = 0.5

            f.write(json.dumps(obj) + "\n")
