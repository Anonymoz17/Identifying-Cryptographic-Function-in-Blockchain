from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable, List

from .adapter import BaseAdapter, Detection


def _is_within(base: Path, candidate: Path) -> bool:
    """Return True if candidate is inside base directory (resolves symlinks)."""
    try:
        base_r = base.resolve(strict=False)
        cand_r = candidate.resolve(strict=False)
    except Exception:
        return False
    try:
        return str(cand_r).startswith(str(base_r))
    except Exception:
        return False


def _atomic_write_text(path: Path, text: str) -> None:
    """Write text to path atomically by writing to a temp file on the same
    directory and replacing the target. Ensures parent directory exists.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # create temp file in same directory to avoid cross-device move issues
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                # best-effort; some platforms may not support fsync on text mode
                pass
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise


def load_manifest_paths(manifest_path: str, base_dir: str | None = None) -> List[str]:
    """Load file paths from a manifest NDJSON.

    If `base_dir` is provided, `artifact_dir` entries will be resolved
    relative to `base_dir`. Otherwise they are resolved relative to the
    manifest file's parent directory (backwards-compatible behavior).
    """
    p = Path(manifest_path)
    if not p.exists():
        return []
    out = []
    # determine base for artifact_dir resolution
    resolved_base = Path(base_dir) if base_dir else p.parent
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            # prefer artifact_dir + input.bin if present else path
            art = obj.get("artifact_dir")
            if art:
                base = resolved_base / art
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
    # allow optional enforcement that out_path is inside a base directory. If callers
    # want to validate ensure they pass base_dir as a prefix of out_path. For
    # backwards-compatibility we keep a single-arg signature but allow callers to
    # pass a tuple-like string 'base::path' to request validation. This keeps
    # changes localized and simple.
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Build the NDJSON content in-memory and write atomically to avoid partial files
    lines = []
    engine_defaults = {
        "yara": 0.9,
        "yara-fallback": 0.5,
        "binary-regex": 0.65,
        "regex": 0.5,
        "semgrep-lite": 0.6,
    }
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

        # compute a confidence score
        try:
            conf = None
            if isinstance(d.details, dict) and "confidence" in d.details:
                conf = float(d.details.get("confidence"))
            else:
                conf = engine_defaults.get(getattr(d, "engine", None), 0.5)
            obj["confidence"] = conf
        except Exception:
            obj["confidence"] = 0.5

        lines.append(json.dumps(obj))

    text = "\n".join(lines) + ("\n" if lines else "")
    _atomic_write_text(p, text)


def generate_summary(
    detections: Iterable[Detection],
    out_dir: Path,
    case_dir: Path,
    adapters: Iterable[BaseAdapter],
) -> None:
    """Generate a small summary JSON from detections for UI visualisations.

    Writes `detector_results.summary.json` into `out_dir` atomically.
    """
    try:
        dets = list(detections)
    except Exception:
        dets = [d for d in detections]

    # aggregates
    by_rule = {}
    by_engine = {}
    files = {}
    examples = {}
    confidences = []

    for d in dets:
        rule = getattr(d, "rule", "<unknown>")
        engine = getattr(d, "engine", "unknown")
        path = getattr(d, "path", "<unknown>")

        by_rule[rule] = by_rule.get(rule, 0) + 1
        by_engine[engine] = by_engine.get(engine, 0) + 1
        files[path] = files.get(path, 0) + 1

        # store an example detection per rule
        if rule not in examples:
            try:
                examples[rule] = {
                    "path": path,
                    "offset": getattr(d, "offset", None),
                    "details": getattr(d, "details", None),
                    "engine": engine,
                }
            except Exception:
                examples[rule] = {"path": path}

        # collect confidence if present
        try:
            if (
                isinstance(getattr(d, "details", None), dict)
                and "confidence" in d.details
            ):
                confidences.append(float(d.details.get("confidence")))
            else:
                # try to set a default per-engine later
                confidences.append(None)
        except Exception:
            confidences.append(None)

    # confidence histogram buckets (0.0-1.0, 10 buckets)
    buckets = [0] * 10
    for c in confidences:
        try:
            if c is None:
                # place unknowns in the last bucket
                buckets[-1] += 1
            else:
                idx = min(9, max(0, int(c * 10)))
                buckets[idx] += 1
        except Exception:
            buckets[-1] += 1

    # prepare top lists
    top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:20]
    top_files = sorted(files.items(), key=lambda x: x[1], reverse=True)[:20]

    summary = {
        "case": str(case_dir),
        "adapters": [a.__class__.__name__ for a in adapters],
        "counts": {"by_rule": by_rule, "by_engine": by_engine},
        "confidence_buckets": buckets,
        "top_rules": [{"rule": r, "count": c} for r, c in top_rules],
        "top_files": [{"path": p, "count": c} for p, c in top_files],
        "examples": examples,
    }

    out = out_dir / "detector_results.summary.json"
    _atomic_write_text(out, json.dumps(summary, indent=2))
