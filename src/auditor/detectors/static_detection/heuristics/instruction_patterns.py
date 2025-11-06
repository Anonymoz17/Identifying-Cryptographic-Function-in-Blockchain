"""Instruction pattern heuristics (quick-profile).

When Ghidra export isn't available in the quick profile, fall back to
entropy analysis produced by `static_preproc` to surface candidate regions
that may contain crypto tables or compressed/packed data.
"""
from typing import List, Dict, Any
import hashlib
import json


def _make_id(prefix: str, text: str) -> str:
    import hashlib

    return f"{prefix}-{hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()[:8]}"


def instruction_patterns_heuristic(ghidra_export: Dict, metadata: Dict, static_artifacts: Dict[str, Any] = None) -> List[Dict]:
    findings: List[Dict] = []
    if not static_artifacts:
        return findings

    ent_path = static_artifacts.get("entropy_map.json")
    if not ent_path:
        return findings

    try:
        with open(ent_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        entmap = doc.get("entropy_map", [])
    except Exception:
        return findings

    # find windows with high entropy
    for e in entmap:
        ent = e.get("entropy", 0.0)
        off = e.get("offset")
        if ent >= 7.5:
            fid = _make_id("entropy", f"{off}:{ent}")
            findings.append(
                {
                    "id": fid,
                    "type": "high_entropy_region",
                    "confidence": 0.6,
                    "reason_tags": ["entropy"],
                    "evidence_snippet": f"offset={off} entropy={ent}",
                    "address_or_range": {"start": hex(off), "end": hex(off + 1)},
                }
            )

    return findings
