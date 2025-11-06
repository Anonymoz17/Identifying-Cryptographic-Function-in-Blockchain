"""Constants/table detection heuristics.

Detect repeated patterns or candidate tables identified by the quick
`static_preproc` and emit findings for repeated chunks.
"""
from typing import List, Dict, Any
import hashlib
import json


def _make_id(prefix: str, text: str) -> str:
    import hashlib

    return f"{prefix}-{hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()[:8]}"


def constants_heuristic(ghidra_export: Dict, metadata: Dict, static_artifacts: Dict[str, Any] = None) -> List[Dict]:
    findings: List[Dict] = []
    if not static_artifacts:
        return findings

    const_path = static_artifacts.get("constants.json")
    if not const_path:
        return findings

    try:
        with open(const_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        consts = doc.get("constants", [])
    except Exception:
        return findings

    for c in consts:
        pattern = c.get("pattern") or ""
        count = c.get("count", 0)
        if count <= 1:
            continue
        fid = _make_id("const", pattern + str(count))
        # confidence proportional to repeat count, capped
        confidence = min(0.1 + 0.15 * (count - 1), 0.8)
        findings.append(
            {
                "id": fid,
                "type": "constant_table",
                "confidence": confidence,
                "reason_tags": ["repeated_pattern"],
                "evidence_snippet": pattern[:200],
                "count": count,
            }
        )

    return findings
