"""Signature heuristics.

Lightweight heuristic that searches printable strings for known crypto
identifiers (AES, RSA, SHA, HMAC, etc.). This is intentionally simple and
only intended for the quick profile to produce starter hints.
"""
from typing import List, Dict, Any
import hashlib


def _make_id(prefix: str, text: str) -> str:
    h = hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()
    return f"{prefix}-{h[:8]}"


def signature_heuristic(ghidra_export: Dict, metadata: Dict, static_artifacts: Dict[str, Any] = None) -> List[Dict]:
    findings: List[Dict] = []
    if not static_artifacts:
        return findings

    strings_path = static_artifacts.get("strings.json")
    if not strings_path:
        return findings

    try:
        import json
        with open(strings_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        strs = doc.get("strings", [])
    except Exception:
        return findings

    keywords = ["AES", "RSA", "SHA", "HMAC", "MD5", "blake", "scrypt", "ed25519", "curve25519", "secp256k1"]

    seen = set()
    for s in strs:
        for kw in keywords:
            if kw.lower() in s.lower():
                key = (kw.lower(), s)
                if key in seen:
                    continue
                seen.add(key)
                fid = _make_id("sig", s + kw)
                confidence = 0.6 if len(s) >= 8 else 0.4
                findings.append(
                    {
                        "id": fid,
                        "type": "signature",
                        "name": kw,
                        "confidence": confidence,
                        "reason_tags": ["string_keyword", kw.lower()],
                        "evidence_snippet": s[:200],
                    }
                )
    return findings
