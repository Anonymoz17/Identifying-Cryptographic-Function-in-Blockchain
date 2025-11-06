import json
import os
from pathlib import Path

from src.auditor.detectors.static_detection.hints_generator import generate_hints


def test_hints_redaction_strips_sensitive_fields(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    # Create a mock finding containing a number of sensitive fields
    findings = [
        {
            "id": "f1",
            "type": "signature",
            "name": "AES",
            "confidence": 0.9,
            "address_or_range": "0x401000-0x401200",
            "evidence_snippet": "sensitive snippet",
            "prototype": "int AES_encrypt(...)",
            "parameters": ["unsigned char *key"],
            "disasm": "push rbp; ...",
            "function_hash": "deadbeef",
            "evidence": {"snippet": "sensitive", "prototype": "int AES_encrypt(...)"},
        }
    ]

    # Generate both full and public redacted variants by writing non-redacted file
    generate_hints(findings, str(out_dir), redact=False, file_hash="abcd")

    pub_path = out_dir / "hints_public.json"
    assert pub_path.exists(), "hints_public.json should be written"

    with open(pub_path, "r", encoding="utf-8") as fh:
        pub = json.load(fh)

    hints = pub.get("hints", [])
    assert len(hints) == 1
    h = hints[0]
    # These sensitive keys must not be present in public hints
    for k in ("address_or_range", "evidence_snippet", "prototype", "parameters", "disasm", "function_hash"):
        assert k not in h, f"Public hint should not contain {k}"
    # evidence should either be absent or not contain sensitive subkeys
    ev = h.get("evidence")
    if ev:
        for k in ("prototype", "parameters", "disasm", "function_hash", "snippet"):
            assert k not in ev
