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


def test_schema_load_failure_handling(tmp_path, monkeypatch):
    # simulate validate_schema raising RuntimeError (jsonschema missing)
    out_dir = tmp_path / "out2"
    out_dir.mkdir()

    # Monkeypatch the validator.validate_schema to raise as if jsonschema missing
    import src.auditor.detectors.static_detection.validator as validator

    def _raise(*a, **k):
        raise RuntimeError("jsonschema package is required for validation")

    monkeypatch.setattr(validator, "validate_schema", _raise)

    findings = []
    # Generate hints; code should annotate meta indicating skipped validation
    from src.auditor.detectors.static_detection.hints_generator import generate_hints

    generate_hints(findings, str(out_dir), redact=False, file_hash=("b" * 64))
    hints_path = out_dir / "hints.json"
    assert hints_path.exists()
    payload = json.loads(hints_path.read_text(encoding="utf-8"))
    meta = payload.get("meta") or {}
    # When jsonschema is not available, generator should annotate meta
    assert "schema_validation" in meta
    assert "skipped" in str(meta.get("schema_validation")).lower()
