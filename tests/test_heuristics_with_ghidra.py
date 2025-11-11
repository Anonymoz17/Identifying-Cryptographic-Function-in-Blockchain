import json
import os
from pathlib import Path

from src.auditor.detectors.static_detection.heuristics.signature import signature_heuristic


def test_signature_heuristic_uses_ghidra_functions(tmp_path):
    # Create a fake ghidra export list with a prototype containing an AES/EVP function
    ghidra_functions = [
        {
            "name": "foo_encrypt",
            "prototype": "int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv)",
            "function_hash": "deadbeef",
            "address": "0x401000",
        },
        {
            "name": "helper",
            "prototype": "void helper(int)",
            "function_hash": "cafebabe",
            "address": "0x402000",
        },
    ]

    findings = signature_heuristic(ghidra_export=ghidra_functions, metadata={}, static_artifacts=None)
    # We expect at least one finding (the EVP_EncryptInit_ex should trigger)
    assert isinstance(findings, list)
    assert len(findings) >= 1
    # Check that the finding references the function_hash or prototype in evidence
    found = False
    for f in findings:
        ev = f.get("evidence") or {}
        if ev.get("function_hash") == "deadbeef" or (isinstance(ev.get("prototype"), str) and "EVP_EncryptInit" in ev.get("prototype")):
            found = True
    assert found, "Expected detection for EVP_EncryptInit_ex prototype"
