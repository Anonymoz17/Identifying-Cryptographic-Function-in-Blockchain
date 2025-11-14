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
    """Detect crypto-related symbols from quick strings and (optionally)
    Ghidra per-function exports.

    The heuristic remains lightweight for quick-profile runs but will inspect
    `ghidra_export` (a list of function dicts produced by the bundled
    exporter) when present. It searches function `name` and `prototype` fields
    for known crypto keywords and emits findings with prototype and function
    identifiers as evidence.

    Enhancements:
    - Extracts function addresses and sizes from Ghidra metadata
    - Creates address ranges using function boundaries
    - Populates location data in additional_data field
    """
    findings: List[Dict] = []

    keywords = ["AES", "RSA", "SHA", "HMAC", "MD5", "BLAKE", "SCRYPT", "ED25519", "CURVE25519", "SECP256K1", "EVP_"]

    # 1) If a Ghidra export (list of function dicts) is provided, prefer
    # scanning prototypes and function names as higher-signal sources.
    try:
        if isinstance(ghidra_export, list) and ghidra_export:
            seen = set()
            for fn in ghidra_export:
                # function dicts are best-effort; tolerate missing keys
                name = str(fn.get("name", ""))
                proto = str(fn.get("prototype", ""))
                func_hash = fn.get("function_hash") or fn.get("id")
                address = fn.get("address") or fn.get("addr") or fn.get("entry_point")
                function_size = fn.get("size") or fn.get("length")

                combined = f"{name} {proto}"
                for kw in keywords:
                    if kw.lower() in combined.lower():
                        key = (kw.lower(), name, proto)
                        if key in seen:
                            continue
                        seen.add(key)
                        fid = _make_id("sig-fn", name + (proto or "" ) + (str(address) if address else ""))
                        confidence = 0.85 if proto else 0.65
                        finding = {
                            "id": fid,
                            "type": "signature",
                            "name": kw,
                            "confidence": confidence,
                            "reason_tags": ["ghidra_proto", kw.lower()],
                            "evidence": {
                                "prototype": proto,
                                "function_hash": func_hash,
                                "name": name,
                                "match_type": "function_prototype",
                                "keyword_matched": kw,
                            },
                            "evidence_snippet": f"Function '{name}' matches {kw} signature. Prototype: {proto if proto else 'N/A'}",
                        }

                        # Extract location data from Ghidra
                        if address or function_size:
                            additional_data = {}

                            # Convert address to hex format and create address range
                            if address:
                                try:
                                    # Handle various address formats (int, string, hex string)
                                    if isinstance(address, str):
                                        if address.startswith("0x") or address.startswith("0X"):
                                            addr_int = int(address, 16)
                                        else:
                                            addr_int = int(address)
                                    else:
                                        addr_int = int(address)

                                    start_hex = hex(addr_int)
                                    if function_size:
                                        try:
                                            size_int = int(function_size) if isinstance(function_size, str) else function_size
                                            end_hex = hex(addr_int + size_int)
                                        except (ValueError, TypeError):
                                            end_hex = start_hex
                                    else:
                                        end_hex = start_hex

                                    additional_data["address_or_range"] = {
                                        "start": start_hex,
                                        "end": end_hex,
                                    }
                                    if function_size:
                                        additional_data["address_or_range"]["size"] = function_size
                                except (ValueError, TypeError):
                                    pass

                            # Add function name as location context
                            if name and name not in ["", "Unknown"]:
                                additional_data["function_name"] = name

                            if additional_data:
                                finding["additional_data"] = additional_data

                        findings.append(finding)
            # If we found things from ghidra functions, return them (higher signal)
            if findings:
                return findings
    except Exception:
        # Fail softly — fall back to strings-based detection below
        pass

    # 2) Fall back to the original strings-based quick heuristic
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

                # Richer finding structure for consistency
                finding = {
                    "id": fid,
                    "type": "signature",
                    "name": kw,
                    "confidence": confidence,
                    "reason_tags": ["string_keyword", kw.lower()],
                    "evidence_snippet": s[:200],
                    "evidence": {
                        "match_type": "string_constant",
                        "keyword_matched": kw,
                        "matched_string": s,
                        "string_length": len(s),
                    },
                    "count": 1,
                }

                # Try to extract location info from string metadata if available
                try:
                    if isinstance(static_artifacts.get("__preproc_dir__"), str):
                        # Location info would be populated by phase 1 enrichment
                        # For now, mark that this is from string analysis
                        finding["additional_data"] = {
                            "source": "string_constant_analysis",
                            "match_location": "binary_string_section",
                        }
                except Exception:
                    pass

                findings.append(finding)
    return findings
