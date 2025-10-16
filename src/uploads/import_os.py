"""Simple scanner to find likely cryptography usage in source trees.

This file was moved from the top-level `uploads/import os.py` and cleaned
to be a valid Python module name (`import_os.py`). It intentionally avoids
any heavy dependencies and writes a JSON report.
"""

import json
import os
import re

# 1) Define known crypto libraries and their key patterns
CRYPTO_LIBS = {
    "OpenSSL": [r"\bEVP_", r"\bRSA_", r"\bAES_"],
    "NaCl/libsodium": [r"\bcrypto_box_", r"\bcrypto_sign_"],
    "BoringSSL": [r"\bSSL_", r"\bBIGNUM_"],
    "crypto-js": [r"\bCryptoJS\.", r"\bAES\.encrypt"],
    "Web3.py": [r"\bweb3\.Middleware\.sign\(", r"\bAccount\.sign_transaction"],
}


def collect_source_files(root_path: str):
    """Yield source file paths under root_path."""
    for root, _dirs, files in os.walk(root_path):
        for f in files:
            if f.endswith((".c", ".cpp", ".py", ".js")):
                yield os.path.join(root, f)


def scan_file(filepath: str):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception:
        return findings
    for lib, patterns in CRYPTO_LIBS.items():
        for pat in patterns:
            for m in re.finditer(pat, content):
                line_no = content.count("\n", 0, m.start()) + 1
                lines = content.splitlines()
                snippet = (
                    lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else ""
                )
                findings.append(
                    {
                        "file": filepath,
                        "line": line_no,
                        "pattern": pat,
                        "snippet": snippet,
                        "library": lib,
                    }
                )
    return findings


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("src", help="Root folder of the project to scan")
    parser.add_argument(
        "--out", help="Output JSON report file", default="crypto_report.json"
    )
    args = parser.parse_args()

    all_findings = []
    for path in collect_source_files(args.src):
        all_findings += scan_file(path)

    # Group by library
    report = {}
    for f in all_findings:
        lib = f["library"]
        report.setdefault(lib, []).append(f)

    with open(args.out, "w", encoding="utf-8") as fo:
        json.dump(report, fo, indent=2)

    print(f"Found {len(all_findings)} crypto uses; report at {args.out}")


if __name__ == "__main__":
    main()
