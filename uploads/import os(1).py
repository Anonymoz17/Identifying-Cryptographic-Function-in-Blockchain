import os
import re
import json

# 1️⃣ Define known crypto libraries and their key patterns
CRYPTO_LIBS = {
    "OpenSSL": [r'\bEVP_', r'\bRSA_', r'\bAES_'],
    "NaCl/libsodium": [r'\bcrypto_box_', r'\bcrypto_sign_'],
    "BoringSSL": [r'\bSSL_', r'\bBIGNUM_'],
    "crypto-js": [r'\bCryptoJS\.', r'\bAES\.encrypt'],
    "Web3.py": [r'\bweb3\.Middleware\.sign\(', r'\bAccount\.sign_transaction'],
}

# 2️⃣ Recursively scan for .c/.cpp/.py/.js files
def collect_source_files(root_path):
    for root, _, files in os.walk(root_path):
        for f in files:
            if f.endswith(('.c', '.cpp', '.py', '.js')):
                yield os.path.join(root, f)

# 3️⃣ Search each file for library patterns
def scan_file(filepath):
    findings = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
        content = fh.read()
    for lib, patterns in CRYPTO_LIBS.items():
        for pat in patterns:
            for m in re.finditer(pat, content):
                line_no = content.count('\n', 0, m.start()) + 1
                snippet = content.splitlines()[line_no-1].strip()
                findings.append({
                    "file": filepath,
                    "line": line_no,
                    "pattern": pat,
                    "snippet": snippet,
                    "library": lib
                })
    return findings

# 4️⃣ Aggregate results and output JSON
def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("src", help="Root folder of the project to scan")
    parser.add_argument("--out", help="Output JSON report file", default="crypto_report.json")
    args = parser.parse_args()

    all_findings = []
    for path in collect_source_files(args.src):
        all_findings += scan_file(path)

    # Group by library
    report = {}
    for f in all_findings:
        lib = f["library"]
        report.setdefault(lib, []).append(f)

    with open(args.out, "w") as fo:
        json.dump(report, fo, indent=2)

    print(f"✅ Found {len(all_findings)} crypto uses; report at {args.out}")

if __name__ == "__main__":
    main()
