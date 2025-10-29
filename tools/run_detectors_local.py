"""Run detectors against a case workspace using built-in adapters.

Usage (from repo root):
    python tools/run_detectors_local.py --case tools/case_demo/CASE-001

This script uses the runner and adapter classes in src/detectors and writes
`detector_results.ndjson` and `detector_results_merged.ndjson` under the case dir.

It defaults to a safe adapter set that falls back to regex if optional
runtimes are not available.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from src.detectors.adapter import RegexAdapter, YaraAdapter
from src.detectors.disasm_adapter import DisasmJsonAdapter
from src.detectors.ghidra_adapter import GhidraAdapter
from src.detectors.merge import dedupe_detections
from src.detectors.runner import (
    load_manifest_paths,
    run_adapters,
    write_ndjson_detections,
)
from src.detectors.semgrep_adapter import SemgrepCliAdapter
from src.detectors.tree_sitter_detector import TreeSitterDetector


def build_adapters(repo_root: str, case_dir: str | None = None) -> List:
    adapters = []
    repo_root_path = Path(repo_root)
    case_path = Path(case_dir) if case_dir else None

    # YARA adapter: prefer yara runtime + rules file under src/detectors/yara/crypto.yar
    yara_rules = str(repo_root_path / "src" / "detectors" / "yara" / "crypto.yar")
    try:
        ada = YaraAdapter(rules_path=yara_rules)
        adapters.append(ada)
    except Exception:
        # fallback to a small regex map
        try:
            fallback = {
                "crypto_fallback": r"keccak|sha3|sha256|AES|AES_encrypt|sha1|md5"
            }
            ada = YaraAdapter(rules_map=fallback)
            adapters.append(ada)
        except Exception:
            # last resort: RegexAdapter directly
            adapters.append(
                RegexAdapter({"crypto_fallback": r"keccak|sha3|sha256|AES|sha1|md5"})
            )

    # Semgrep CLI adapter: prefer semgrep if available, else fallback substring rules
    try:
        sem = SemgrepCliAdapter(
            rules_dir=None, fallback_rules={"sol_func": r"function\s+[A-Za-z0-9_]+"}
        )
        adapters.append(sem)
    except Exception:
        # fallback to simple regex
        adapters.append(RegexAdapter({"sol_func": r"function\s+[A-Za-z0-9_]+"}))

    # Tree-sitter detector (best-effort; will use AST caches when available)
    try:
        ts = TreeSitterDetector(
            queries_dir=str(repo_root_path / "src" / "detectors" / "queries")
        )
        adapters.append(ts)
    except Exception:
        # ignore
        pass

    # Disasm adapter: load disasm rules if present, else fallback ruleset
    dis_rules = str(
        repo_root_path / "src" / "detectors" / "disasm-rules" / "rules.json"
    )
    try:
        if Path(dis_rules).exists():
            d = DisasmJsonAdapter(rules_path=dis_rules)
        else:
            d = DisasmJsonAdapter(fallback_rules={})
        adapters.append(d)
    except Exception:
        pass

    # Ghidra adapter (best-effort): prefer exports under the case's artifacts
    try:
        if case_path:
            exports_root = str(case_path / "artifacts" / "ghidra_exports")
        else:
            # backwards-compatible default used in developer convenience scripts
            exports_root = str(repo_root_path / "tools" / "case_demo")
        g = GhidraAdapter(exports_root=exports_root)
        adapters.append(g)
    except Exception:
        pass

    return adapters


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True, help="Path to case workspace (workdir)")
    ap.add_argument(
        "--out",
        default="detector_results.ndjson",
        help="Output filename (relative to case)",
    )
    args = ap.parse_args()

    case_dir = Path(args.case)
    if not case_dir.exists():
        print("Case dir not found:", case_dir)
        raise SystemExit(1)

    manifest = case_dir / "inputs.manifest.ndjson"
    if not manifest.exists():
        print("Manifest not found at", manifest)
        raise SystemExit(1)

    files = load_manifest_paths(str(manifest), base_dir=str(case_dir))
    print(f"Loaded {len(files)} file paths from manifest (example: {files[:3]})")

    adapters = build_adapters(str(Path(__file__).resolve().parents[1]), str(case_dir))
    print("Using adapters:", [type(a).__name__ for a in adapters])

    detections = run_adapters(adapters, files)

    out_path = case_dir / args.out
    write_ndjson_detections(detections, str(out_path))
    print("Wrote detections to", out_path)

    # read back and run merge/dedupe
    try:
        dets = []
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            dets.append(json.loads(line))

        # convert JSON lines back to Detection-like dicts for merge convenience
        # Simple approach: wrap minimal fields
        from src.detectors.adapter import Detection

        det_objs = []
        for d in dets:
            det_objs.append(
                Detection(
                    path=d.get("path"),
                    offset=d.get("offset"),
                    rule=d.get("rule"),
                    details=d.get("details") or {},
                    engine=d.get("engine"),
                )
            )

        merged = dedupe_detections(det_objs)
        merged_out = case_dir / (
            str(args.out).replace(".ndjson", "") + "_merged.ndjson"
        )
        with merged_out.open("w", encoding="utf-8") as mf:
            for m in merged:
                mf.write(
                    json.dumps(
                        {
                            "path": m.path,
                            "offset": m.offset,
                            "rule": m.rule,
                            "details": m.details,
                            "engine": m.engine,
                        }
                    )
                    + "\n"
                )
        print("Wrote merged detections to", merged_out)
    except Exception as e:
        print("Merge step failed:", e)


if __name__ == "__main__":
    main()
