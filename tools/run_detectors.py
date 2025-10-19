"""Simple CLI to run configured adapters against a manifest and produce an NDJSON results file.

Usage (simple):
    python tools/run_detectors.py <inputs.manifest.ndjson> <output.ndjson>

The script currently supports programmatic adapter configuration. For production use, convert this to a small config file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from src.detectors.adapter import BinaryRegexAdapter, RegexAdapter, YaraAdapter
from src.detectors.disasm_adapter import DisasmJsonAdapter
from src.detectors.ghidra_adapter import GhidraExportAdapter
from src.detectors.merge import dedupe_detections
from src.detectors.runner import (
    load_manifest_paths,
    run_adapters,
    write_ndjson_detections,
)
from src.detectors.semgrep_adapter import SemgrepCliAdapter
from src.detectors.tree_sitter_example import TreeSitterJsonExample


def load_config(path: Path) -> Any:
    txt = path.read_text(encoding="utf-8")
    try:
        return json.loads(txt)
    except Exception:
        return yaml.safe_load(txt)


def load_weights(path: Path) -> dict:
    txt = path.read_text(encoding="utf-8")
    try:
        return json.loads(txt)
    except Exception:
        return yaml.safe_load(txt)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("manifest")
    p.add_argument("out")
    p.add_argument("--config", help="path to adapters config (json or yaml)")
    p.add_argument("--weights", help="path to engine weights (json or yaml)")
    args = p.parse_args(argv)

    manifest = args.manifest
    out = args.out

    # resolve artifact_dir entries relative to the manifest parent directory
    files = load_manifest_paths(manifest, base_dir=str(Path(manifest).parent))
    if not files:
        print(f"No files found in manifest: {manifest}")
        return 1

    adapters = []
    cfg = None
    if args.config:
        cfg = load_config(Path(args.config))
        for a in cfg.get("adapters", []):
            kind = a.get("kind")
            if kind == "regex":
                adapters.append(RegexAdapter(a.get("rules", {})))
            elif kind == "yara":
                adapters.append(
                    YaraAdapter(
                        rules_map=a.get("rules"),
                        rules_path=a.get("rules_path"),
                        rules_dir=a.get("rules_dir"),
                        rules_str=a.get("rules_str"),
                    )
                )
            elif kind == "binary-regex":
                adapters.append(BinaryRegexAdapter(a.get("rules", {})))
            elif kind == "semgrep":
                adapters.append(
                    SemgrepCliAdapter(
                        rules_dir=a.get("rules_dir"),
                        fallback_rules=a.get("fallback_rules"),
                    )
                )
            elif kind == "disasm":
                adapters.append(
                    DisasmJsonAdapter(fallback_rules=a.get("fallback_rules"))
                )
            elif kind == "ghidra":
                adapters.append(GhidraExportAdapter())
            elif kind == "tree-sitter-example":
                adapters.append(TreeSitterJsonExample(query=a.get("query")))

    if not adapters:
        # default
        adapters = [
            RegexAdapter({"example_secret": "SECRET_KEY"}),
            YaraAdapter(rules_map={"example_secret": "SECRET_KEY"}),
        ]

    detections = list(run_adapters(adapters, files))

    # load engine weights if provided via flag or config
    weights = None
    if args.weights:
        weights = load_weights(Path(args.weights))
    elif cfg:
        merge_cfg = cfg.get("merge")
        if merge_cfg and merge_cfg.get("engine_weights"):
            weights = merge_cfg.get("engine_weights")

    # check if merging enabled
    merge_enabled = False
    if cfg and cfg.get("merge"):
        merge_enabled = cfg.get("merge", {}).get("enabled", False)
    if merge_enabled:
        detections = dedupe_detections(detections, engine_weights=weights)

    write_ndjson_detections(detections, out)
    print(f"Wrote detections to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
