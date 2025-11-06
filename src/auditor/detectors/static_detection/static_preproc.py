"""Generate lightweight static preproc artifacts from a preproc directory.

This module implements a conservative, pure-Python `generate_static_preproc`
used by unit tests and as a quick-profile extractor. It is intentionally
lightweight (no external deps) so CI and local dev can run quickly.

Artifacts produced (JSON):
- sections.json
- strings.json
- imports.json
- constants.json
- entropy_map.json

Each artifact contains a small marker payload: {"generated": True, "profile": ...}
and additional minimal data useful for downstream heuristics.
"""
from typing import Dict, Any
import os
import json


def _extract_ascii_strings(data: bytes, min_len: int = 4):
    res = []
    cur = []
    for b in data:
        if 0x20 <= b <= 0x7e:  # printable ASCII
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                res.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        res.append("".join(cur))
    return res


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    import math

    ent = 0.0
    L = len(data)
    for v in freq.values():
        p = v / L
        ent -= p * math.log2(p)
    return ent


def generate_static_preproc(preproc_dir: str, out_dir: str, profile: str = "quick") -> Dict[str, str]:
    """Generate static preproc artifacts.

    Args:
        preproc_dir: path to directory containing `input.bin` and `metadata.json`.
        out_dir: directory where artifacts will be written (will be created).
        profile: 'quick' or 'full' (controls detail level).

    Returns: mapping of artifact filename -> absolute path
    """
    preproc_dir = os.path.abspath(preproc_dir)
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    input_path = os.path.join(preproc_dir, "input.bin")
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"preproc input not found: {input_path}")

    with open(input_path, "rb") as fh:
        data = fh.read()

    artifacts: Dict[str, Any] = {}

    # sections.json: conservative placeholder describing the whole blob
    sections = [{"name": "raw", "offset": 0, "size": len(data)}]
    artifacts["sections.json"] = {"generated": True, "profile": profile, "sections": sections}

    # strings.json: extract printable ASCII strings
    strings = _extract_ascii_strings(data, min_len=4)
    if profile != "full":
        strings = strings[:200]
    artifacts["strings.json"] = {"generated": True, "profile": profile, "strings": strings}

    # imports.json: without disassembly, leave empty list placeholder
    artifacts["imports.json"] = {"generated": True, "profile": profile, "imports": []}

    # constants.json: detect repeating sequences (naive) as candidate tables
    constants = []
    # simple heuristic: look for repeated 4-byte sequences
    if len(data) >= 8:
        seen = {}
        for i in range(0, len(data) - 4 + 1):
            chunk = data[i : i + 4]
            seen.setdefault(chunk, 0)
            seen[chunk] += 1
        for k, v in seen.items():
            if v > 3:
                constants.append({"pattern": k.hex(), "count": v})
    artifacts["constants.json"] = {"generated": True, "profile": profile, "constants": constants}

    # entropy_map.json: sliding-window entropy
    window = 64 if profile == "full" else 256
    entmap = []
    for off in range(0, max(1, len(data) - window + 1), window):
        chunk = data[off : off + window]
        entmap.append({"offset": off, "entropy": _entropy(chunk)})
    artifacts["entropy_map.json"] = {"generated": True, "profile": profile, "entropy_map": entmap}

    # write artifacts
    out_paths: Dict[str, str] = {}
    for name, payload in artifacts.items():
        p = os.path.join(out_dir, name)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        out_paths[name] = p

    return out_paths


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("preproc_dir")
    p.add_argument("out_dir")
    p.add_argument("--profile", default="quick")
    args = p.parse_args()
    print(generate_static_preproc(args.preproc_dir, args.out_dir, profile=args.profile))

