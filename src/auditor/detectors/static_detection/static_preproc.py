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
import logging
import time

logger = logging.getLogger(__name__)


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


def generate_static_preproc(preproc_dir: str, out_dir: str, profile: str = "quick", timeout_sec: float = 60.0) -> Dict[str, str]:
    """Generate static preproc artifacts with timeout and progress tracking.

    Args:
        preproc_dir: path to directory containing `input.bin` and `metadata.json`.
        out_dir: directory where artifacts will be written (will be created).
        profile: 'quick' or 'full' (controls detail level).
        timeout_sec: Maximum time in seconds to spend reading/processing (default 60s).

    Returns: mapping of artifact filename -> absolute path

    Raises:
        FileNotFoundError: If preproc input not found
        TimeoutError: If processing exceeds timeout_sec
    """
    start_time = time.time()
    preproc_dir = os.path.abspath(preproc_dir)
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    input_path = os.path.join(preproc_dir, "input.bin")
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"preproc input not found: {input_path}")

    # Check for timeout before reading large files
    if time.time() - start_time > timeout_sec:
        raise TimeoutError(f"Static preproc exceeded {timeout_sec}s timeout during initialization")

    # Read file in chunks with memory limit to prevent OOM
    data_chunks = []
    total_bytes = 0
    max_file_size = 100 * 1024 * 1024  # 100MB limit for quick safety

    try:
        with open(input_path, "rb") as fh:
            while True:
                # Check timeout periodically
                if time.time() - start_time > timeout_sec:
                    raise TimeoutError(f"Static preproc file read exceeded {timeout_sec}s timeout")

                chunk = fh.read(32768)  # Read 32KB at a time
                if not chunk:
                    break
                total_bytes += len(chunk)

                # Safety limit to prevent OOM
                if total_bytes > max_file_size:
                    logger.warning(f"Input file {input_path} exceeds {max_file_size} bytes, capping at {max_file_size}")
                    data_chunks.append(chunk[:max_file_size - total_bytes + len(chunk)])
                    break

                data_chunks.append(chunk)

        data = b"".join(data_chunks)
    except TimeoutError:
        raise
    except Exception as e:
        raise RuntimeError(f"Failed to read input file {input_path}: {e}") from e

    artifacts: Dict[str, Any] = {}

    # sections.json: conservative placeholder describing the whole blob
    sections = [{"name": "raw", "offset": 0, "size": len(data)}]
    artifacts["sections.json"] = {"generated": True, "profile": profile, "sections": sections}

    # strings.json: extract printable ASCII strings
    try:
        if time.time() - start_time > timeout_sec:
            raise TimeoutError(f"Static preproc exceeded {timeout_sec}s timeout during string extraction")
        strings = _extract_ascii_strings(data, min_len=4)
        if profile != "full":
            strings = strings[:200]
        artifacts["strings.json"] = {"generated": True, "profile": profile, "strings": strings}
    except TimeoutError:
        raise
    except Exception as e:
        logger.warning(f"Failed to extract strings: {e}")
        artifacts["strings.json"] = {"generated": True, "profile": profile, "strings": [], "error": str(e)}

    # imports.json: without disassembly, leave empty list placeholder
    artifacts["imports.json"] = {"generated": True, "profile": profile, "imports": []}

    # constants.json: detect repeating sequences (naive) as candidate tables
    # OPTIMIZATION: Skip on very large files or in quick profile to prevent timeout
    constants = []
    if len(data) >= 8 and (profile == "full" or len(data) < 10 * 1024 * 1024):  # Skip if > 10MB in quick mode
        try:
            if time.time() - start_time > timeout_sec:
                raise TimeoutError(f"Static preproc exceeded {timeout_sec}s timeout during constants detection")

            # Sample data instead of scanning entire file if very large
            sample_size = min(len(data), 5 * 1024 * 1024)  # Sample up to 5MB
            sample = data[:sample_size]

            seen = {}
            for i in range(0, len(sample) - 4 + 1):
                # Periodic timeout check for very large samples
                if i % 100000 == 0 and time.time() - start_time > timeout_sec:
                    logger.warning(f"Constants detection timeout, partial results")
                    break
                chunk = sample[i : i + 4]
                seen.setdefault(chunk, 0)
                seen[chunk] += 1

            for k, v in seen.items():
                if v > 3:
                    constants.append({"pattern": k.hex(), "count": v})
        except TimeoutError:
            raise
        except Exception as e:
            logger.warning(f"Failed to detect constants: {e}")

    artifacts["constants.json"] = {"generated": True, "profile": profile, "constants": constants}

    # entropy_map.json: sliding-window entropy
    try:
        if time.time() - start_time > timeout_sec:
            raise TimeoutError(f"Static preproc exceeded {timeout_sec}s timeout during entropy calculation")

        window = 64 if profile == "full" else 256
        entmap = []
        # Walk the file in fixed-size windows and include the final partial window
        if len(data) == 0:
            entmap = []
        else:
            for off in range(0, len(data), window):
                chunk = data[off : off + window]
                entmap.append({"offset": off, "entropy": _entropy(chunk)})
        artifacts["entropy_map.json"] = {"generated": True, "profile": profile, "entropy_map": entmap}
    except TimeoutError:
        raise
    except Exception as e:
        logger.warning(f"Failed to calculate entropy: {e}")
        artifacts["entropy_map.json"] = {"generated": True, "profile": profile, "entropy_map": [], "error": str(e)}

    # write artifacts
    try:
        if time.time() - start_time > timeout_sec:
            raise TimeoutError(f"Static preproc exceeded {timeout_sec}s timeout during artifact writing")

        out_paths: Dict[str, str] = {}
        for name, payload in artifacts.items():
            p = os.path.join(out_dir, name)
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            out_paths[name] = p
    except TimeoutError:
        raise
    except Exception as e:
        logger.error(f"Failed to write artifacts: {e}")
        raise RuntimeError(f"Failed to write preproc artifacts: {e}") from e

    return out_paths


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("preproc_dir")
    p.add_argument("out_dir")
    p.add_argument("--profile", default="quick")
    args = p.parse_args()
    print(generate_static_preproc(args.preproc_dir, args.out_dir, profile=args.profile))

