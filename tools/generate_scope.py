"""Generate a test scope directory with random files for fast debugging.

Usage:
    python tools/generate_scope.py --dir PATH --count N --size MIN MAX

Defaults: creates ./tools/sample_scope with 20 files sized 1KB-16KB.
This script is intentionally cross-platform and fast.
"""

from __future__ import annotations

import argparse
import os
import random
import string
from pathlib import Path

CHARS = string.ascii_letters + string.digits + " \n\t!@#$%^&*()-_=+[]{};:,.<>?/"


def make_random_file(path: Path, size: int):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write pseudo-random bytes/text; use os.urandom for binary-like data
    with path.open("wb") as f:
        # Mix deterministic patterns to avoid compressing too well
        f.write(os.urandom(max(0, size // 4)))
        # Append repeated textual content
        text = "".join(random.choice(CHARS) for _ in range(256)) + "\n"
        while f.tell() < size:
            f.write(text.encode("utf-8"))


def generate(
    scope_dir: Path, count: int = 20, min_size: int = 1024, max_size: int = 16 * 1024
):
    scope_dir = Path(scope_dir)
    scope_dir.mkdir(parents=True, exist_ok=True)

    created = []
    for i in range(1, count + 1):
        # create some subdirectory structure
        sub = scope_dir / f"dir_{random.randint(1,5)}"
        fname = f"file_{i:03d}.dat"
        p = sub / fname
        size = random.randint(min_size, max_size)
        make_random_file(p, size)
        created.append(p)
    return created


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--dir", default="tools/sample_scope", help="Directory to create scope files"
    )
    ap.add_argument("--count", type=int, default=20, help="Number of files to create")
    ap.add_argument(
        "--min-size", type=int, default=1024, help="Minimum file size in bytes"
    )
    ap.add_argument(
        "--max-size", type=int, default=16 * 1024, help="Maximum file size in bytes"
    )
    ns = ap.parse_args()
    files = generate(Path(ns.dir), ns.count, ns.min_size, ns.max_size)
    print(f"Created {len(files)} files under {ns.dir}")
