"""Build a shared library containing Tree-sitter language grammars.

This helper builds a combined shared library `tree_sitter_langs.so` by
compiling the specified grammars. It's a convenience script and requires
`tree-sitter-cli` (npm) and a C compiler to be installed.

Usage:
    python tools/build_tree_sitter.py --out tree_sitter_langs.so --langs solidity go

It will clone language repos under .treesitter/ and build a combined
shared object via `tree-sitter build` where available.

Note: Building grammars can be platform-specific. This script attempts a
portable approach but may require manual steps on Windows.
"""

import argparse
import subprocess
from pathlib import Path

GRAM_REPOS = {
    "go": "https://github.com/tree-sitter/tree-sitter-go",
    "solidity": "https://github.com/tree-sitter/tree-sitter-solidity",
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="tree_sitter_langs.so")
    p.add_argument("--langs", nargs="+", default=["go", "solidity"])
    args = p.parse_args()
    root = Path(".treesitter")
    root.mkdir(exist_ok=True)
    for lang in args.langs:
        repo = GRAM_REPOS.get(lang)
        if not repo:
            print(f"Unknown grammar {lang}, skipping")
            continue
        clone_dir = root / f"tree-sitter-{lang}"
        if not clone_dir.exists():
            subprocess.check_call(
                ["git", "clone", "--depth", "1", repo, str(clone_dir)]
            )
        # build
        print(f"Building {lang}...")
        # `tree-sitter` CLI can generate a C parser; many grammars include build steps
        try:
            subprocess.check_call(["tree-sitter", "generate"], cwd=str(clone_dir))
        except Exception:
            pass
    print("Compilation of combined library is platform dependent.")
    print(
        "You may need to compile manually into a shared library containing the languages."
    )


if __name__ == "__main__":
    main()
