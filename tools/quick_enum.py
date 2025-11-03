"""Quick helper to enumerate repository files using auditor.intake.

Run from the repository root:
    python tools/quick_enum.py

This prints the first 50 enumerated input paths (no hashing) so we can
quickly verify excluded directories/files are not returned.
"""

import sys
from pathlib import Path

sys.path.insert(0, "src")

from auditor.intake import enumerate_inputs_iter


def main():
    start = Path(".")
    print(f"Enumerating under: {start.resolve()}")
    count = 0
    for itm in enumerate_inputs_iter([str(start)], hash_workers=0):
        print(itm.get("path"))
        count += 1
        if count >= 50:
            break
    print(f"Printed {count} items (first 50)")


if __name__ == "__main__":
    main()
