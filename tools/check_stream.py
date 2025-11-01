"""Quick diagnostic: stream-enumerate the repository without hashing and write an incremental manifest.

This script prints progress and exits after a short limit so it's safe to run on large repos.
"""

import json
import os
import sys
import threading
import time
from pathlib import Path

# ensure local src is importable
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from auditor.intake import count_inputs, enumerate_inputs_iter  # noqa: E402


def main():
    scope = "."
    manifest = Path("tools") / "_stream_check_manifest.ndjson"
    max_items = 500
    timeout = 12.0

    # start background count
    total_est = None

    def count_worker():
        nonlocal total_est
        try:
            total_est = count_inputs([scope])
        except Exception:
            total_est = None

    tcount = threading.Thread(target=count_worker, daemon=True)
    tcount.start()

    start = time.time()
    seen = 0
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", encoding="utf-8") as mf:
        try:
            it = enumerate_inputs_iter([scope], compute_sha=False)
            for item in it:
                seen += 1
                try:
                    mf.write(json.dumps(item, ensure_ascii=False) + "\n")
                    mf.flush()
                    try:
                        os.fsync(mf.fileno())
                    except Exception:
                        pass
                except Exception:
                    pass

                if seen % 50 == 0:
                    elapsed = time.time() - start
                    rate = seen / elapsed if elapsed > 0 else 0
                    print(f"seen={seen}, estimate={total_est}, rate={rate:.2f}/s")
                if seen >= max_items:
                    print("Reached max_items, stopping")
                    break
                if time.time() - start > timeout:
                    print("Timeout reached, stopping")
                    break
        except KeyboardInterrupt:
            print("Interrupted")

    print(
        f"Finished: seen={seen}, estimate={total_est}, elapsed={time.time()-start:.2f}s"
    )


if __name__ == "__main__":
    main()
