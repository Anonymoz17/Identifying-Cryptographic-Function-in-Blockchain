import subprocess
import sys
from pathlib import Path

NODES_FILE = Path(".pytest_nodes.txt")
TIMEOUT = 20  # seconds per test

if not NODES_FILE.exists():
    print(
        "Nodes file missing: run `pytest --collect-only -q > .pytest_nodes.txt` first"
    )
    sys.exit(2)

raw = NODES_FILE.read_bytes()
try:
    text = raw.decode("utf-8")
except Exception:
    text = raw.decode("utf-8", errors="replace")
raw_lines = [line for line in text.splitlines() if line.strip()]
nodes = []
for line in raw_lines:
    # sanitize: find the first path starting with tests/ or tools/
    idx = line.find("tests/")
    if idx == -1:
        idx = line.find("tools/")
    if idx != -1:
        node = line[idx:].strip()
    else:
        node = line.strip()
    # remove any non-printable or control characters
    node = "".join(ch for ch in node if ch.isprintable())
    if node:
        nodes.append(node)
print(f"Found {len(nodes)} test nodes; running each with timeout={TIMEOUT}s")

results = []
for i, node in enumerate(nodes, 1):
    print(f"[{i}/{len(nodes)}] Running {node} ...", end=" ")
    try:
        # run pytest for single node; use -q to keep output minimal
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", node], check=True, timeout=TIMEOUT
        )
        print("OK")
        results.append((node, "OK", None))
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT after {TIMEOUT}s")
        results.append((node, "TIMEOUT", None))
    except subprocess.CalledProcessError as e:
        # test failed quickly
        print(f"FAIL (rc={e.returncode})")
        results.append((node, "FAIL", e.returncode))

# summarize
print("\nSummary:\n")
for node, status, _info in results:
    if status != "OK":
        print(f"{status}: {node}")

# exit non-zero if any timeout
if any(r[1] == "TIMEOUT" for r in results):
    sys.exit(3)

print("All tests run under timeout.")
