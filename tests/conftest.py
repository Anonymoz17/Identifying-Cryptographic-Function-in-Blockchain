import sys
from pathlib import Path

# Ensure project root is importable while running tests. Use the helper
# in src/_repo.py so this remains correct after restructuring.
try:
    from _repo import find_repo_root

    repo_root = find_repo_root(Path(__file__).resolve())
except Exception:
    repo_root = Path(__file__).resolve().parents[1]

if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))
