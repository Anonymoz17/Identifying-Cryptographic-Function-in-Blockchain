import sys
from pathlib import Path

# Ensure project root is importable while running tests. Use the helper
# in src/_repo.py so this remains correct after restructuring.
try:
    from _repo import find_repo_root

    repo_root = find_repo_root(Path(__file__).resolve())
except Exception:
    repo_root = Path(__file__).resolve().parents[1]

src_dir = repo_root / "src"
# If project uses a "src/" layout, make that directory importable so tests can
# import top-level package names (e.g. 'auditor', 'core', 'file_handler').
if src_dir.exists() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
# Fallback: also ensure repo root is on sys.path for any other imports.
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))
