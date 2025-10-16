import shutil
import sys
from pathlib import Path
from pathlib import Path as _P

# ensure src/ is on sys.path (project uses src layout)
repo_root = _P(__file__).resolve().parents[1]
src_dir = repo_root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))


def main() -> None:
    # import project modules after ensuring src/ is on sys.path
    from auditor.workspace import Workspace

    ws = Workspace(Path("tools/check_scope"), "CHECK")
    ws.ensure()
    print("evidence dir exists:", ws.evidence_dir.exists())
    # create a dummy evidence file
    p = ws.evidence_dir / "dummy.txt"
    p.write_text("x")
    # perform archive
    base = str((ws.evidence_dir.parent / "export_test").resolve())
    shutil.make_archive(base, "zip", root_dir=str(ws.evidence_dir))
    print("created", base + ".zip")


if __name__ == "__main__":
    main()
