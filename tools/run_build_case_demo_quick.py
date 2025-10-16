import sys
from pathlib import Path


def main():
    ROOT = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(ROOT))
    from auditor import evidence

    root = Path("case_demo/CASE-001").resolve()
    print("root", root)
    # collect only well-known files (no preproc inputs)
    files = [
        root / "engagement.json",
        root / "inputs.manifest.json",
        root / "preproc.index.jsonl",
        root / "auditlog.ndjson",
    ]
    files = [f for f in files if f.exists()]
    print("collected", len(files))
    for i, f in enumerate(files, 1):
        try:
            print(i, f.relative_to(root))
        except Exception:
            print(i, f)

    zip_path, zip_sha = evidence.build_evidence_pack(
        root, "CASE-001", files=files, out_dir=root / "evidence"
    )
    print("zip", zip_path.exists(), zip_path)
    print("sha", zip_sha)
    print("zip size", zip_path.stat().st_size)
    print(".sha exists", (zip_path.with_suffix(zip_path.suffix + ".sha256")).exists())

    import json
    import zipfile

    with zipfile.ZipFile(zip_path) as zf:
        print("zip entries count", len(zf.namelist()))
        if "evidence_manifest.json" in zf.namelist():
            mf = json.loads(zf.read("evidence_manifest.json").decode("utf-8"))
            print("manifest file count", len(mf.get("files", [])))
            for entry in mf.get("files", []):
                print("-", entry["path"], entry["sha256"], entry.get("size"))
        else:
            print("no manifest in zip")


if __name__ == "__main__":
    main()
