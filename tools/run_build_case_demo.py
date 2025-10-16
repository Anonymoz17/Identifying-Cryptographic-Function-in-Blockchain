import sys
from pathlib import Path


def progress_cb(i, total):
    # print sparse progress to avoid flooding output
    if total and total > 0:
        if i % 200 == 0 or i == 1 or i == total:
            print(f"pack progress: {i}/{total}")
    else:
        if i % 200 == 0:
            print(f"pack progress: {i}")

    # Note: local package import is done inside main so tools can be imported without
    # requiring package path adjustments at import time (reduces linter E402 warnings).


def main():
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))

    from auditor import evidence

    root = Path("case_demo/CASE-001").resolve()
    print("root", root)
    files = evidence.collect_case_files(root)
    print("collected", len(files))
    for i, f in enumerate(files[:10], 1):
        try:
            print(i, f.relative_to(root))
        except Exception:
            print(i, f)

    zip_path, zip_sha = evidence.build_evidence_pack(
        root,
        "CASE-001",
        files=files,
        out_dir=root / "evidence",
        progress_cb=progress_cb,
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
        else:
            print("no manifest in zip")


if __name__ == "__main__":
    main()
