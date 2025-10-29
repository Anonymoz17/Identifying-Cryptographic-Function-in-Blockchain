import json
import tempfile
from pathlib import Path

from src.detectors.ghidra_adapter import GhidraAdapter

sha = "deadbeef"
with tempfile.TemporaryDirectory() as td:
    tmp_path = Path(td)
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True)
    input_bin = preproc_dir / "input.bin"
    input_bin.write_bytes(b"\x00\x01\x02")

    export_dir = tmp_path / "artifacts" / "ghidra_exports" / sha
    export_dir.mkdir(parents=True)

    repo_root = Path(__file__).resolve().parents[1]
    mock_file = (
        repo_root / "tools" / "ghidra" / "mock_exports" / "example_functions.json"
    )
    print("mock exists:", mock_file.exists())
    raw = json.loads(mock_file.read_text(encoding="utf-8"))
    if (
        isinstance(raw, list)
        and len(raw) == 1
        and isinstance(raw[0], dict)
        and "functions" in raw[0]
    ):
        funcs = raw[0]["functions"]
    elif isinstance(raw, dict) and "functions" in raw:
        funcs = raw["functions"]
    else:
        funcs = raw
    export_file = export_dir / f"{sha}_functions.json"
    export_file.write_text(json.dumps({"functions": funcs}), encoding="utf-8")
    print("wrote export:", export_file)
    print("export content:", export_file.read_text(encoding="utf-8"))

    adapter = GhidraAdapter(exports_root=str(tmp_path / "artifacts" / "ghidra_exports"))
    print("adapter regex:", adapter.regex.pattern)
    print("search encrypt_data ->", bool(adapter.regex.search("encrypt_data")))
    print("search helper_sha ->", bool(adapter.regex.search("helper_sha")))
    dets = list(adapter.scan_files([str(input_bin)]))
    print("detections count:", len(dets))
    for d in dets:
        print("det:", d)
