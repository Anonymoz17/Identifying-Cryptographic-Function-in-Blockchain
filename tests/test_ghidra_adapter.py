import json
from pathlib import Path

from src.detectors.ghidra_adapter import GhidraAdapter


def test_ghidra_adapter_reads_mock_export(tmp_path: Path):
    # Setup a minimal fake case structure with preproc/<sha>/input.bin and
    # artifacts/ghidra_exports/<sha>/<sha>_functions.json
    sha = "deadbeef"
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True)
    input_bin = preproc_dir / "input.bin"
    input_bin.write_bytes(b"\x00\x01\x02")

    export_dir = tmp_path / "artifacts" / "ghidra_exports" / sha
    export_dir.mkdir(parents=True)

    # Load mock content from the repository tools mock (to keep test deterministic)
    repo_root = Path(__file__).resolve().parents[1]
    mock_file = (
        repo_root / "tools" / "ghidra" / "mock_exports" / "example_functions.json"
    )
    assert mock_file.exists(), "mock export json missing in tools/ghidra/mock_exports"
    raw = json.loads(mock_file.read_text(encoding="utf-8"))
    # normalize the mock: it may be a list with a single dict that has 'functions'
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
        # fallback: assume raw itself is the functions list
        funcs = raw

    # Write the export in the expected file name pattern '<sha>_functions.json'
    export_file = export_dir / f"{sha}_functions.json"
    export_file.write_text(json.dumps({"functions": funcs}), encoding="utf-8")

    # Instantiate adapter pointing to our tmp artifacts root
    adapter = GhidraAdapter(exports_root=str(tmp_path / "artifacts" / "ghidra_exports"))

    detections = list(adapter.scan_files([str(input_bin)]))
    # We expect at least one detection for the 'encrypt_data' or 'helper_sha' mock functions
    assert len(detections) >= 1
    engines = {d.engine for d in detections}
    assert "ghidra" in engines
    names = {d.details.get("function") for d in detections}
    assert any(n and ("encrypt" in n.lower() or "sha" in n.lower()) for n in names)
