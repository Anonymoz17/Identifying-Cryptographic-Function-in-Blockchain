import json
import shutil
import subprocess
from pathlib import Path


def test_integration_runner_with_mock_ghidra(tmp_path: Path):
    """Integration test: copy sample case, inject mock ghidra exports, run runner,
    and assert ghidra detections appear in detector_results.ndjson.
    """
    repo_root = Path(__file__).resolve().parents[1]
    src_case = repo_root / "tools" / "case_demo" / "CASE-001"
    assert src_case.exists(), "sample case_demo/CASE-001 missing"

    # Copy case into temp dir so test doesn't mutate repo files
    dst_case = tmp_path / "CASE-001"
    shutil.copytree(src_case, dst_case)

    # Inject mock ghidra exports into the copied case using the helper script
    # (this writes into dst_case/artifacts/ghidra_exports/<sha>/)
    consume_script = repo_root / "tools" / "consume_ghidra_mock.py"
    assert consume_script.exists(), "consume_ghidra_mock.py helper missing"

    env = dict(**{"PYTHONPATH": str(repo_root)})

    subprocess.run(
        [str(Path("python")), str(consume_script), "--case", str(dst_case)],
        check=True,
        env=env,
    )

    # Now run the detector flow programmatically using the runner helpers so we
    # can point the GhidraAdapter at dst_case/artifacts/ghidra_exports directly.
    from src.detectors.adapter import RegexAdapter
    from src.detectors.ghidra_adapter import GhidraAdapter
    from src.detectors.runner import (
        load_manifest_paths,
        run_adapters,
        write_ndjson_detections,
    )

    manifest = dst_case / "inputs.manifest.ndjson"
    files = load_manifest_paths(str(manifest), base_dir=str(dst_case))

    # build a minimal adapter set including GhidraAdapter pointing to our case
    adapters = [
        RegexAdapter({"crypto_fallback": r"sha|AES|md5"}),
        GhidraAdapter(exports_root=str(dst_case / "artifacts" / "ghidra_exports")),
    ]

    detections_iter = list(run_adapters(adapters, files))

    # write NDJSON output like the runner would
    out_file = dst_case / "detector_results.ndjson"
    write_ndjson_detections(detections_iter, str(out_file))

    # also produce a merged NDJSON using the same merge logic used by the
    # real runner so tests can assert final fused outputs
    try:
        from src.detectors.merge import dedupe_detections

        merged = dedupe_detections(detections_iter)
        merged_out = dst_case / "detector_results_merged.ndjson"
        with merged_out.open("w", encoding="utf-8") as mf:
            for m in merged:
                mf.write(
                    json.dumps(
                        {
                            "path": m.path,
                            "offset": m.offset,
                            "rule": m.rule,
                            "details": m.details,
                            "engine": m.engine,
                        }
                    )
                    + "\n"
                )
    except Exception:
        merged_out = None

    out_file = dst_case / "detector_results.ndjson"
    assert out_file.exists(), "detector_results.ndjson not produced"

    found_ghidra = False
    for line in out_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        if j.get("engine") == "ghidra":
            found_ghidra = True
            break

    assert found_ghidra, "No ghidra-engine detections found in detector_results.ndjson"
