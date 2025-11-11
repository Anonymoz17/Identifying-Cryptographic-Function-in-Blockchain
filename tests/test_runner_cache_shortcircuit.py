import os
from datetime import datetime, timezone

from auditor.detectors.static_detection.runner import StaticRunner
from auditor.detectors.static_detection.preproc_adapter import _sha256_of_file, load_preproc
from auditor.detectors.static_detection.context import RunContext


def _make_preproc_dir(tmp_path, content=b"hello world"):
    preproc = tmp_path / "preproc_case"
    preproc.mkdir()
    input_path = preproc / "input.bin"
    input_path.write_bytes(content)
    # minimal metadata.json
    import json
    metadata = {"producer": "test"}
    (preproc / "metadata.json").write_text(json.dumps(metadata))
    return str(preproc)


def test_runner_reuses_cache(tmp_path):
    # create preproc dir
    preproc_dir = _make_preproc_dir(tmp_path)

    # load preproc to determine file_hash
    preproc = load_preproc(preproc_dir)
    analysis_base = str(tmp_path)

    analysis_dir = os.path.join(analysis_base, "analysis", "static", preproc.file_hash)
    os.makedirs(analysis_dir, exist_ok=True)

    # create static_results.json and fresh .cache_meta.json
    (os.path.join(analysis_dir, "static_results.json"))
    with open(os.path.join(analysis_dir, "static_results.json"), "w", encoding="utf-8") as fh:
        fh.write("[]")

    cache_meta = {
        "file_hash": preproc.file_hash,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": "quick",
        "tool_versions": {},
    }
    with open(os.path.join(analysis_dir, ".cache_meta.json"), "w", encoding="utf-8") as fh:
        import json

        json.dump(cache_meta, fh)

    # run runner and expect cached True
    runner = StaticRunner()
    ctx = RunContext(file_hash="", preproc_dir=preproc_dir, analysis_base=analysis_base, profile="quick", force=False)
    # use a simple dict for tool_versions to match the cache meta written above
    ctx.tool_versions = {}
    result = runner.run(ctx)
    assert result.cached is True
    assert result.static_results_path is not None
