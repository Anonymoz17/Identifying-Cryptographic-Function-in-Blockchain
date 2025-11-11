import json
import os
from pathlib import Path

import pytest

from auditor.detectors.static_detection import static_preproc
from auditor.detectors.static_detection.heuristics.signature import signature_heuristic
from auditor.detectors.static_detection.heuristics.constants import constants_heuristic
from auditor.detectors.static_detection.heuristics.instruction_patterns import instruction_patterns_heuristic
from auditor.detectors.static_detection.runner import StaticRunner
from auditor.detectors.static_detection.context import RunContext


def _write_preproc_fixture(tmp_path: Path, content: bytes) -> Path:
    preproc_dir = tmp_path / "preproc_fixture"
    preproc_dir.mkdir()
    input_path = preproc_dir / "input.bin"
    input_path.write_bytes(content)
    metadata = {"orig_filename": "sample.bin"}
    (preproc_dir / "metadata.json").write_text(json.dumps(metadata))
    return preproc_dir


def test_static_preproc_generates_artifacts(tmp_path):
    data = b"This is a test binary with AES and RSA and some repeated patterns." + b"ABCD" * 10
    preproc_dir = _write_preproc_fixture(tmp_path, data)

    out_dir = tmp_path / "analysis_preproc"
    artifacts = static_preproc.generate_static_preproc(str(preproc_dir), str(out_dir), profile="quick")

    # expected artifacts
    assert "strings.json" in artifacts
    assert "constants.json" in artifacts
    assert "entropy_map.json" in artifacts

    with open(artifacts["strings.json"], "r", encoding="utf-8") as fh:
        sdoc = json.load(fh)
    assert isinstance(sdoc.get("strings"), list)
    # should include ASCII keywords
    joined = "\n".join(sdoc.get("strings", []))
    assert "AES" in joined or "RSA" in joined


def test_heuristics_produce_findings(tmp_path):
    data = b"contains AES keyword and some table data" + b"1234" * 6
    preproc_dir = _write_preproc_fixture(tmp_path, data)
    out_dir = tmp_path / "analysis_preproc2"
    artifacts = static_preproc.generate_static_preproc(str(preproc_dir), str(out_dir), profile="quick")

    # signature heuristic
    sig = signature_heuristic({}, {}, static_artifacts=artifacts)
    assert isinstance(sig, list)

    # constants heuristic
    consts = constants_heuristic({}, {}, static_artifacts=artifacts)
    assert isinstance(consts, list)

    # entropy heuristic (may be empty depending on content)
    entropy = instruction_patterns_heuristic({}, {}, static_artifacts=artifacts)
    assert isinstance(entropy, list)


def test_runner_quick_path_creates_outputs(tmp_path):
    data = b"Runner sample AES content" + b"PATTERN" * 5
    preproc_dir = _write_preproc_fixture(tmp_path, data)

    # Run StaticRunner
    ctx = RunContext(file_hash="", preproc_dir=str(preproc_dir), analysis_base=str(tmp_path), profile="quick", force=True)
    runner = StaticRunner()
    result = runner.run(ctx)

    assert result is not None
    assert result.static_results_path is not None
    assert os.path.isfile(result.static_results_path)

    with open(result.static_results_path, "r", encoding="utf-8") as fh:
        rj = json.load(fh)
    assert rj.get("file_hash")
    assert isinstance(rj.get("findings"), list)
