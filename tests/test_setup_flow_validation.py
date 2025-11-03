from pathlib import Path
import pytest

from auditor.setup_flow.setupcontext import FlowContext, FlowConfig
from auditor.setup_flow.validation import path_validation, PathValidationError


def test_path_validation_happy(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir()
    work = tmp_path / "work"
    work.mkdir()

    ctx = FlowContext(scope=scope, workdir=work, case_id="CASE-001")
    out = path_validation(ctx)

    assert out.case_dir.exists()
    assert out.preproc_dir is not None
    assert out.manifest_path is not None
    assert out.case_dir == work / "CASE-001"


def test_path_validation_refuse_root(tmp_path):
    # use drive root (anchor) to simulate root; on POSIX this will be '/'
    root = Path(tmp_path.anchor)
    ctx = FlowContext(scope=root, workdir=tmp_path, case_id="CASE-002")
    with pytest.raises(PathValidationError):
        path_validation(ctx)
