import os
import hashlib
import importlib.util


def _load_adapter_module():
    # Load module directly from file since package path contains a hyphen and
    # cannot be imported using normal package syntax.
    repo_root = os.path.dirname(os.path.dirname(__file__))
    module_path = os.path.join(
        repo_root, "..", "src", "auditor", "detectors", "static_detection", "preproc_adapter.py"
    )
    module_path = os.path.normpath(module_path)
    spec = importlib.util.spec_from_file_location("preproc_adapter", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_load_preproc_computes_hash(tmp_path):
    preproc_adapter = _load_adapter_module()
    # Use the fixture files under tests/fixtures/preproc_example
    repo_root = os.path.dirname(os.path.dirname(__file__))
    fixture_dir = os.path.join(repo_root, "fixtures", "preproc_example")

    # sanity: ensure fixture exists
    assert os.path.isdir(fixture_dir)

    result = preproc_adapter.load_preproc(fixture_dir)

    assert "file_hash" in result
    assert "input_path" in result
    assert "metadata" in result

    # compute expected hash and compare
    h = hashlib.sha256()
    with open(result["input_path"], "rb") as fh:
        h.update(fh.read())
    expected = h.hexdigest()
    assert result["file_hash"] == expected


def test_missing_files_raise(tmp_path):
    preproc_adapter = _load_adapter_module()
    # directory without required files
    d = tmp_path / "empty"
    d.mkdir()
    try:
        preproc_adapter.load_preproc(str(d))
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass
