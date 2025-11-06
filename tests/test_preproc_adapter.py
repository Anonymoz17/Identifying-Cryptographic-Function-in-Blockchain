import os
import hashlib
import importlib.util
import sys
import types


def _load_adapter_module():
    # Load module directly from file since package path contains a hyphen and
    # cannot be imported using normal package syntax. Resolve the repository
    # root by walking up until we find a `src` directory to make this robust
    # to different test working directories.
    def _find_repo_root(start: str) -> str:
        cur = os.path.abspath(start)
        while True:
            if os.path.isdir(os.path.join(cur, "src")):
                return cur
            parent = os.path.dirname(cur)
            if parent == cur:
                # fallback to the start's parent
                return os.path.dirname(start)
            cur = parent

    repo_root = _find_repo_root(os.path.dirname(os.path.dirname(__file__)))
    module_path = os.path.join(
        repo_root, "src", "auditor", "detectors", "static_detection", "preproc_adapter.py"
    )
    module_path = os.path.normpath(module_path)
    spec = importlib.util.spec_from_file_location("preproc_adapter", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _install_noop_validator():
    """Install a no-op validator into sys.modules so schema checks are skipped."""
    sys.modules["auditor.detectors.static_detection.validator"] = types.SimpleNamespace(
        validate_schema=lambda instance, schema: None
    )


def _install_failing_validator():
    """Install a validator that always raises a ValueError to simulate schema failure."""
    def _fail(instance, schema):
        raise ValueError("schema validation failed: simulated")

    sys.modules["auditor.detectors.static_detection.validator"] = types.SimpleNamespace(
        validate_schema=_fail
    )


def test_load_preproc_computes_hash(tmp_path):
    preproc_adapter = _load_adapter_module()
    _install_noop_validator()
    # Use the fixture files under tests/fixtures/preproc_example
    tests_dir = os.path.dirname(__file__)
    fixture_dir = os.path.join(tests_dir, "fixtures", "preproc_example")

    # sanity: ensure fixture exists
    assert os.path.isdir(fixture_dir)

    result = preproc_adapter.load_preproc(fixture_dir)

    # support both Preproc dataclass or dict for backward-compat
    if hasattr(result, "to_dict"):
        data = result.to_dict()
    else:
        data = result

    assert "file_hash" in data
    assert "input_path" in data
    assert "metadata" in data

    # compute expected hash and compare
    h = hashlib.sha256()
    with open(data["input_path"], "rb") as fh:
        h.update(fh.read())
    expected = h.hexdigest()
    assert data["file_hash"] == expected


def test_missing_files_raise(tmp_path):
    preproc_adapter = _load_adapter_module()
    _install_noop_validator()
    # directory without required files
    d = tmp_path / "empty"
    d.mkdir()
    try:
        preproc_adapter.load_preproc(str(d))
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass


def test_metadata_matching_and_mismatch(tmp_path):
    preproc_adapter = _load_adapter_module()
    tests_dir = os.path.dirname(__file__)

    # Positive case: metadata contains matching file_hash
    _install_noop_validator()
    fixture_good = os.path.join(tests_dir, "fixtures", "preproc_with_hash")
    res_good = preproc_adapter.load_preproc(fixture_good)
    data_good = res_good.to_dict() if hasattr(res_good, "to_dict") else res_good
    assert data_good["file_hash"] == data_good["file_hash"]  # trivial, ensures no exception

    # Negative case: metadata contains mismatched file_hash -> ValueError
    fixture_bad = os.path.join(tests_dir, "fixtures", "preproc_mismatch_hash")
    try:
        preproc_adapter.load_preproc(fixture_bad)
        assert False, "expected ValueError due to hash mismatch"
    except ValueError:
        pass


def test_schema_validation_rejects_invalid_metadata(tmp_path):
    """Simulate schema validation failure and ensure load_preproc surfaces it as ValueError."""
    preproc_adapter = _load_adapter_module()
    _install_failing_validator()

    # Create a temporary preproc dir that contains schema_version so the
    # loader will attempt schema validation. Copy fixture input.bin and
    # metadata.json but augment metadata with schema_version.
    tests_dir = os.path.dirname(__file__)
    fixture_dir = os.path.join(tests_dir, "fixtures", "preproc_example")

    td = tmp_path / "preproc_with_version"
    td.mkdir()
    import shutil, json

    shutil.copyfile(os.path.join(fixture_dir, "input.bin"), str(td / "input.bin"))
    with open(os.path.join(fixture_dir, "metadata.json"), "r", encoding="utf-8") as fh:
        meta = json.load(fh)
    meta["schema_version"] = "1.0"
    with open(str(td / "metadata.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh)

    # Now loading should attempt validation and, because we installed the
    # failing validator, should raise ValueError.
    try:
        preproc_adapter.load_preproc(str(td))
        assert False, "expected ValueError due to schema validation failure"
    except ValueError:
        # expected
        pass
