import os
import importlib.util


def _load_module():
    repo_root = os.path.abspath(os.path.dirname(__file__) + os.sep + "..")
    module_path = os.path.normpath(os.path.join(repo_root, "src", "auditor", "detectors", "static_detection", "static_preproc.py"))
    spec = importlib.util.spec_from_file_location("static_preproc", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generate_static_preproc_creates_artifacts(tmp_path):
    mod = _load_module()
    repo_root = os.path.abspath(os.path.dirname(__file__) + os.sep + "..")
    fixture_dir = os.path.join(repo_root, "tests", "fixtures", "preproc_example")
    out_dir = str(tmp_path / "out")
    artifacts = mod.generate_static_preproc(fixture_dir, out_dir, profile="quick")

    # expected artifact files
    expected = ["sections.json", "strings.json", "imports.json", "constants.json", "entropy_map.json"]
    assert set(artifacts.keys()) == set(expected)

    for name, path in artifacts.items():
        assert os.path.isfile(path)
        # ensure JSON contains our generated marker
        import json

        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert data.get("generated") is True
        assert data.get("profile") == "quick"
