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


def test_entropy_map_includes_tail(tmp_path):
    # create an input.bin of 300 bytes (not multiple of 256 window)
    data = bytes([i % 256 for i in range(300)])
    pre = tmp_path / "pre"
    out = tmp_path / "out"
    pre.mkdir()
    (pre / "input.bin").write_bytes(data)
    # import module using same loader to match test env
    mod = _load_module()
    mod.generate_static_preproc(str(pre), str(out), profile="quick")
    ent_path = out / "entropy_map.json"
    assert ent_path.exists()
    import json

    payload = json.loads(ent_path.read_text(encoding="utf-8"))
    entmap = payload.get("entropy_map")
    # window is 256 for quick profile: expect two entries (offset 0 and 256)
    offsets = [e["offset"] for e in entmap]
    assert offsets[0] == 0
    assert offsets[-1] == 256
    assert len(entmap) >= 2
