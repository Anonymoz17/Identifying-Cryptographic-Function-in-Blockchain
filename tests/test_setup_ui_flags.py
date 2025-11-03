import threading
from pathlib import Path

import pages.setup as ps


class DummyEntry:
    def __init__(self, v):
        self._v = v

    def get(self):
        return self._v


class DummyVar:
    def __init__(self, v):
        self._v = v

    def get(self):
        return self._v


class DummyWidget:
    def insert(self, *a, **k):
        pass


class DummyProgress:
    def set(self, v):
        pass


class DummyLabel:
    def configure(self, *a, **k):
        pass


class DummyBtn:
    def configure(self, *a, **k):
        pass


class DummyMaster:
    def __init__(self):
        self.current_scan_meta = {}
        self.tk = object()


def make_setup_instance(tmp_path):
    inst = object.__new__(ps.SetupPage)
    # minimal UI-like attributes used by _run_engagement_flow
    inst.workdir_entry = DummyEntry(str(tmp_path))
    inst.case_entry = DummyEntry("CASE-001")
    inst.client_entry = DummyEntry("test-client")
    inst.scope_entry = DummyEntry(str(tmp_path))
    inst.policy_entry = DummyEntry("")
    inst.max_depth_entry = DummyEntry("1")
    inst.setup_results_box = DummyWidget()
    inst.progress = DummyProgress()
    inst.progress_label = DummyLabel()
    inst.continue_btn = DummyBtn()
    inst.start_btn = DummyBtn()
    inst.cancel_btn = DummyBtn()
    inst._cancel_event = threading.Event()
    inst.after = lambda ms, func, *fargs: func(*fargs)
    inst.master = DummyMaster()
    return inst


def test_ui_flags_map_to_preproc_args(monkeypatch, tmp_path):
    """Verify the UI checkboxes control the flags passed into preprocess_items.

    We test two permutations:
    - fast_scan_var=True (fast scan) -> compute_sha should be False
      and copy_inputs should be False; extract_var controls do_extract.
    - fast_scan_var=False -> compute_sha True and copy_inputs True.
    """

    inst = make_setup_instance(tmp_path)

    # stub Engagement to provide a workdir
    class DummyEng:
        def __init__(self, workdir, case_id, client=None, scope=None):
            self.workdir = Path(workdir)

        def write_metadata(self):
            pass

        def import_policy_baseline(self, policy):
            pass

    monkeypatch.setattr(ps, "Engagement", DummyEng)

    # simple AuditLog stub
    class DummyAuditLog:
        def __init__(self, path):
            self.path = path

        def append(self, ev, payload):
            pass

    monkeypatch.setattr(ps, "AuditLog", DummyAuditLog)

    # fake enumerate_inputs_iter to yield one item with a sha
    def fake_enum_iter(inputs, compute_sha=True, progress_cb=None, cancel_event=None, hash_workers=1, **kw):
        # return an iterator yielding a single item with sha if compute_sha True
        if compute_sha:
            yield {"path": str(tmp_path / "f.txt"), "sha256": "deadbeef", "size": 1}
        else:
            # when no sha, preprocess will skip unless compute_sha later
            yield {"path": str(tmp_path / "f.txt")}

    monkeypatch.setattr(ps, "enumerate_inputs_iter", fake_enum_iter)

    # We'll capture the kwargs passed into preprocess_items
    captured = {}

    def fake_preproc(items_stream, outdir, **kwargs):
        # record the relevant flags
        captured["do_extract"] = kwargs.get("do_extract")
        captured["compute_sha"] = kwargs.get("compute_sha")
        captured["copy_inputs"] = kwargs.get("copy_inputs")
        # return minimal valid structure
        return {"stats": {"index_lines": 0}}

    monkeypatch.setattr(ps, "preprocess_items", fake_preproc)

    # Test 1: fast_scan True (no hashing), extract True
    inst.extract_var = DummyVar(True)
    inst.fast_scan_var = DummyVar(True)
    inst.ast_var = DummyVar(False)
    inst.disasm_var = DummyVar(False)

    ps.SetupPage._run_engagement_flow(inst)

    assert captured.get("do_extract") is True
    # fast_scan True -> compute_sha should be False
    assert captured.get("compute_sha") is False
    # copy_inputs mirrors compute_sha
    assert captured.get("copy_inputs") is False

    # Test 2: fast_scan False (compute hashes), extract False
    captured.clear()
    inst.extract_var = DummyVar(False)
    inst.fast_scan_var = DummyVar(False)

    ps.SetupPage._run_engagement_flow(inst)

    assert captured.get("do_extract") is False
    assert captured.get("compute_sha") is True
    assert captured.get("copy_inputs") is True
