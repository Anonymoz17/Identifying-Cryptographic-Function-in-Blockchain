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
    # entries
    inst.workdir_entry = DummyEntry(str(tmp_path))
    inst.case_entry = DummyEntry("CASE-001")
    inst.client_entry = DummyEntry("test-client")
    inst.scope_entry = DummyEntry(str(tmp_path))
    inst.policy_entry = DummyEntry("")
    inst.max_depth_entry = DummyEntry("1")
    inst.extract_var = DummyVar(True)
    inst.fast_scan_var = DummyVar(True)
    inst.ast_var = DummyVar(False)
    inst.disasm_var = DummyVar(False)
    inst.results_box = DummyWidget()
    inst.progress = DummyProgress()
    inst.progress_label = DummyLabel()
    inst.continue_btn = DummyBtn()
    inst.start_btn = DummyBtn()
    inst.cancel_btn = DummyBtn()
    inst._cancel_event = threading.Event()
    inst.after = lambda ms, func, *fargs: func(*fargs)
    inst.master = DummyMaster()
    return inst


def test_preproc_cancelled(monkeypatch, tmp_path):
    inst = make_setup_instance(tmp_path)

    # fake Engagement to provide a case_dir
    class DummyEng:
        def __init__(self, workdir, case_id, client=None, scope=None):
            self.workdir = Path(workdir)

        def write_metadata(self):
            pass

        def import_policy_baseline(self, policy):
            pass

    monkeypatch.setattr(ps, "Engagement", DummyEng)

    # capture appended audit events
    appended = []

    class DummyAuditLog:
        def __init__(self, path):
            self.path = path

        def append(self, ev, payload):
            appended.append((ev, payload))

    monkeypatch.setattr(ps, "AuditLog", DummyAuditLog)

    # fake enumerate_inputs -> return some items
    # accept new compute_sha and arbitrary kwargs to match the real signature
    def fake_enumerate(
        inputs, progress_cb=None, cancel_event=None, compute_sha=True, **kw
    ):
        return [{"path": "a", "sha256": "x"}]

    monkeypatch.setattr(ps, "enumerate_inputs", fake_enumerate)

    # fake write_manifest (no-op)
    monkeypatch.setattr(ps, "write_manifest", lambda p, items: None)

    # fake preprocess_items: set cancel_event and return
    def fake_preproc(items, outdir, progress_cb=None, cancel_event=None, **kw):
        if cancel_event:
            cancel_event.set()
        return {"stats": {"index_lines": 0}}

    monkeypatch.setattr(ps, "preprocess_items", fake_preproc)

    # run the flow
    ps.SetupPage._run_engagement_flow(inst)

    # ensure a preproc.cancelled event was appended
    print("DEBUG APPENDED:", appended)
    assert any(ev == "preproc.cancelled" for ev, _ in appended)


def test_preproc_failed(monkeypatch, tmp_path):
    inst = make_setup_instance(tmp_path)

    class DummyEng:
        def __init__(self, workdir, case_id, client=None, scope=None):
            self.workdir = Path(workdir)

        def write_metadata(self):
            pass

        def import_policy_baseline(self, policy):
            pass

    monkeypatch.setattr(ps, "Engagement", DummyEng)

    appended = []

    class DummyAuditLog:
        def __init__(self, path):
            self.path = path

        def append(self, ev, payload):
            appended.append((ev, payload))

    monkeypatch.setattr(ps, "AuditLog", DummyAuditLog)

    # accept new compute_sha and arbitrary kwargs to match the real signature
    def fake_enumer(
        inputs, progress_cb=None, cancel_event=None, compute_sha=True, **kw
    ):
        return [{"path": "a", "sha256": "x"}]

    monkeypatch.setattr(ps, "enumerate_inputs", fake_enumer)
    monkeypatch.setattr(ps, "write_manifest", lambda p, items: None)

    # fake preprocess_items that raises an exception (not cancellation)
    def fake_preproc_fail(items, outdir, progress_cb=None, cancel_event=None, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(ps, "preprocess_items", fake_preproc_fail)

    ps.SetupPage._run_engagement_flow(inst)

    # ensure a preproc.failed event was appended
    assert any(ev == "preproc.failed" for ev, _ in appended)
