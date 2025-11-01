import os
import sys

# ruff: noqa: E402
sys.path.insert(0, os.path.abspath("src"))
import threading
from pathlib import Path

import pages.setup as ps


# Build instance similar to test
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


inst = object.__new__(ps.SetupPage)
inst.workdir_entry = DummyEntry(str(Path(".")))
inst.case_entry = DummyEntry("CASE-001")
inst.client_entry = DummyEntry("test-client")
inst.scope_entry = DummyEntry(str(Path(".")))
inst.policy_entry = DummyEntry("")
inst.max_depth_entry = DummyEntry("1")
inst.extract_var = DummyVar(True)
inst.ast_var = DummyVar(False)
inst.disasm_var = DummyVar(False)
inst.fast_scan_var = DummyVar(True)
inst.results_box = DummyWidget()
inst.progress = DummyProgress()
inst.progress_label = DummyLabel()
inst.continue_btn = DummyBtn()
inst.start_btn = DummyBtn()
inst.cancel_btn = DummyBtn()
inst._cancel_event = threading.Event()
inst.after = lambda ms, func, *fargs: func(*fargs)
inst.master = DummyMaster()


# Dummy Engagement
class DummyEng:
    def __init__(self, workdir, case_id, client=None, scope=None):
        self.workdir = Path(workdir)

    def write_metadata(self):
        pass

    def import_policy_baseline(self, policy):
        pass


ps.Engagement = DummyEng

# closure-style appended list and DummyAuditLog
appended = []


class DummyAuditLog:
    def __init__(self, path):
        self.path = path

    def append(self, ev, payload):
        print("DummyAuditLog.append called", ev, payload)
        appended.append((ev, payload))


ps.AuditLog = DummyAuditLog

# monkeypatch functions
ps.enumerate_inputs = (
    lambda inputs, progress_cb=None, cancel_event=None, compute_sha=True: [
        {"path": "a", "sha256": "x"}
    ]
)
ps.write_manifest = lambda p, items: None


def fake_preproc(items, outdir, progress_cb=None, cancel_event=None, **kw):
    if cancel_event:
        cancel_event.set()
    return {"stats": {"index_lines": 0}}


ps.preprocess_items = fake_preproc

# run flow
inst._run_engagement_flow()
print("appended final:", appended)
