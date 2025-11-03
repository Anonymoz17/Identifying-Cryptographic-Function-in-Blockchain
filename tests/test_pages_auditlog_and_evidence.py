import pages.auditlog as pa
import pages.evidence as pe


def test_show_auditlog_viewer_verify(monkeypatch, tmp_path):
    # prepare a small auditlog file
    p = tmp_path / "auditlog.ndjson"
    p.write_text('{"event":"x"}\n')

    # dummy Toplevel/Text/CTkButton to capture command
    class DummyTop:
        def __init__(self, master):
            self.master = master

        def title(self, *a, **k):
            pass

        def geometry(self, *a, **k):
            pass

    class DummyText:
        def __init__(self, master, wrap=None):
            self._buf = []

        def pack(self, *a, **k):
            pass

        def insert(self, *a, **k):
            self._buf.append((a, k))

    cmd_holder = {}

    def fake_ctk_button(top, text=None, command=None):
        # capture the command and return a dummy with pack
        cmd_holder["cmd"] = command

        class Btn:
            def pack(self, *a, **k):
                pass

        return Btn()

    # fake AuditLog that records verify + append
    class DummyAuditLog:
        appended = []
        verify_called = False

        def __init__(self, path):
            self.path = path

        def verify(self):
            DummyAuditLog.verify_called = True
            return True

        def append(self, ev, payload):
            DummyAuditLog.appended.append((ev, payload))

    monkeypatch.setattr(pa, "tk", pa.tk)
    monkeypatch.setattr(pa, "AuditLog", DummyAuditLog)
    monkeypatch.setattr(pa, "ctk", pa.ctk)
    monkeypatch.setattr(pa.tk, "Toplevel", DummyTop)
    monkeypatch.setattr(pa, "ctk", pa.ctk)
    monkeypatch.setattr(pa.ctk, "CTkButton", fake_ctk_button)
    # Replace tk.Text used inside the module with our DummyText
    monkeypatch.setattr(pa.tk, "Text", DummyText)

    # call viewer (should create button and read file)
    pa.show_auditlog_viewer(None, str(p))

    # ensure command was captured and calling it triggers verify/append
    assert "cmd" in cmd_holder
    cmd_holder["cmd"]()
    assert DummyAuditLog.verify_called is True
    # appended should include verification event
    assert any(
        ev.startswith("auditlog.verified") or ev.startswith("auditlog.verify_failed")
        for ev, _ in DummyAuditLog.appended
    )


def test_evidence_page_calls_build_pack(monkeypatch, tmp_path):
    # create a dummy workspace root
    wd = tmp_path / "case"
    wd.mkdir()
    case_id = "CASE-001"

    # dummy Workspace.ensure behavior is simple; we'll let real Workspace be used
    # patch build_evidence_pack to verify it's called and return a dummy zip path
    called = {}

    def fake_build_evidence_pack(
        root, cid, files, out_dir, progress_cb, cancel_event, progress_step
    ):
        called["args"] = (root, cid, files, out_dir)
        # create a dummy zip file
        out_dir.mkdir(parents=True, exist_ok=True)
        z = out_dir / f"{cid}.zip"
        z.write_text("dummy")
        return (z, "deadbeef")

    # patch threading.Thread so worker runs synchronously in test
    class DummyThread:
        def __init__(self, target, daemon=True):
            self._target = target

        def start(self):
            self._target()

    monkeypatch.setattr(pe, "threading", pe.threading)
    monkeypatch.setattr(pe.threading, "Thread", DummyThread)
    monkeypatch.setattr(
        "auditor.evidence.build_evidence_pack", fake_build_evidence_pack
    )

    # patch UI classes used so no real windows are created
    class DummyTop:
        def __init__(self, master):
            pass

        def title(self, *a, **k):
            pass

        def geometry(self, *a, **k):
            pass

    monkeypatch.setattr(pe.tk, "Toplevel", DummyTop)
    # patch ctk UI elements used so they are no-ops
    monkeypatch.setattr(pe, "ctk", pe.ctk)
    monkeypatch.setattr(
        pe.ctk,
        "CTkLabel",
        lambda *a, **k: type("L", (), {"pack": lambda self, *a, **k: None})(),
    )
    monkeypatch.setattr(
        pe.ctk,
        "CTkProgressBar",
        lambda *a, **k: type(
            "PB", (), {"pack": lambda self, *a, **k: None, "set": lambda self, v: None}
        )(),
    )
    monkeypatch.setattr(
        pe.ctk,
        "CTkButton",
        lambda *a, **k: type(
            "B",
            (),
            {
                "pack": lambda self, *a, **k: None,
                "configure": lambda self, *a, **k: None,
            },
        )(),
    )

    # instantiate EvidencePage with a dummy master that has current_scan_meta
    class DummyMaster:
        def __init__(self, wd, cid):
            self.current_scan_meta = {"workdir": str(wd), "case_id": cid}
            # tkinter widgets expect master to have a 'tk' attribute; provide a dummy
            self.tk = object()

    # instantiate EvidencePage without running its __init__ (avoids tkinter init)
    inst = object.__new__(pe.EvidencePage)
    inst.master = DummyMaster(wd, case_id)
    # implement a simple .after that immediately calls the callback
    inst.after = lambda ms, func, *fargs: func(*fargs)
    # use the real _show_status implementation bound to our instance
    inst._show_status = pe.EvidencePage._show_status.__get__(inst, pe.EvidencePage)

    # call export (worker runs synchronously due to DummyThread)
    pe.EvidencePage._on_export(inst)
    # assert build_evidence_pack was called
    assert "args" in called
    root, cid, files, out_dir = called["args"]
    assert cid == case_id
    assert out_dir.exists()
