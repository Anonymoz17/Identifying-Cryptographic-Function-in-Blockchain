import zipfile
from pathlib import Path

from auditor.setup_flow.archives import extract_archive
from auditor.setup_flow.setupcontext import FlowContext


class DummyNotifier:
    def __init__(self):
        self.msgs = []

    def info(self, text, path=None, details=None):
        self.msgs.append(("info", text, path, details))

    def warn(self, text, path=None, details=None):
        self.msgs.append(("warn", text, path, details))

    def ok(self, text, path=None, details=None):
        self.msgs.append(("ok", text, path, details))


def test_extract_zip(tmp_path):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("foo.txt", "hello")

    ctx = FlowContext(scope=tmp_path, workdir=tmp_path, case_id="C1")
    ctx.case_dir = tmp_path
    # enable extraction in config for the test
    ctx.config.extract_archives = True
    notifier = DummyNotifier()
    res = list(extract_archive(z, ctx, notifier=notifier, sandbox_parent=tmp_path, recursive=False))
    assert any(r.get("path") for r in res)
    # ensure file content exists
    p = res[0]["path"]
    assert Path(p).exists()
    assert Path(p).read_text(encoding="utf-8") == "hello"
