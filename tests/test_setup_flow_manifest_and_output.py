import json
from pathlib import Path

from auditor.setup_flow.manifest import ManifestWriter
from auditor.setup_flow.output import sanitize_name, write_text_artifact, write_binary_artifact, copy_to_output
from auditor.setup_flow.setupcontext import FlowContext


class DummyNotifier:
    def __init__(self):
        self.msgs = []

    def info(self, text, path=None, details=None):
        self.msgs.append(("info", text, path, details))


def test_manifest_writer_and_summary(tmp_path):
    p = tmp_path / "manifest.ndjson"
    notifier = DummyNotifier()
    w = ManifestWriter(p, flush_every=1, notifier=notifier)
    w.write({"id": "abc", "path": "file"})
    w.flush()
    # summary
    summary = {"written": 1}
    s = tmp_path / "manifest.summary.json"
    w.write_summary(s, summary)
    assert s.exists()
    assert json.loads(s.read_text(encoding="utf-8")) == summary
    # notifier got info messages
    assert any(m[0] == "info" for m in notifier.msgs)


def test_output_write_and_copy(tmp_path):
    # create context
    scope = tmp_path / "scope"
    scope.mkdir()
    work = tmp_path
    ctx = FlowContext(scope=scope, workdir=work, case_id="CASE-1")
    ctx.case_dir = work

    sha = "deadbeef"
    t = write_text_artifact(ctx, sha, "hello.txt", "hello world")
    assert t.exists()
    assert t.read_text(encoding="utf-8") == "hello world"

    b = write_binary_artifact(ctx, sha, "bin.bin", b"\x01\x02")
    assert b.exists()
    assert b.read_bytes() == b"\x01\x02"

    src = tmp_path / "src.txt"
    src.write_text("copy me", encoding="utf-8")
    dest = copy_to_output(ctx, sha, src, name="copied.txt")
    assert dest is not None
    assert dest.exists()
    assert dest.read_text(encoding="utf-8") == "copy me"

    # sanitize
    assert sanitize_name("weird:/name??.py") != "weird:/name??.py"
