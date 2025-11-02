from pathlib import Path

from auditor.setup_flow.preproc import preprocess_items
from auditor.setup_flow.setupcontext import FlowContext
from auditor.setup_flow.manifest import ManifestWriter


class DummyNotifier:
    def __init__(self):
        self.msgs = []

    def ok(self, text, path=None, details=None):
        self.msgs.append(("ok", text, path, details))


def test_preprocess_items_writes_manifest(tmp_path):
    f = tmp_path / "input.bin"
    f.write_bytes(b"content")
    ctx = FlowContext(scope=tmp_path, workdir=tmp_path, case_id="C1")
    ctx.case_dir = tmp_path
    notifier = DummyNotifier()
    manifest_path = tmp_path / "manifest.ndjson"
    mw = ManifestWriter(manifest_path, flush_every=1, notifier=notifier)

    items = [{"path": str(f), "size": f.stat().st_size}]
    res = preprocess_items(items, ctx, notifier=notifier, manifest_writer=mw)

    # manifest entry written
    mw.flush()
    assert manifest_path.exists()
    lines = manifest_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1

    # metadata.json exists under preproc/<sha>/metadata.json
    meta_dir = (tmp_path / "preproc")
    assert meta_dir.exists()
