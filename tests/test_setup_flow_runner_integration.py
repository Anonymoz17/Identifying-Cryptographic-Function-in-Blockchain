import json
from pathlib import Path

from src.auditor.setup_flow.setupcontext import SetupContext
from src.auditor.setup_flow.progress import ProgressReporter
from src.auditor.setup_flow.runner import run_pipeline


def write_file(p: Path, data: bytes):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def test_run_pipeline_creates_progress_and_preproc(tmp_path):
    # prepare scope with three files, two of which are duplicates
    scope = tmp_path / "scope"
    scope.mkdir()
    a = scope / "a.txt"
    b = scope / "b.txt"
    c = scope / "c.txt"
    write_file(a, b"hello")
    write_file(b, b"hello")
    write_file(c, b"other")

    case_dir = tmp_path / "case"

    ctx = SetupContext(scope=scope, workdir=tmp_path, case_id="case1")
    ctx.case_dir = case_dir
    # allow plain .txt files in this test
    ctx.config.allowed_exts = (".txt",)

    calls = []
    reporter = ProgressReporter(ui_callback=lambda pu: calls.append(pu), file_path=case_dir / "progress.json", throttle_s=0.0)

    # run pipeline (streaming mode). two_phase param is accepted but currently not
    # required by the runner implementation; pass it to exercise the parameter.
    res = run_pipeline(ctx, notifier=None, cancel_event=None, progress_reporter=reporter, pre_count=True, two_phase=True)

    # progress.json persisted
    pjson = case_dir / "progress.json"
    assert pjson.exists()
    pj = json.loads(pjson.read_text())
    assert pj.get("phase") == "preprocessing"

    # dedupe summary written and should indicate 2 processed, 1 duplicate
    ds = case_dir / "dedupe-summary.json"
    assert ds.exists()
    ddata = json.loads(ds.read_text())
    assert ddata.get("processed") == 2
    assert ddata.get("duplicates") == 1

    # preproc artifacts directory should contain two artifact dirs (unique files)
    preproc = case_dir / "preproc"
    assert preproc.exists()
    subdirs = [p for p in preproc.iterdir() if p.is_dir()]
    assert len(subdirs) == 2
