import json
from pathlib import Path

from auditor.case import Engagement
from settings import get_setting, set_setting


def test_run_settings_written(tmp_path):
    # Prepare known settings
    set_setting("include_globs", "*.py,*.md")
    set_setting("exclude_globs", "tests,docs")
    set_setting("max_file_size_kb", 1)  # 1 KB -> 1024 bytes
    set_setting("do_extract", False)
    set_setting("max_extract_depth", 3)
    set_setting("follow_symlinks", True)

    # create engagement
    eng = Engagement(
        workdir=str(tmp_path), case_id="CASE-TEST", client="tester", scope=str(tmp_path)
    )
    eng.write_metadata()

    # emulate the run_settings write performed by SetupPage._run_engagement_flow
    try:
        inc_txt = get_setting("include_globs", "") or ""
    except Exception:
        inc_txt = ""
    try:
        exc_txt = get_setting("exclude_globs", "") or ""
    except Exception:
        exc_txt = ""
    try:
        msz_kb = int(get_setting("max_file_size_kb", 0) or 0)
    except Exception:
        msz_kb = 0
    try:
        follow_links = bool(get_setting("follow_symlinks", False))
    except Exception:
        follow_links = False

    include_globs = (
        [g.strip() for g in inc_txt.split(",") if g.strip()] if inc_txt else None
    )
    exclude_globs = (
        [g.strip() for g in exc_txt.split(",") if g.strip()] if exc_txt else None
    )
    max_bytes = (msz_kb * 1024) if (msz_kb and msz_kb > 0) else None

    run_settings = {
        "include_globs": include_globs,
        "exclude_globs": exclude_globs,
        "max_file_size_bytes": max_bytes,
        "do_extract": bool(get_setting("do_extract", True)),
        "max_extract_depth": int(get_setting("max_extract_depth", 2)),
        "follow_symlinks": follow_links,
    }

    rs_path = Path(eng.workdir) / "run_settings.json"
    tmp = rs_path.with_suffix(rs_path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(run_settings, sort_keys=True, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tmp.replace(rs_path)

    # assert file exists
    assert rs_path.exists()

    data = json.loads(rs_path.read_text(encoding="utf-8"))
    # check expected keys
    assert set(data.keys()) == {
        "include_globs",
        "exclude_globs",
        "max_file_size_bytes",
        "do_extract",
        "max_extract_depth",
        "follow_symlinks",
    }

    # verify values
    assert data["include_globs"] == ["*.py", "*.md"]
    assert data["exclude_globs"] == ["tests", "docs"]
    assert data["max_file_size_bytes"] == 1024
    assert data["do_extract"] is False
    assert data["max_extract_depth"] == 3
    assert data["follow_symlinks"] is True
