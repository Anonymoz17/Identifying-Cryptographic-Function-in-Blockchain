import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from auditor.detectors.static_detection import cache


def test_write_and_read_cache_meta(tmp_path):
    out = tmp_path / "analysis_dir"
    out.mkdir()
    meta = {"file_hash": "deadbeef", "generated_at": datetime.now(timezone.utc).isoformat(), "profile": "quick", "tool_versions": {"ghidra": "9.2"}}
    path = cache.write_cache_meta(str(out), meta)
    assert os.path.isfile(path)

    read = cache.read_cache_meta(str(out))
    assert read is not None
    assert read.get("file_hash") == "deadbeef"


def test_is_cache_fresh_and_stale():
    now = datetime.now(timezone.utc)
    fresh = {"generated_at": now.isoformat()}
    assert cache.is_cache_fresh(fresh, max_age_seconds=60)

    old = {"generated_at": (now - timedelta(days=10)).isoformat()}
    assert not cache.is_cache_fresh(old, max_age_seconds=60)


class CtxStub:
    def __init__(self, profile="quick", tool_versions=None, force=False):
        self.profile = profile
        self.tool_versions = tool_versions or {}
        self.force = force


def test_is_cache_compatible_and_should_use_cache(tmp_path):
    analysis = tmp_path / "analysis"
    analysis.mkdir()
    static_results = analysis / "static_results.json"
    static_results.write_text("[]")

    now = datetime.now(timezone.utc).isoformat()
    cache_meta = {
        "file_hash": "aaa",
        "generated_at": now,
        "profile": "quick",
        "tool_versions": {"ghidra": "9.2"},
    }
    (analysis / ".cache_meta.json").write_text(json.dumps(cache_meta))

    ctx = CtxStub(profile="quick", tool_versions={"ghidra": "9.2"}, force=False)
    use, reason = cache.should_use_cache(str(analysis), ctx)
    assert use is True
    assert reason == "ok"

    # force should prevent reuse
    ctx_force = CtxStub(profile="quick", tool_versions={"ghidra": "9.2"}, force=True)
    use2, reason2 = cache.should_use_cache(str(analysis), ctx_force)
    assert use2 is False
    assert reason2 == "force_requested"
