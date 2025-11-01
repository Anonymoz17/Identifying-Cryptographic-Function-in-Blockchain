from auditor.intake import estimate_disk_usage


def test_estimate_disk_usage_basic(tmp_path):
    # create a small tree: three files in two folders
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    f1 = a / "one.txt"
    f2 = a / "two.bin"
    f3 = b / "three.log"
    f1.write_text("hello")
    f2.write_bytes(b"x" * 1024)
    f3.write_text("zzz")

    res = estimate_disk_usage([str(tmp_path)], sample_limit=10)
    assert isinstance(res, dict)
    assert res.get("sampled_files", 0) >= 1
    assert res.get("sampled_bytes", 0) >= 0
    # top_dirs should include 'a' and/or 'b'
    td = res.get("top_dirs", {})
    assert isinstance(td, dict)
    # top_dirs should capture at least one folder seen in the sample
    assert len(td) >= 1
