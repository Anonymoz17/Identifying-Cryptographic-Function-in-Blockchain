import threading

from auditor import intake


def make_files(tmp_path, n=50):
    p = tmp_path / "files"
    p.mkdir()
    for i in range(n):
        f = p / f"file_{i}.txt"
        f.write_text(f"{i}\n")
    return p


def test_enumerate_no_hash_count_matches(tmp_path):
    p = make_files(tmp_path, n=50)
    items = intake.enumerate_inputs([str(p)], compute_sha=False)
    assert len(items) == 50
    # ensure items don't have sha256 when compute_sha=False
    assert all("sha256" not in it for it in items)


def test_enumerate_iter_cancel(tmp_path):
    p = make_files(tmp_path, n=200)
    cancel = threading.Event()
    gen = intake.enumerate_inputs_iter([str(p)], compute_sha=False, cancel_event=cancel)
    got = []
    for i, item in enumerate(gen):
        got.append(item)
        if i >= 5:
            # request cancellation after a few items
            cancel.set()
            break
    # consume remainder (should stop quickly)
    remaining = list(gen)
    assert len(got) <= 10
    assert len(remaining) == 0


def test_write_manifest_iter(tmp_path):
    p = tmp_path / "manifest.ndjson"
    items = [{"path": "a", "sha256": "1"}, {"path": "b", "sha256": "2"}]
    intake.write_manifest_iter(str(p), iter(items))
    data = p.read_text().splitlines()
    assert len(data) == 2
    assert '"path": "a"' in data[0]
