import io
import tarfile
import zipfile
from pathlib import Path

from src.auditor.preproc import extract_artifacts


def _make_zip_with_unsafe(tmp_path: Path):
    z = tmp_path / "bad.zip"
    member_good = "good.txt"
    member_bad = "../evil.txt"
    (tmp_path / "good.txt").write_text("hello")
    (tmp_path / "evil.txt").write_text("pwned")
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(tmp_path / "good.txt", arcname=member_good)
        # zipfile allows adding entries with ../ in name
        zf.writestr(member_bad, "should-not-extract")
    return z


def _make_tar_with_unsafe(tmp_path: Path):
    t = tmp_path / "bad.tar"
    good = tmp_path / "good2.txt"
    good.write_text("ok")
    # create a tar with an absolute and ../ member
    with tarfile.open(t, "w") as tf:
        tf.add(str(good), arcname="good2.txt")
        # add a TarInfo with unsafe name
        ti = tarfile.TarInfo(name="../traverse.txt")
        data = b"nope"
        ti.size = len(data)
        tf.addfile(ti, fileobj=io.BytesIO(data))
    return t


def test_zip_slip_skipped(tmp_path: Path):
    z = _make_zip_with_unsafe(tmp_path)
    import hashlib

    h = hashlib.sha256()
    h.update(z.read_bytes())
    sha = h.hexdigest()

    _ = extract_artifacts([{"path": str(z), "sha256": sha}], str(tmp_path), max_depth=1)
    # only good.txt should be present somewhere under extracted dir
    extracted_dir = tmp_path / "extracted" / sha
    found = list(extracted_dir.rglob("good.txt"))
    assert found, f"good.txt not found under {extracted_dir!s}"
    # the traversal file should not be written outside extraction dir
    assert not (tmp_path.parent / "traverse.txt").exists()


def test_tar_slip_skipped(tmp_path: Path):
    t = _make_tar_with_unsafe(tmp_path)
    import hashlib

    h = hashlib.sha256()
    h.update(t.read_bytes())
    sha = h.hexdigest()

    _ = extract_artifacts([{"path": str(t), "sha256": sha}], str(tmp_path), max_depth=1)
    extracted_dir = tmp_path / "extracted" / sha
    found = list(extracted_dir.rglob("good2.txt"))
    assert found, f"good2.txt not found under {extracted_dir!s}"
    # ../traverse.txt should not be created in parent dir
    assert not (tmp_path.parent / "traverse.txt").exists()
