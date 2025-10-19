import os
import shutil
import stat
import zipfile
from pathlib import Path

from src.auditor.preproc import extract_artifacts


def make_zip_with_perm(tmpdir: Path, member_name: str, content: bytes, perm: int):
    zpath = tmpdir / "test_archive.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        # create a temp file with desired permissions
        member_path = tmpdir / member_name
        member_path.parent.mkdir(parents=True, exist_ok=True)
        member_path.write_bytes(content)
        # set permission on the file
        os.chmod(member_path, perm)
        # write into zip
        zf.write(member_path, arcname=member_name)
    return zpath


def test_extract_move_and_permissions(tmp_path: Path):
    # create an archive with a file that has executable bit set
    member_name = "bin/hello.sh"
    content = b"#!/bin/sh\necho hello\n"
    perm = 0o755
    zpath = make_zip_with_perm(tmp_path, member_name, content, perm)

    item = {"path": str(zpath), "sha256": None}
    # compute sha for the archive so extract_artifacts will use it
    import hashlib

    h = hashlib.sha256()
    h.update(zpath.read_bytes())
    sha = h.hexdigest()
    item["sha256"] = sha

    # run extraction with move_extracted=True and preserve_permissions=True
    extracted = extract_artifacts(
        [item],
        str(tmp_path),
        max_depth=1,
        preserve_permissions=True,
        move_extracted=True,
    )

    # assert extracted entry exists for the inner file
    relpaths = [e["relpath"] for e in extracted]
    assert any(member_name in r for r in relpaths)

    # check that the extracted file exists under extracted/<sha>/ and permissions preserved
    outp = tmp_path / "extracted" / sha / member_name
    assert outp.exists()
    mode = outp.stat().st_mode
    # On Windows the executable bit is not preserved in the same way; only
    # assert the permission on POSIX-like platforms.
    import sys

    if not sys.platform.startswith("win"):
        assert bool(mode & stat.S_IXUSR)  # executable by owner

    # cleanup
    shutil.rmtree(tmp_path / "extracted")
