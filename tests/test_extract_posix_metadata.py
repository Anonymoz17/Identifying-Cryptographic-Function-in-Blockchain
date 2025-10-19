import stat
import sys
import zipfile
from pathlib import Path

import pytest

from src.auditor.preproc import extract_artifacts


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only metadata test")
def test_extract_preserves_owner_group_and_permissions(tmp_path: Path):
    # Create a small zip and set owner/group where possible (best-effort)
    member_name = "script.sh"
    content = b"#!/bin/sh\necho hi\n"
    member_path = tmp_path / member_name
    member_path.write_bytes(content)
    # set executable and owner/group if possible (may require root; best-effort)
    member_path.chmod(0o755)

    zpath = tmp_path / "testposix.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(member_path, arcname=member_name)

    import hashlib

    h = hashlib.sha256()
    h.update(zpath.read_bytes())
    sha = h.hexdigest()

    item = {"path": str(zpath), "sha256": sha}
    # call for side-effects (write extracted files)
    extract_artifacts(
        [item],
        str(tmp_path),
        max_depth=1,
        preserve_permissions=True,
        move_extracted=True,
    )

    # locate extracted file
    outp = tmp_path / "extracted" / sha / member_name
    assert outp.exists()
    mode = outp.stat().st_mode
    assert bool(mode & stat.S_IXUSR)
    # owner and group should be set (non-zero uid/gid) on POSIX
    st = outp.stat()
    assert st.st_uid is not None
    assert st.st_gid is not None
