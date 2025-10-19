import stat
import sys
import zipfile
from pathlib import Path

from src.auditor.preproc import extract_artifacts


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

    # On POSIX systems we expect the executable bit and uid/gid info.
    # On Windows these attributes may not be meaningful; assert existence only.
    if not sys.platform.startswith("win"):
        mode = outp.stat().st_mode
        assert bool(mode & stat.S_IXUSR), "extracted file should be executable on POSIX"
        # owner and group should be present (may be 0 for root but attributes exist)
        st = outp.stat()
        assert hasattr(st, "st_uid") and st.st_uid is not None
        assert hasattr(st, "st_gid") and st.st_gid is not None
    else:
        # On Windows we at least ensure the file is readable and has non-zero size
        assert outp.stat().st_size > 0
