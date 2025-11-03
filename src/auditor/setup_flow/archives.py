from __future__ import annotations

import os
import shutil
import stat
import tarfile
import zipfile
import uuid
import posixpath
from pathlib import Path
from typing import Dict, Iterator, Optional

from .setupcontext import SetupContext
from .setupmessages import Notifier


def _safe_make_parent(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)


def _is_within_dir(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except Exception:
        return False


def extract_archive(
    archive_path: Path,
    ctx: SetupContext,
    notifier: Optional[Notifier] = None,
    sandbox_parent: Optional[Path] = None,
    max_extract_bytes: Optional[int] = 50 * 1024 * 1024,
    max_members: int = 1000,
    max_member_bytes: Optional[int] = None,
    chunk_size: int = 64 * 1024,
    recursive: bool = False,
) -> Iterator[Dict]:
    """Safely extract an archive into a sandbox and yield extracted file metadata.

    Yields dicts: { 'path': Path, 'relpath': Path, 'size': int, 'parent_archive': str }

    Safety checks:
    - Do not extract if ctx.config.extract_archives is False.
    - Enforce max total extracted bytes and max members.
    - Prevent ZipSlip by checking resolved targets remain under sandbox.
    - Skip symlinks inside archives (warn).
    - Optionally handle nested archives when recursive=True (but default False).
    """
    if notifier is None:
        notifier = Notifier()

    if not getattr(ctx.config, "extract_archives", False):
        notifier.skip("Archive extraction disabled in config", path=str(archive_path))
        return

    if sandbox_parent is None:
        if ctx.case_dir:
            sandbox_parent = ctx.case_dir / "extracts"
        else:
            sandbox_parent = Path(".") / "extracts"

    sandbox_dir = sandbox_parent / uuid.uuid4().hex
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    notifier.info("Extracting archive", path=str(archive_path), details={"sandbox": str(sandbox_dir)})

    total_extracted = 0
    members_extracted = 0

    # Helper to yield after writing file
    def _yield_file(target: Path) -> Dict:
        try:
            size = target.stat().st_size
        except Exception:
            size = 0
        return {"path": target, "relpath": target.relative_to(sandbox_dir), "size": size, "parent_archive": str(archive_path)}

    # Zip archives
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for zi in zf.infolist():
                    if members_extracted >= max_members:
                        notifier.warn("Max archive members reached; stopping extraction", path=str(archive_path), details={"max_members": max_members})
                        break

                    # Normalize member name to avoid odd separators and absolute
                    # paths. Zip uses forward slashes; normalize and strip any
                    # leading slashes or drive letters.
                    name = zi.filename
                    # skip directories
                    if name.endswith("/"):
                        continue
                    try:
                        # normalize posix path, drop leading slashes
                        norm = posixpath.normpath(name)
                        if norm.startswith("/"):
                            norm = norm.lstrip("/")
                        # reject traversal components
                        if norm.split("/") and any(p == ".." for p in norm.split("/")):
                            notifier.warn("Archive member has traversal components; skipping", path=str(archive_path), details={"member": name})
                            continue
                        name = norm
                    except Exception:
                        # conservative: skip if we cannot normalize
                        notifier.warn("Could not normalize archive member name; skipping", path=str(archive_path), details={"member": zi.filename})
                        continue

                    # target path
                    target = sandbox_dir / Path(name)
                    if not _is_within_dir(target, sandbox_dir):
                        notifier.warn("Archive member would extract outside sandbox; skipping", path=str(archive_path), details={"member": name})
                        continue

                    # detect symlink entries in ZIP (Unix external attributes)
                    try:
                        mode = (zi.external_attr >> 16) & 0xFFFF
                        if stat.S_ISLNK(mode):
                            notifier.warn("Archive member is a symlink; skipping", path=str(archive_path), details={"member": name})
                            continue
                    except Exception:
                        # best-effort: if detection fails, continue
                        pass

                    # size check (use uncompressed size when available)
                    member_size = zi.file_size or 0
                    if max_member_bytes is not None and member_size > max_member_bytes:
                        notifier.warn("Archive member exceeds per-member size limit; skipping", path=str(archive_path), details={"member": name, "member_size": member_size, "max_member": max_member_bytes})
                        continue
                    if max_extract_bytes is not None and (total_extracted + member_size) > max_extract_bytes:
                        notifier.warn("Archive extract size limit reached; skipping remaining", path=str(archive_path), details={"max_bytes": max_extract_bytes})
                        break

                    # write the member safely using streaming and enforce byte limits
                    _safe_make_parent(target)
                    written = 0
                    try:
                        with zf.open(zi, "r") as src, open(target, "wb") as dst:
                            while True:
                                chunk = src.read(chunk_size)
                                if not chunk:
                                    break
                                dst.write(chunk)
                                written += len(chunk)
                                # if uncompressed size wasn't provided or lied, stop if we exceed allowed bytes
                                if max_extract_bytes is not None and (total_extracted + written) > max_extract_bytes:
                                    raise ValueError("extracted bytes exceed max_extract_bytes")
                                if max_member_bytes is not None and written > max_member_bytes:
                                    raise ValueError("member exceeds max_member_bytes")
                    except Exception as e:
                        # cleanup partial file
                        try:
                            if target.exists():
                                target.unlink()
                        except Exception:
                            pass
                        notifier.warn("Failed to extract archive member; skipping", path=str(archive_path), details={"member": name, "error": str(e)})
                        continue

                    total_extracted += written
                    members_extracted += 1
                    notifier.ok("Extracted archive member", path=str(target), details={"size": written})
                    yield _yield_file(target)

            notifier.info("Zip extraction complete", path=str(archive_path), details={"members": members_extracted, "bytes": total_extracted})
            return

        # Tar archives
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as tf:
                for member in tf.getmembers():
                    if members_extracted >= max_members:
                        notifier.warn("Max archive members reached; stopping extraction", path=str(archive_path), details={"max_members": max_members})
                        break

                    if member.isdir():
                        continue

                    if member.issym() or member.islnk():
                        notifier.warn("Archive member is a symlink; skipping for safety", path=str(archive_path), details={"member": member.name})
                        continue

                    name = member.name
                    # normalize and reject traversal
                    try:
                        norm = posixpath.normpath(name)
                        if norm.startswith("/"):
                            norm = norm.lstrip("/")
                        if norm.split("/") and any(p == ".." for p in norm.split("/")):
                            notifier.warn("Archive member has traversal components; skipping", path=str(archive_path), details={"member": name})
                            continue
                        name = norm
                    except Exception:
                        notifier.warn("Could not normalize archive member name; skipping", path=str(archive_path), details={"member": name})
                        continue

                    target = sandbox_dir / Path(name)
                    if not _is_within_dir(target, sandbox_dir):
                        notifier.warn("Archive member would extract outside sandbox; skipping", path=str(archive_path), details={"member": name})
                        continue

                    member_size = member.size or 0
                    if max_member_bytes is not None and member_size > max_member_bytes:
                        notifier.warn("Archive member exceeds per-member size limit; skipping", path=str(archive_path), details={"member": name, "member_size": member_size, "max_member": max_member_bytes})
                        continue
                    if max_extract_bytes is not None and (total_extracted + member_size) > max_extract_bytes:
                        notifier.warn("Archive extract size limit reached; skipping remaining", path=str(archive_path), details={"max_bytes": max_extract_bytes})
                        break

                    _safe_make_parent(target)
                    written = 0
                    try:
                        f = tf.extractfile(member)
                        if f is None:
                            notifier.warn("Could not extract member (no file); skipping", path=str(archive_path), details={"member": name})
                            continue
                        with open(target, "wb") as dst:
                            while True:
                                chunk = f.read(chunk_size)
                                if not chunk:
                                    break
                                dst.write(chunk)
                                written += len(chunk)
                                if max_extract_bytes is not None and (total_extracted + written) > max_extract_bytes:
                                    raise ValueError("extracted bytes exceed max_extract_bytes")
                                if max_member_bytes is not None and written > max_member_bytes:
                                    raise ValueError("member exceeds max_member_bytes")
                    except Exception as e:
                        try:
                            if target.exists():
                                target.unlink()
                        except Exception:
                            pass
                        notifier.warn("Failed to extract archive member; skipping", path=str(archive_path), details={"member": name, "error": str(e)})
                        continue

                    total_extracted += written
                    members_extracted += 1
                    notifier.ok("Extracted archive member", path=str(target), details={"size": written})
                    yield _yield_file(target)

            notifier.info("Tar extraction complete", path=str(archive_path), details={"members": members_extracted, "bytes": total_extracted})
            return

    except Exception as e:
        notifier.warn("Archive extraction failed", path=str(archive_path), details={"error": str(e)})

    # If we get here, unsupported archive or nothing extracted
    notifier.skip("Archive type not supported or no members extracted", path=str(archive_path))
