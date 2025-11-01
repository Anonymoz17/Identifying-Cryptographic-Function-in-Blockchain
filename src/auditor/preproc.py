"""auditor.preproc

Minimal preprocessing scaffold (stage 2).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import mimetypes
import shutil
import tarfile
import threading
import traceback
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


def _atomic_write(path: Path, data: str) -> None:
    """Write data to a temporary file and rename into place.

    This avoids partial writes when multiple processes/threads are involved.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)


def _detect_binary_metadata(
    path: Path,
) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str]]:
    """Return (format, arch, bitness, endianness) for known binaries or (None, None, None, None)."""
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except Exception:
        return None, None, None, None
    # ELF
    if head.startswith(b"\x7fELF"):
        e_ident = head[0:16]
        ei_class = e_ident[4]
        ei_data = e_ident[5]
        bitness = 64 if ei_class == 2 else 32
        endianness = "little" if ei_data == 1 else "big"
        try:
            e_machine = head[18:20]
            if endianness == "little":
                mach = int.from_bytes(e_machine, "little")
            else:
                mach = int.from_bytes(e_machine, "big")
            arch = {3: "x86", 62: "x86_64", 40: "arm", 183: "aarch64"}.get(
                mach, "unknown"
            )
        except Exception:
            arch = "unknown"
        return "elf", arch, bitness, endianness
    # PE (MZ)
    if head.startswith(b"MZ"):
        try:
            with open(path, "rb") as f:
                f.seek(0x3C)
                e_lfanew = int.from_bytes(f.read(4), "little")
                f.seek(e_lfanew + 4)
                mach = int.from_bytes(f.read(2), "little")
                arch = {0x014C: "x86", 0x8664: "x86_64", 0x01C0: "arm"}.get(
                    mach, "unknown"
                )
                bitness = 64 if mach == 0x8664 else 32
                return "pe", arch, bitness, "little"
        except Exception:
            return "pe", None, None, None
    # Mach-O magic values
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return "macho", None, None, None
    # WASM
    if head[:4] == b"\x00asm":
        return "wasm", "wasm", None, None
    return None, None, None, None


def preprocess_items(
    items: Union[List[Dict[str, Any]], Iterable[Dict[str, Any]]],
    workdir: str,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    cancel_event: Optional[threading.Event] = None,
    max_extract_depth: int = 2,
    do_extract: bool = True,
    build_ast: bool = False,
    build_disasm: bool = False,
    preserve_permissions: bool = True,
    move_extracted: bool = False,
    stream: bool = False,
    resume: bool = False,
    compute_sha: bool = True,
    copy_inputs: bool = True,
) -> Dict[str, Any]:  # noqa: C901 (complexity; split into helpers later)
    """Process items and write per-file artifacts.

    Supports a streaming mode when `stream=True` where manifest lines are
    written incrementally to a temporary ndjson file (flushed after each write)
    so downstream consumers and the UI can observe progress without buffering
    the entire manifest in memory.

    progress_cb, if provided, will be called as progress_cb(processed_count, total)
    after each item is completed. If cancel_event is set the function will stop
    early and return the index entries created up to that point.

    Returns a dict with keys:
    - index: list of index entries written to preproc.index.jsonl
    - manifest_path: path to inputs.manifest.ndjson (or None on failure)
    - stats: summary stats
    """

    wd = Path(workdir)
    preproc_dir = wd / "preproc"
    preproc_dir.mkdir(parents=True, exist_ok=True)
    index_path = wd / "preproc.index.jsonl"
    index_entries: List[Dict[str, Any]] = []
    manifest_entries: List[Dict[str, Any]] = []

    manifest_path = wd / "inputs.manifest.ndjson"
    tmp_manifest = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
    manifest_writer = None
    if stream:
        try:
            manifest_writer = tmp_manifest.open("w", encoding="utf-8")
        except Exception:
            manifest_writer = None

    # support iterators: try to determine total when possible
    try:
        total = len(items)  # type: ignore[arg-type]
    except Exception:
        total = None

    processed = 0

    # build resume set from existing index/dirs when requested
    processed_shas_set = set()
    if resume:
        try:
            # read existing index entries
            if index_path.exists():
                try:
                    with index_path.open("r", encoding="utf-8") as f:
                        for ln in f:
                            try:
                                obj = json.loads(ln)
                                mid = obj.get("manifest_id") or obj.get("sha256")
                                if mid:
                                    processed_shas_set.add(mid)
                            except Exception:
                                continue
                except Exception:
                    pass
            # also include any existing directories under preproc/
            try:
                if preproc_dir.exists():
                    for d in preproc_dir.iterdir():
                        if d.is_dir():
                            processed_shas_set.add(d.name)
            except Exception:
                pass
        except Exception:
            processed_shas_set = set()

    # iterate over items (items may be an iterator)
    for it in items:  # type: ignore
        if cancel_event is not None and cancel_event.is_set():
            break

        sha = it.get("sha256")
        src = it.get("path")
        src_path = Path(src) if src else None
        # If sha256 not provided and hashing is enabled, try to compute it
        if not sha and src_path and src_path.exists() and compute_sha:
            try:
                h = hashlib.sha256()
                with open(src_path, "rb") as fh:
                    while True:
                        b = fh.read(8192)
                        if not b:
                            break
                        h.update(b)
                sha = h.hexdigest()
                # populate into item for consumers
                it["sha256"] = sha
            except Exception:
                sha = None

        if not sha:
            processed += 1
            if callable(progress_cb):
                try:
                    progress_cb(processed, total)
                except Exception:
                    pass
            continue

        # if resuming and this sha was already processed, skip
        if resume and sha in processed_shas_set:
            processed += 1
            if callable(progress_cb):
                try:
                    progress_cb(processed, total)
                except Exception:
                    pass
            continue

        # deterministic artifact dir per sha
        art_dir = preproc_dir / sha
        art_dir.mkdir(parents=True, exist_ok=True)
        if not src or not src_path.exists():
            # create artifact dir and metadata indicating missing source
            try:
                art_dir.mkdir(parents=True, exist_ok=True)
                meta = {
                    "id": sha,
                    "path": str(Path(src).resolve()) if src else "",
                    "relpath": art_dir.relative_to(wd).as_posix(),
                    "sha256": sha,
                    "size": it.get("size"),
                    "mtime": None,
                    "mtime_epoch": None,
                    "mime": "application/octet-stream",
                    "language": "unknown",
                    "is_binary": False,
                    "origin": "local",
                    "artifact_dir": art_dir.relative_to(wd).as_posix(),
                    "generated_at": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                    "extra": {"error": "source_missing"},
                }
                try:
                    _atomic_write(
                        art_dir / "metadata.json",
                        json.dumps(meta, sort_keys=True, indent=2),
                    )
                except Exception:
                    pass
                idx = {
                    "manifest_id": sha,
                    "input_path": str(Path(src).resolve()) if src else "",
                    "relpath": art_dir.relative_to(wd).as_posix(),
                    "sha256": sha,
                    "size": it.get("size"),
                    "mime": meta.get("mime"),
                    "language": meta.get("language"),
                    "is_binary": meta.get("is_binary"),
                    "artifact_dir": art_dir.relative_to(wd).as_posix(),
                    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "error": "source_missing",
                }
                index_entries.append(idx)
                # write manifest entry immediately in stream mode
                if stream and manifest_writer is not None:
                    try:
                        manifest_writer.write(
                            json.dumps(meta, sort_keys=True, ensure_ascii=False) + "\n"
                        )
                        manifest_writer.flush()
                    except Exception:
                        pass
                else:
                    manifest_entries.append(meta)
                try:
                    with index_path.open("a", encoding="utf-8") as f:
                        f.write(
                            json.dumps(idx, sort_keys=True, ensure_ascii=False) + "\n"
                        )
                except Exception:
                    pass
            except Exception:
                pass

            processed += 1
            if callable(progress_cb):
                try:
                    progress_cb(processed, total)
                except Exception:
                    pass
            continue

        # copy the original file as input.bin if requested (may be disabled
        # for fast scan to avoid duplicating large scopes)
        dst_input = art_dir / "input.bin"
        try:
            if copy_inputs:
                if not dst_input.exists():
                    shutil.copy2(str(src), str(dst_input))
        except Exception:
            # skip on copy failure; continue to write metadata
            pass

        # also prepare a Ghidra-friendly inputs dir under artifacts/ghidra_inputs/<sha>/
        # this gives a canonical place for headless Ghidra runners to look
        try:
            # only prepare Ghidra-friendly inputs if we copied inputs
            if copy_inputs:
                gh_in_root = Path(workdir) / "artifacts" / "ghidra_inputs" / sha
                gh_in_root.mkdir(parents=True, exist_ok=True)
                gh_input = gh_in_root / "input.bin"
                try:
                    # copy the canonical input.bin into ghidra_inputs if not present
                    if not gh_input.exists() and dst_input.exists():
                        shutil.copy2(str(dst_input), str(gh_input))
                except Exception:
                    pass
            # write minimal metadata so headless runners have context
            try:
                gh_meta = {
                    "id": sha,
                    "input": str(dst_input.resolve()) if dst_input.exists() else "",
                    "artifact_dir": gh_in_root.relative_to(Path(workdir)).as_posix(),
                    "generated_at": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                }
                try:
                    _atomic_write(
                        gh_in_root / "metadata.json",
                        json.dumps(gh_meta, sort_keys=True, indent=2),
                    )
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass

        # attempt extraction for archives using helper; extracted files will be
        # placed under workdir/extracted/<sha>/ and added to manifest_entries.
        if do_extract:
            try:
                try:
                    extracted_records = extract_artifacts(
                        [it],
                        str(wd),
                        max_depth=max_extract_depth,
                        preserve_permissions=preserve_permissions,
                        move_extracted=move_extracted,
                    )
                    # write/collect extracted records
                    if stream and manifest_writer is not None:
                        try:
                            for mrec in extracted_records:
                                manifest_writer.write(
                                    json.dumps(mrec, sort_keys=True, ensure_ascii=False)
                                    + "\n"
                                )
                            manifest_writer.flush()
                        except Exception:
                            pass
                    else:
                        manifest_entries.extend(extracted_records)
                except Exception:
                    # top-level safeguard: do not stop preprocessing on extraction failure
                    pass
            except Exception:
                pass

        # normalize mtime: produce both an ISO8601 string for metadata.json
        # (backwards-compatibility for callers/tests) and an epoch integer for
        # the manifest NDJSON lines.
        raw_mtime = it.get("mtime")
        mtime_epoch: Optional[int] = None
        mtime_iso: Optional[str] = None
        if isinstance(raw_mtime, (int, float)):
            try:
                mtime_epoch = int(float(raw_mtime))
                mtime_iso = datetime.datetime.fromtimestamp(
                    float(raw_mtime), datetime.timezone.utc
                ).isoformat()
            except Exception:
                mtime_epoch = None
                mtime_iso = None
        elif isinstance(raw_mtime, str):
            # try parsing ISO8601 to epoch
            try:
                dt = datetime.datetime.fromisoformat(raw_mtime)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                mtime_epoch = int(dt.timestamp())
                mtime_iso = dt.isoformat()
            except Exception:
                # keep the raw string in ISO if parse failed
                mtime_iso = raw_mtime
                mtime_epoch = None
        else:
            mtime_epoch = None
            mtime_iso = None

        # do some lightweight file type / language detection
        def _is_binary(path: Path, blocksize: int = 4096) -> bool:
            try:
                with open(path, "rb") as f:
                    chunk = f.read(blocksize)
                    return b"\x00" in chunk
            except Exception:
                return False

        def _detect_mime_and_lang(path: Path) -> Tuple[str, str]:
            # mime guess by extension first
            mime, _ = mimetypes.guess_type(str(path))
            if mime is None:
                mime = "application/octet-stream" if _is_binary(path) else "text/plain"
            ext = path.suffix.lower()
            lang_map = {
                ".sol": "solidity",
                ".c": "c",
                ".cpp": "cpp",
                ".cc": "cpp",
                ".h": "c",
                ".hpp": "cpp",
                ".go": "go",
                ".py": "python",
                ".js": "javascript",
                ".ts": "typescript",
                ".rs": "rust",
                ".wasm": "wasm",
                ".bin": "evm",
                ".elf": "elf",
            }
            lang = lang_map.get(ext, "binary" if _is_binary(path) else "unknown")
            # special-case by magic for common binaries
            try:
                with open(path, "rb") as f:
                    head = f.read(4)
                    if head.startswith(b"\x7fELF"):
                        mime = "application/x-elf"
                        lang = "elf"
                    elif head.startswith(b"MZ"):
                        mime = "application/x-dosexec"
                        lang = "pe"
                    elif head[:4] in (
                        b"\xca\xfe\xba\xbe",
                        b"\xfe\xed\xfa\xce",
                        b"\xfe\xed\xfa\xcf",
                    ):
                        # many mach-o magic variants; best-effort
                        mime = "application/x-mach-binary"
                        lang = "macho"
            except Exception:
                pass
            return mime, lang

        pass

        mime, language = (None, None)
        try:
            mime, language = _detect_mime_and_lang(Path(src))
        except Exception:
            mime, language = (None, None)

        # detect binary metadata
        binary_format, arch, bitness, endianness = _detect_binary_metadata(Path(src))

        meta = {
            "id": sha,
            "path": str(Path(src).resolve()),
            "relpath": art_dir.relative_to(wd).as_posix(),
            "sha256": sha,
            "size": it.get("size"),
            # keep ISO string in metadata.json for compatibility
            "mtime": mtime_iso,
            "mime": mime or "application/octet-stream",
            "language": language or "unknown",
            "is_binary": bool(language in ("binary", "elf", "pe", "macho", "wasm"))
            or (binary_format is not None),
            "binary_format": binary_format,
            "arch": arch,
            "bitness": bitness,
            "endianness": endianness,
            "origin": "local",
            "artifact_dir": art_dir.relative_to(wd).as_posix(),
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        meta_path = art_dir / "metadata.json"
        try:
            _atomic_write(meta_path, json.dumps(meta, sort_keys=True, indent=2))
        except Exception:
            # best-effort
            pass

        idx = {
            "manifest_id": sha,
            "input_path": str(Path(src).resolve()),
            "relpath": art_dir.relative_to(wd).as_posix(),
            "sha256": sha,
            "size": it.get("size"),
            "mime": meta.get("mime"),
            "language": meta.get("language"),
            "is_binary": meta.get("is_binary"),
            "artifact_dir": art_dir.relative_to(wd).as_posix(),
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        index_entries.append(idx)

        # manifest entry should prefer epoch seconds for mtime to match schema
        manifest_entry = dict(meta)
        # include both ISO and epoch seconds in the manifest for flexibility
        manifest_entry["mtime"] = mtime_iso
        manifest_entry["mtime_epoch"] = mtime_epoch
        if stream and manifest_writer is not None:
            try:
                manifest_writer.write(
                    json.dumps(manifest_entry, sort_keys=True, ensure_ascii=False)
                    + "\n"
                )
                manifest_writer.flush()
            except Exception:
                pass
        else:
            manifest_entries.append(manifest_entry)

        # append to index file (ndjson)
        try:
            with index_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(idx, sort_keys=True, ensure_ascii=False) + "\n")
        except Exception:
            pass

        processed += 1
        if callable(progress_cb):
            try:
                progress_cb(processed, total)
            except Exception:
                pass

    # finish manifest writer if streaming, else write manifest atomically
    try:
        if stream and manifest_writer is not None:
            try:
                manifest_writer.close()
                tmp_manifest.replace(manifest_path)
            except Exception:
                pass
        else:
            manifest_path = wd / "inputs.manifest.ndjson"
            tmp_manifest = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
            with tmp_manifest.open("w", encoding="utf-8") as mf:
                for m in manifest_entries:
                    mf.write(json.dumps(m, sort_keys=True, ensure_ascii=False) + "\n")
            tmp_manifest.replace(manifest_path)
    except Exception:
        # best-effort: don't fail the whole preprocess if manifest write fails
        pass

    # Optionally build AST and disasm caches for processed shas (best-effort)
    try:
        processed_shas = [
            e.get("manifest_id") for e in index_entries if e.get("manifest_id")
        ]
        # dedupe while preserving order
        seen = set()
        unique_shas = [x for x in processed_shas if not (x in seen or seen.add(x))]
        if build_ast and unique_shas:
            try:
                build_ast_cache(unique_shas, str(wd))
            except Exception:
                # do not fail preprocessing on AST build errors
                pass
        if build_disasm and unique_shas:
            try:
                build_disasm_cache(unique_shas, str(wd))
            except Exception:
                pass
    except Exception:
        pass

    # build summary stats
    stats = {
        "total_input_items": total,
        "processed": processed,
        "index_lines": len(index_entries),
        "manifest_lines": len(manifest_entries) if not stream else None,
    }

    return {
        "index": index_entries,
        "manifest_path": str(manifest_path) if "manifest_path" in locals() else None,
        "stats": stats,
    }


def extract_artifacts(
    items: List[Dict[str, Any]],
    outdir: str,
    max_depth: int = 2,
    preserve_permissions: bool = True,
    move_extracted: bool = False,
) -> List[Dict[str, Any]]:
    """Extract archive files from items into outdir/extracted/<sha>/ and return list of extracted items metadata.

    Improvements over the prior implementation:
    - Use magic/header detection to choose extraction strategy when possible.
    - Preserve Unix permission bits for zip members when available.
    - Optional `move_extracted` mode: when True, move extracted files to the
      target location and delete intermediate temp files (best-effort).

    Supports zip and tar-based archives using zipfile/tarfile. This function
    remains best-effort and will not raise on individual extraction failures.
    """
    import os

    wd = Path(outdir)
    logger = logging.getLogger(__name__)
    extracted: List[Dict[str, Any]] = []
    for it in items:
        path = Path(it.get("path"))
        sha = it.get("sha256")
        if not path.exists() or not sha:
            continue
        target_root = wd / "extracted" / sha
        target_root.mkdir(parents=True, exist_ok=True)

        # BFS queue: (file_path, depth, origin_name)
        queue: List[Tuple[Path, int, str]] = [(path, 0, path.name)]
        while queue:
            cur_path, depth, origin = queue.pop(0)
            if depth >= max_depth:
                continue
            targ = target_root / origin
            targ.mkdir(parents=True, exist_ok=True)
            extracted_any = False

            # read header for heuristic detection
            try:
                with open(cur_path, "rb") as fh:
                    head = fh.read(8)
            except Exception:
                head = b""

            # ZIP magic signature
            try:
                if head.startswith(b"PK\x03\x04") or zipfile.is_zipfile(str(cur_path)):
                    try:
                        with zipfile.ZipFile(str(cur_path)) as zf:
                            for zi in zf.infolist():
                                # Skip directories
                                try:
                                    if zi.is_dir():
                                        continue
                                except Exception:
                                    # older ZipInfo may not have is_dir(); fallback
                                    if zi.filename.endswith("/"):
                                        continue

                                # sanitize the member name to avoid zip-slip/path traversal
                                member_name = zi.filename
                                # skip absolute or traversal filenames
                                mp = Path(member_name)
                                if mp.is_absolute() or any(
                                    part == ".." for part in mp.parts
                                ):
                                    # skip unsafe entries
                                    try:
                                        logger.warning(
                                            "skipping unsafe zip member '%s' in %s",
                                            member_name,
                                            str(cur_path),
                                        )
                                    except Exception:
                                        pass
                                    continue

                                dest_path = targ.joinpath(*mp.parts)
                                dest_path_parent = dest_path.parent
                                dest_path_parent.mkdir(parents=True, exist_ok=True)

                                # extract member to the destination path
                                with zf.open(zi, "r") as srcf, open(
                                    dest_path, "wb"
                                ) as dstf:
                                    shutil.copyfileobj(srcf, dstf)

                                # preserve permissions when available
                                if preserve_permissions:
                                    try:
                                        perm = (zi.external_attr >> 16) & 0o777
                                        if perm:
                                            os.chmod(dest_path, perm)
                                    except Exception:
                                        pass

                        extracted_any = True
                    except Exception:
                        extracted_any = False

            except Exception:
                extracted_any = False

            # tarfile (supports gz, bz2, xz compressed tars) fallback
            if not extracted_any:
                try:
                    if tarfile.is_tarfile(str(cur_path)):
                        with tarfile.open(str(cur_path)) as tf:
                            # iterate members and extract safely to avoid path traversal
                            for member in tf.getmembers():
                                mname = member.name
                                mp = Path(mname)
                                # skip absolute or traversal filenames
                                if mp.is_absolute() or any(
                                    part == ".." for part in mp.parts
                                ):
                                    try:
                                        logger.warning(
                                            "skipping unsafe tar member '%s' in %s",
                                            mname,
                                            str(cur_path),
                                        )
                                    except Exception:
                                        pass
                                    continue
                                # only extract regular files and links that have a fileobj
                                if member.isreg() or member.isfile():
                                    try:
                                        fobj = tf.extractfile(member)
                                        if fobj is None:
                                            continue
                                        dest_path = targ.joinpath(*mp.parts)
                                        dest_path.parent.mkdir(
                                            parents=True, exist_ok=True
                                        )
                                        with open(dest_path, "wb") as out_f:
                                            shutil.copyfileobj(fobj, out_f)
                                        # apply permission bits from member.mode if requested
                                        if preserve_permissions and hasattr(
                                            member, "mode"
                                        ):
                                            try:
                                                os.chmod(dest_path, member.mode & 0o777)
                                            except Exception:
                                                pass
                                    except Exception:
                                        # ignore individual member extraction failures
                                        continue
                                else:
                                    # create directory entries as needed
                                    try:
                                        (targ.joinpath(*mp.parts)).mkdir(
                                            parents=True, exist_ok=True
                                        )
                                    except Exception:
                                        pass

                            extracted_any = True
                except Exception:
                    extracted_any = False

            # shutil.unpack_archive as a final fallback (extension based)
            if not extracted_any:
                try:
                    shutil.unpack_archive(str(cur_path), str(targ))
                    extracted_any = True
                except (shutil.ReadError, ValueError):
                    extracted_any = False
                except Exception:
                    extracted_any = False

            if not extracted_any:
                # nothing extracted here; continue
                continue

            # enumerate extracted files and collect metadata
            for p in targ.rglob("**/*"):
                if not p.is_file():
                    continue
                try:
                    with open(p, "rb") as fh:
                        h = hashlib.sha256()
                        while True:
                            b = fh.read(8192)
                            if not b:
                                break
                            h.update(b)
                        sub_sha = h.hexdigest()
                except Exception:
                    sub_sha = None
                try:
                    mtime_iso_sub = datetime.datetime.fromtimestamp(
                        p.stat().st_mtime, datetime.timezone.utc
                    ).isoformat()
                    mtime_epoch_sub = int(p.stat().st_mtime)
                except Exception:
                    mtime_iso_sub = None
                    mtime_epoch_sub = None
                # detect binary metadata for extracted file
                try:
                    b_format, b_arch, b_bitness, b_endianness = _detect_binary_metadata(
                        p
                    )
                except Exception:
                    b_format = None
                    b_arch = None
                    b_bitness = None
                    b_endianness = None
                rec = {
                    "id": sub_sha or "",
                    "path": str(p.resolve()),
                    "relpath": p.relative_to(wd).as_posix(),
                    "size": p.stat().st_size,
                    "mtime": mtime_iso_sub,
                    "mtime_epoch": mtime_epoch_sub,
                    "sha256": sub_sha,
                    "mime": mimetypes.guess_type(str(p))[0]
                    or "application/octet-stream",
                    "language": "unknown",
                    "is_binary": False,
                    "binary_format": b_format,
                    "arch": b_arch,
                    "bitness": b_bitness,
                    "endianness": b_endianness,
                    "origin": f"extracted:{origin}",
                    "artifact_dir": (wd / "extracted" / sha).relative_to(wd).as_posix(),
                    "generated_at": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                }
                extracted.append(rec)
                # if extracted file is itself an archive, enqueue for nested extraction
                try:
                    if zipfile.is_zipfile(str(p)) or tarfile.is_tarfile(str(p)):
                        queue.append((p, depth + 1, p.name))
                except Exception:
                    pass

            # if move_extracted is requested, attempt to move the targ tree to the
            # target_root top-level and remove the archive; keep best-effort semantics
            if move_extracted:
                try:
                    # move each file from targ into target_root (flattening origin)
                    for child in targ.rglob("**/*"):
                        if child.is_file():
                            rel = child.relative_to(targ)
                            dest = target_root / rel
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            shutil.move(str(child), str(dest))
                    # attempt to remove the now-empty targ directory
                    try:
                        targ.rmdir()
                    except Exception:
                        # ignore if not empty; do not raise
                        pass
                except Exception:
                    pass

    return extracted


def build_ast_cache(shas: List[str], workdir: str) -> None:
    """Placeholder to build AST caches for given manifest ids.

    Real implementation should invoke Tree-sitter parsers and write
    JSON AST to `artifacts/ast/<sha>.json` under workdir. This stub is a
    no-op to be implemented later.
    """
    wd = Path(workdir)
    ast_dir = wd / "artifacts" / "ast"
    ast_dir.mkdir(parents=True, exist_ok=True)
    # Try to populate AST caches by scanning preproc/<sha>/input.bin or extracted files.
    # Prefer Tree-sitter when available for Solidity and Go; otherwise fall back
    # to a lightweight regex-based heuristic.
    logger = logging.getLogger(__name__)

    try:
        from tree_sitter import Language, Parser

        have_treesitter = True
    except Exception:
        have_treesitter = False

    ts_langs: Dict[str, object] = {}
    if have_treesitter:
        # try to locate a precompiled languages library; best-effort, fall back
        try:
            # support multiple extensions (.so, .dll, .dylib, .pyd)
            patterns = ["**/tree_sitter_langs.*", "**/tree_sitter_languages.*"]
            candidates = []
            # Limit search to the current workdir (test temporary dirs) to avoid
            # scanning the full repository (node_modules etc) which can be very large
            # and cause tests to hang. If the user has a prebuilt lang lib elsewhere,
            # they should set up the environment accordingly.
            for pat in patterns:
                try:
                    candidates.extend(list(Path(workdir).glob(pat)))
                except Exception:
                    continue
            libpath = None
            for c in candidates:
                if c.is_file():
                    libpath = c
                    break
            if libpath:
                try:
                    # attempt to load a few known language symbols; ignore failures
                    for lname in ("go", "solidity", "javascript", "python"):
                        try:
                            ts_langs[lname] = Language(str(libpath), lname)
                        except Exception:
                            # ignore missing language in the lib
                            continue
                    logger.debug("loaded tree-sitter langs from %s", str(libpath))
                except Exception:
                    logger.debug("failed to load languages from %s", str(libpath))
            else:
                logger.debug("no precompiled tree-sitter langlib found; falling back")
        except Exception:
            ts_langs = {}

    import re

    for s in shas:
        dest = ast_dir / (s + ".json")
        if dest.exists():
            continue
        # locate input file(s) under preproc/<sha>/ and extracted/<sha>/
        candidates = list((Path(workdir) / "preproc" / s).glob("**/*"))
        candidates += list((Path(workdir) / "extracted" / s).glob("**/*"))
        ast_obj = {"sha": s, "ast": None}
        for p in candidates:
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except Exception:
                text = None
            if not text:
                continue

            funcs = []
            # prefer tree-sitter if available for known extensions
            ext = p.suffix.lower()
            lang = None
            if ext in (".sol",) or "solidity" in p.name.lower():
                lang = "solidity"
            elif ext in (".go",) or p.name.endswith(".go"):
                lang = "go"

            parsed_ok = False
            if have_treesitter and lang in ts_langs:
                try:
                    parser = Parser()
                    parser.set_language(ts_langs[lang])
                    tree = parser.parse(bytes(text, "utf8"))
                    # simple traversal: find function_def or function_definition nodes
                    root = tree.root_node
                    for node in root.walk():
                        # tree-sitter python bindings expose node directly
                        n = getattr(node, "node", node)
                        if getattr(n, "type", None) in (
                            "function_definition",
                            "function_declaration",
                            "function_definition_statement",
                        ):
                            # extract name child if present
                            for c in getattr(n, "children", []):
                                if getattr(c, "type", None) in (
                                    "identifier",
                                    "function_name",
                                ):
                                    name = text[c.start_byte : c.end_byte]
                                    funcs.append({"name": name, "lang": lang})
                    parsed_ok = True
                except Exception:
                    logger.debug("tree-sitter parse failed for %s", str(p))
                    parsed_ok = False

            if not parsed_ok:
                # fallback heuristics: solidity: function <name>(, go: func <name>(
                for m in re.finditer(r"function\s+([A-Za-z0-9_]+)", text):
                    funcs.append({"name": m.group(1), "lang": "solidity"})
                for m in re.finditer(r"func\s+([A-Za-z0-9_]+)", text):
                    funcs.append({"name": m.group(1), "lang": "go"})

            if funcs:
                ast_obj["ast"] = {"functions": funcs}
                break
        dest.write_text(json.dumps(ast_obj), encoding="utf-8")


def build_disasm_cache(shas: List[str], workdir: str) -> None:
    """Placeholder to build disassembly caches for given manifest ids.

    Real implementation should invoke Capstone or other disassembly
    tooling and write `artifacts/disasm/<sha>.json`. This stub writes a
    simple placeholder JSON file.
    """
    wd = Path(workdir)
    disasm_dir = wd / "artifacts" / "disasm"
    disasm_dir.mkdir(parents=True, exist_ok=True)
    # Attempt to disassemble binaries using capstone if available, otherwise
    # write a placeholder. We only run a short disassembly to avoid doing
    # heavy work in preprocess.
    logger = logging.getLogger(__name__)
    try:
        import capstone as _capstone

        have_capstone = True
    except Exception:
        _capstone = None
        have_capstone = False

    for s in shas:
        dest = disasm_dir / (s + ".json")
        if dest.exists():
            continue
        # find the input.bin
        bin_path = Path(workdir) / "preproc" / s / "input.bin"
        if not bin_path.exists():
            # fallback placeholder
            dest.write_text(json.dumps({"sha": s, "disasm": None}), encoding="utf-8")
            continue
        if not have_capstone:
            logger.debug("capstone not available, writing placeholder for %s", s)
            dest.write_text(json.dumps({"sha": s, "disasm": None}), encoding="utf-8")
            continue
        # read a small window of bytes to disassemble
        try:
            data = bin_path.read_bytes()[:4096]
            # attempt to pick architecture/mode from binary metadata
            try:
                # we only need arch/bitness and endianness here; ignore format
                _, b_arch, b_bitness, b_endianness = _detect_binary_metadata(bin_path)
            except Exception:
                b_arch = None
                b_bitness = None
                b_endianness = None

            # Attempt to autodetect a base address for PE / Mach-O so we can
            # pass a sensible base to capstone and produce offset mappings.
            base_address = 0
            try:
                with open(bin_path, "rb") as bf:
                    head = bf.read(64)
                    # PE detection: look for DOS header + e_lfanew -> PE header
                    if head.startswith(b"MZ"):
                        try:
                            bf.seek(0x3C)
                            e_lfanew = int.from_bytes(bf.read(4), "little")
                            bf.seek(e_lfanew)
                            sig = bf.read(4)
                            if sig == b"PE\x00\x00":
                                # Optional header starts after PE signature + file header (4 + 20)
                                optional_start = e_lfanew + 4 + 20
                                bf.seek(optional_start)
                                magic = int.from_bytes(bf.read(2), "little")
                                if magic == 0x20B:
                                    # PE32+ ImageBase is 8 bytes at offset 24 from optional start
                                    bf.seek(optional_start + 24)
                                    base_address = int.from_bytes(bf.read(8), "little")
                                else:
                                    # PE32 ImageBase is 4 bytes at offset 28
                                    bf.seek(optional_start + 28)
                                    base_address = int.from_bytes(bf.read(4), "little")
                        except Exception:
                            base_address = 0
                    # Mach-O detection (little-endian variants): try to read first load command vmaddr
                    elif head[:4] in (
                        b"\xca\xfe\xba\xbe",
                        b"\xfe\xed\xfa\xce",
                        b"\xfe\xed\xfa\xcf",
                    ):
                        try:
                            # read ncmds at offset 16 (after magic, cputype, cpusub, filetype)
                            ncmds = int.from_bytes(head[16:20], "little")
                            # header size for 64-bit Mach-O is 32 bytes
                            bf.seek(32)
                            if ncmds >= 1:
                                # read first load command header
                                first8 = bf.read(8)
                                if len(first8) >= 8:
                                    _cmd = int.from_bytes(first8[0:4], "little")
                                    cmdsize = int.from_bytes(first8[4:8], "little")
                                    # read rest of the load command
                                    lc_rest = bf.read(max(0, cmdsize - 8))
                                    # vmaddr is typically at offset 24 from load command start,
                                    # which is index 16 inside lc_rest (since we already consumed 8 bytes)
                                    if len(lc_rest) >= 24:
                                        vmaddr = int.from_bytes(
                                            lc_rest[16:24], "little"
                                        )
                                        base_address = vmaddr or 0
                        except Exception:
                            base_address = 0

            except Exception:
                base_address = 0

            # Map detected arch/bitness to capstone constants (best-effort)
            cs_Cs = getattr(_capstone, "Cs", None)
            arch_const = None
            mode = 0

            # Common arch defaults
            if b_arch in ("x86", "x86_64"):
                arch_const = getattr(_capstone, "CS_ARCH_X86", None)
                if b_bitness == 64:
                    mode = getattr(_capstone, "CS_MODE_64", 0)
                else:
                    mode = getattr(_capstone, "CS_MODE_32", 0)
            elif b_arch in ("arm",):
                arch_const = getattr(_capstone, "CS_ARCH_ARM", None)
                # ARM mode selection: 32-bit ARM vs THUMB
                if b_bitness == 32:
                    mode = getattr(_capstone, "CS_MODE_ARM", 0)
                    # if endianness is little, try to set little-end flag
                    if b_endianness == "little":
                        mode |= getattr(_capstone, "CS_MODE_LITTLE_ENDIAN", 0)
                else:
                    mode = getattr(_capstone, "CS_MODE_ARM", 0)
            elif b_arch in ("aarch64", "arm64"):
                arch_const = getattr(_capstone, "CS_ARCH_ARM64", None)
                # capstone ARM64 modes are often 0 or little-end specific
                mode = getattr(_capstone, "CS_MODE_LITTLE_ENDIAN", 0) or 0
            elif b_arch in ("mips",):
                arch_const = getattr(_capstone, "CS_ARCH_MIPS", None)
                mode = getattr(_capstone, "CS_MODE_MIPS32", 0)
            else:
                # default to x86-64 if available
                arch_const = getattr(_capstone, "CS_ARCH_X86", None)
                mode = getattr(_capstone, "CS_MODE_64", 0)

            if cs_Cs is None or arch_const is None:
                logger.debug(
                    "capstone runtime not usable for %s (arch=%s, bit=%s)",
                    s,
                    b_arch,
                    b_bitness,
                )
                raise RuntimeError("capstone runtime not usable")

            md = cs_Cs(arch_const, mode)
            insns = []
            for i in md.disasm(data, base_address):
                insns.append(
                    {"addr": i.address, "mnemonic": i.mnemonic, "op_str": i.op_str}
                )

            # produce mappings (offset = virtual_addr - base_address)
            mappings = []
            for ins in insns:
                try:
                    addr = int(ins.get("addr") or 0)
                    mappings.append({"addr": addr, "offset": addr - int(base_address)})
                except Exception:
                    continue

            dest.write_text(
                json.dumps(
                    {
                        "sha": s,
                        "disasm": insns,
                        "mappings": mappings,
                        "base_address": int(base_address),
                    }
                ),
                encoding="utf-8",
            )
        except Exception:
            logger.debug("disasm failed for %s: %s", s, traceback.format_exc())
            dest.write_text(json.dumps({"sha": s, "disasm": None}), encoding="utf-8")


if __name__ == "__main__":
    print("preproc module: call preprocess_items(items, workdir)")
