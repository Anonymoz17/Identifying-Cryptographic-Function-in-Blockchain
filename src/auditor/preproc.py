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
from typing import Any, Callable, Dict, List, Optional, Tuple


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
        # Check for Mach-O magic bytes
        if head[:4] in (b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            return "macho", None, None, None
    # WASM
    if head[:4] == b"\x00asm":
        return "wasm", "wasm", None, None
    return None, None, None, None


def preprocess_items(
    items: List[Dict[str, Any]],
    workdir: str,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    cancel_event: Optional[threading.Event] = None,
    max_extract_depth: int = 2,
    do_extract: bool = True,
    build_ast: bool = False,
    build_disasm: bool = False,
    preserve_permissions: bool = True,
    move_extracted: bool = False,
) -> List[Dict[str, Any]]:  # noqa: C901 (complexity; split into helpers later)
    """Process items and write per-file artifacts.

    progress_cb, if provided, will be called as progress_cb(processed_count, total)
    after each item is completed. If cancel_event is set the function will stop
    early and return the index entries created up to that point.

    Returns list of index entries written to preproc.index.jsonl.
    """

    wd = Path(workdir)
    preproc_dir = wd / "preproc"
    preproc_dir.mkdir(parents=True, exist_ok=True)
    index_path = wd / "preproc.index.jsonl"
    index_entries: List[Dict[str, Any]] = []
    manifest_entries: List[Dict[str, Any]] = []

    total = len(items)
    processed = 0

    # extraction configuration is now passed in as parameter

    for it in items:
        if cancel_event is not None and cancel_event.is_set():
            break

        sha = it.get("sha256")
        src = it.get("path")
        src_path = Path(src) if src else None
        # If sha256 not provided, try to compute it from the source file
        if not sha and src_path and src_path.exists():
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

        # copy the original file as input.bin if not present
        dst_input = art_dir / "input.bin"
        try:
            if not dst_input.exists():
                shutil.copy2(str(src), str(dst_input))
        except Exception:
            # skip on copy failure; continue to write metadata
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
                    # extend manifest entries with the returned records
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

    # write inputs.manifest.ndjson atomically
    try:
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
        "manifest_lines": len(manifest_entries),
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
            for pat in patterns:
                candidates.extend(list(Path(workdir).glob(pat)))
                candidates.extend(list(Path.cwd().glob(pat)))
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
                # capture format, arch, bitness and endianness
                b_format, b_arch, b_bitness, b_endianness = _detect_binary_metadata(
                    bin_path
                )
            except Exception:
                b_format = None
                b_arch = None
                b_bitness = None
                b_endianness = None

            # determine a disassembly base address when possible. Prefer
            # ELF entry point when available, but also attempt to read PE
            # ImageBase and Mach-O segment vmaddrs for non-zero-base binaries.
            base_address = 0
            try:
                if b_format == "elf":
                    with open(bin_path, "rb") as fh:
                        e_ident = fh.read(16)
                        if len(e_ident) >= 6:
                            ei_class = e_ident[4]
                            ei_data = e_ident[5]
                            endian = "little" if ei_data == 1 else "big"
                            # e_entry offset is 24 for both 32-bit and 64-bit ELF
                            fh.seek(24)
                            if ei_class == 1:
                                # 32-bit
                                e_entry = fh.read(4)
                            else:
                                # 64-bit
                                e_entry = fh.read(8)
                            if e_entry:
                                base_address = int.from_bytes(e_entry, endian)
                elif b_format == "pe":
                    # PE: read e_lfanew from DOS header then parse OptionalHeader.ImageBase
                    with open(bin_path, "rb") as fh:
                        # e_lfanew at offset 0x3C (little-endian)
                        fh.seek(0x3C)
                        e_lfanew_bytes = fh.read(4)
                        if len(e_lfanew_bytes) == 4:
                            e_lfanew = int.from_bytes(e_lfanew_bytes, "little")
                            # optional header starts at e_lfanew + 4 (PE signature) + IMAGE_FILE_HEADER (20)
                            optional_header_start = e_lfanew + 4 + 20
                            fh.seek(optional_header_start)
                            magic_bytes = fh.read(2)
                            if len(magic_bytes) == 2:
                                magic = int.from_bytes(magic_bytes, "little")
                                # PE32 (0x10b) has 4-byte ImageBase at offset 28 from optional header
                                # PE32+ (0x20b) has 8-byte ImageBase at offset 24
                                if magic == 0x10B:
                                    imagebase_off = optional_header_start + 28
                                    fh.seek(imagebase_off)
                                    ib = fh.read(4)
                                    if len(ib) == 4:
                                        base_address = int.from_bytes(ib, "little")
                                elif magic == 0x20B:
                                    imagebase_off = optional_header_start + 24
                                    fh.seek(imagebase_off)
                                    ib = fh.read(8)
                                    if len(ib) == 8:
                                        base_address = int.from_bytes(ib, "little")
                            # fallback: if the optional header parsing didn't yield an ImageBase,
                            # try locating the PE signature in the file and parse from there.
                            if base_address == 0:
                                try:
                                    fh.seek(0)
                                    whole = fh.read()
                                    idx = whole.find(b"PE\x00\x00")
                                    if idx != -1:
                                        optional_header_start = idx + 4 + 20
                                        if optional_header_start + 2 < len(whole):
                                            magic = int.from_bytes(
                                                whole[
                                                    optional_header_start : optional_header_start
                                                    + 2
                                                ],
                                                "little",
                                            )
                                            if magic == 0x10B:
                                                off = optional_header_start + 28
                                                if off + 4 <= len(whole):
                                                    base_address = int.from_bytes(
                                                        whole[off : off + 4], "little"
                                                    )
                                            elif magic == 0x20B:
                                                off = optional_header_start + 24
                                                if off + 8 <= len(whole):
                                                    base_address = int.from_bytes(
                                                        whole[off : off + 8], "little"
                                                    )
                                except Exception:
                                    pass
                elif b_format == "macho":
                    # Mach-O: parse header and load commands to find segment vmaddrs.
                    # Best-effort: support 32-bit and 64-bit little-endian variants.
                    with open(bin_path, "rb") as fh:
                        head = fh.read(32)
                        if len(head) >= 4:
                            magic = head[:4]
                            # skip fat binaries (cafebabe)
                            if magic == b"\xca\xfe\xba\xbe":
                                # fat binary: do not attempt complex parsing here
                                pass
                            else:
                                # heuristics: identify 64-bit magic 0xFEEDFACF (little-endian file bytes)
                                is_64 = magic in (
                                    b"\xfe\xed\xfa\xcf",
                                    b"\xcf\xfa\xed\xfe",
                                )
                                # ncmds at offset 16 (both 32/64), sizeofcmds at 20
                                fh.seek(16)
                                ncmds_b = fh.read(4)
                                sizeofcmds_b = fh.read(4)
                                if len(ncmds_b) == 4 and len(sizeofcmds_b) == 4:
                                    try:
                                        ncmds = int.from_bytes(ncmds_b, "little")
                                    except Exception:
                                        ncmds = 0
                                    # load commands begin after header: 32 bytes for 64-bit, 28 for 32-bit
                                    loadoff = 32 if is_64 else 28
                                    vmaddrs = []
                                    cur = loadoff
                                    for _ in range(max(0, ncmds)):
                                        fh.seek(cur)
                                        cmd_b = fh.read(4)
                                        cmdsize_b = fh.read(4)
                                        if len(cmd_b) < 4 or len(cmdsize_b) < 4:
                                            break
                                        cmd = int.from_bytes(cmd_b, "little")
                                        cmdsize = int.from_bytes(cmdsize_b, "little")
                                        # LC_SEGMENT == 0x1, LC_SEGMENT_64 == 0x19
                                        if cmd in (0x1, 0x19):
                                            # vmaddr sits after segname (16 bytes)
                                            vmaddr_off = cur + 8 + 16
                                            fh.seek(vmaddr_off)
                                            if is_64:
                                                vm = fh.read(8)
                                                if len(vm) == 8:
                                                    vmaddrs.append(
                                                        int.from_bytes(vm, "little")
                                                    )
                                            else:
                                                vm = fh.read(4)
                                                if len(vm) == 4:
                                                    vmaddrs.append(
                                                        int.from_bytes(vm, "little")
                                                    )
                                        # advance to next load command
                                        if cmdsize <= 0:
                                            break
                                        cur += cmdsize
                                    # choose the smallest non-zero vmaddr if present
                                    vmaddrs = [
                                        v for v in vmaddrs if v is not None and v != 0
                                    ]
                                    if vmaddrs:
                                        base_address = min(vmaddrs)
            except Exception:
                # best-effort: if anything fails, leave base_address as 0
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
            mappings = []
            for i in md.disasm(data, base_address):
                # record instruction and a mapping entry. Since we disassemble
                # the raw bytes window starting at 0x0, the instruction address
                # corresponds to a byte offset into the input.bin window. We
                # therefore set offset == address here. Consumers can use the
                # mappings array to translate addresses into file offsets.
                insns.append(
                    {"addr": i.address, "mnemonic": i.mnemonic, "op_str": i.op_str}
                )
                try:
                    # compute file offset relative to base_address when numeric
                    off = int(i.address) - int(base_address)
                    mappings.append({"address": i.address, "offset": off})
                except Exception:
                    mappings.append({"address": i.address, "offset": i.address})
            dest.write_text(
                json.dumps(
                    {
                        "sha": s,
                        "disasm": insns,
                        "mappings": mappings,
                        "base_address": base_address,
                    }
                ),
                encoding="utf-8",
            )
        except Exception:
            logger.debug("disasm failed for %s: %s", s, traceback.format_exc())
            dest.write_text(json.dumps({"sha": s, "disasm": None}), encoding="utf-8")


if __name__ == "__main__":
    print("preproc module: call preprocess_items(items, workdir)")
