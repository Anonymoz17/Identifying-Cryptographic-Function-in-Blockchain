"""setup_flow.preproc

Focused preprocessing core for the setup pipeline. This module contains the
streaming `preprocess_items` entrypoint.

This file is a migration target for the older `auditor.preproc` module. It
implements a compact, focused subset of preprocessing functionality used by
the setup pipeline: copy inputs into `preproc/<sha>/`, create per-artifact
`metadata.json`, and write manifest entries via the caller's writer.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import mimetypes
import shutil
import logging
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union
from .setupcontext import SetupContext
from .setupmessages import Notifier
from .persistence import NDJSONBufferedWriter, atomic_write_json



def _detect_binary_metadata(path: Path) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str]]:
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except Exception:
        return None, None, None, None
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
            arch = {3: "x86", 62: "x86_64", 40: "arm", 183: "aarch64"}.get(mach, "unknown")
        except Exception:
            arch = "unknown"
        return "elf", arch, bitness, endianness
    if head.startswith(b"MZ"):
        try:
            with open(path, "rb") as f:
                f.seek(0x3C)
                e_lfanew = int.from_bytes(f.read(4), "little")
                f.seek(e_lfanew + 4)
                mach = int.from_bytes(f.read(2), "little")
                arch = {0x014C: "x86", 0x8664: "x86_64", 0x01C0: "arm"}.get(mach, "unknown")
                bitness = 64 if mach == 0x8664 else 32
                return "pe", arch, bitness, "little"
        except Exception:
            return "pe", None, None, None
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return "macho", None, None, None
    if head[:4] == b"\x00asm":
        return "wasm", "wasm", None, None
    return None, None, None, None


def preprocess_items(
    items: Union[List[Dict[str, Any]], Iterable[Dict[str, Any]]],
    ctx: SetupContext,
    notifier: Optional[Notifier] = None,
    manifest_writer: Optional[NDJSONBufferedWriter] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    cancel_event: Optional[object] = None,
    compute_sha: bool = True,
    copy_inputs: bool = True,
    **kwargs,
) -> Dict[str, Any]:
    """Streaming preprocess core that integrates with SetupContext and Notifier.

        Behavior:
            - prefers ctx.case_dir as working directory
            - writes per-artifact metadata.json into `preproc/<sha>/`
            - when `manifest_writer` is provided, writes manifest lines as NDJSON
                (one object per input) for streaming durability
            - emits notifier.ok() for each successfully handled input

        Notes:
            - This function implements only general, cross-cutting preprocessing
                (enumeration, canonical copy, metadata, manifest/index emission). It
                intentionally does not perform language-specific AST building or
                binary disassembly; such steps should be implemented in separate
                post-preproc stages. Any legacy flags passed in `kwargs` are ignored.
    """
    # prefer ctx.case_dir / preproc if available
    if getattr(ctx, "case_dir", None):
        wd = Path(ctx.case_dir)
    else:
        wd = Path(ctx.workdir)
    preproc_dir = wd / "preproc"
    preproc_dir.mkdir(parents=True, exist_ok=True)

    index_entries: List[Dict[str, Any]] = []
    manifest_entries: List[Dict[str, Any]] = []

    total = None
    try:
        total = len(items)  # type: ignore
    except Exception:
        total = None

    processed = 0

    for it in items:  # type: ignore
        if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
            break

        sha = it.get("sha256")
        src = it.get("path")
        src_path = Path(src) if src else None

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

        art_dir = preproc_dir / sha
        art_dir.mkdir(parents=True, exist_ok=True)

        # copy original input
        dst_input = art_dir / "input.bin"
        try:
            if copy_inputs and src_path and src_path.exists() and not dst_input.exists():
                shutil.copy2(str(src_path), str(dst_input))
        except Exception:
            pass

        # compute mtime
        raw_mtime = it.get("mtime")
        mtime_epoch = None
        mtime_iso = None
        if isinstance(raw_mtime, (int, float)):
            try:
                mtime_epoch = int(float(raw_mtime))
                mtime_iso = datetime.datetime.fromtimestamp(float(raw_mtime), datetime.timezone.utc).isoformat()
            except Exception:
                mtime_epoch = None
                mtime_iso = None
        elif isinstance(raw_mtime, str):
            try:
                dt = datetime.datetime.fromisoformat(raw_mtime)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                mtime_epoch = int(dt.timestamp())
                mtime_iso = dt.isoformat()
            except Exception:
                mtime_iso = raw_mtime
                mtime_epoch = None

        mime, language = (None, None)
        try:
            mime = mimetypes.guess_type(str(src_path))[0]
        except Exception:
            mime = None

        binary_format, arch, bitness, endianness = (None, None, None, None)
        try:
            if src_path and src_path.exists():
                binary_format, arch, bitness, endianness = _detect_binary_metadata(src_path)
        except Exception:
            pass

        meta = {
            "id": sha,
            "path": str(src_path.resolve()) if src_path else "",
            "relpath": art_dir.relative_to(wd).as_posix(),
            "sha256": sha,
            "size": it.get("size"),
            "mtime": mtime_iso,
            "mtime_epoch": mtime_epoch,
            "mime": mime or "application/octet-stream",
            "language": language or "unknown",
            "is_binary": bool(language in ("binary", "elf", "pe", "macho", "wasm")) or (binary_format is not None),
            "binary_format": binary_format,
            "arch": arch,
            "bitness": bitness,
            "endianness": endianness,
            "origin": "local",
            "artifact_dir": art_dir.relative_to(wd).as_posix(),
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        try:
            atomic_write_json(art_dir / "metadata.json", meta)
        except Exception:
            pass

        manifest_entry = dict(meta)
        manifest_entry["mtime_epoch"] = mtime_epoch

        # stream to manifest writer if provided
        if manifest_writer is not None:
            try:
                manifest_writer.write(manifest_entry)
            except Exception:
                pass
        else:
            manifest_entries.append(manifest_entry)

        idx = {
            "manifest_id": sha,
            "input_path": str(src_path.resolve()) if src_path else "",
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

        # notifier hook
        if notifier is not None:
            try:
                notifier.ok(f"preprocessed {src_path}", path=str(src_path))
            except Exception:
                pass

        processed += 1
        if callable(progress_cb):
            try:
                progress_cb(processed, total)
            except Exception:
                pass

    stats = {
        "total_input_items": total,
        "processed": processed,
        "index_lines": len(index_entries),
        "manifest_lines": len(manifest_entries),
    }

    return {"index": index_entries, "manifest_entries": manifest_entries, "stats": stats}
