"""auditor.preproc

Minimal preprocessing scaffold (stage 2).
"""

from __future__ import annotations

import datetime
import json
import mimetypes
import shutil
import tarfile
import threading
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


def preprocess_items(
    items: List[Dict[str, Any]],
    workdir: str,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    cancel_event: Optional[threading.Event] = None,
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

    for it in items:
        if cancel_event is not None and cancel_event.is_set():
            break

        sha = it.get("sha256")
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

        src = it.get("path")
        if not src or not Path(src).exists():
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
                        b"\xfe\xed\fa\xcf",
                    ):
                        # many mach-o magic variants; best-effort
                        mime = "application/x-mach-binary"
                        lang = "macho"
            except Exception:
                pass
            return mime, lang

        mime, language = (None, None)
        try:
            mime, language = _detect_mime_and_lang(Path(src))
        except Exception:
            mime, language = (None, None)

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
            "is_binary": bool(language in ("binary", "elf", "pe", "macho", "wasm")),
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

    return index_entries


def extract_artifacts(
    items: List[Dict[str, Any]], outdir: str, max_depth: int = 2
) -> List[Dict[str, Any]]:
    """Extract archive files from items into outdir/extracted/<sha>/ and return list of extracted items metadata.

    Supports zip and tar-based archives using shutil.unpack_archive/TarFile/ZipFile.
    """
    wd = Path(outdir)
    extracted = []
    for it in items:
        path = Path(it.get("path"))
        sha = it.get("sha256")
        if not path.exists() or not sha:
            continue
        target = wd / "extracted" / sha
        target.mkdir(parents=True, exist_ok=True)
        # try shutil.unpack_archive (supports many common formats)
        try:
            shutil.unpack_archive(str(path), str(target))
            extracted.append({"origin": str(path), "extracted_to": str(target)})
            continue
        except (shutil.ReadError, ValueError):
            # not a supported archive for shutil
            pass
        # fallback: try tarfile
        try:
            if tarfile.is_tarfile(str(path)):
                with tarfile.open(str(path)) as tf:
                    tf.extractall(path=str(target))
                    extracted.append({"origin": str(path), "extracted_to": str(target)})
                    continue
        except Exception:
            pass
        # fallback: try zipfile
        try:
            if zipfile.is_zipfile(str(path)):
                with zipfile.ZipFile(str(path)) as zf:
                    zf.extractall(path=str(target))
                    extracted.append({"origin": str(path), "extracted_to": str(target)})
                    continue
        except Exception:
            pass
    return extracted


if __name__ == "__main__":
    print("preproc module: call preprocess_items(items, workdir)")
