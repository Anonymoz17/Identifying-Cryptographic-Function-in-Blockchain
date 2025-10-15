# auditor/evidence.py
"""Create a deterministic evidence pack (zip) for an engagement.

Produces a zip with lexicographically sorted relative paths and an
evidence_manifest.json listing included files and their SHA-256 digests.
Also writes a '<zip>.sha256' sidecar containing the digest of the zip.
"""
from __future__ import annotations

from pathlib import Path
import json
import hashlib
import zipfile
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional, Any


def _sha256_file(path: Path, chunk_size: int = 8192) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def collect_case_files(root: Path, include_preproc_inputs: bool = True) -> List[Path]:
    """Collect common case files under `root` for inclusion in an evidence pack.

    Looks for:
    - engagement.json
    - policy.baseline.json
    - inputs.manifest.json
    - preproc.index.jsonl
    - all preproc/<sha>/input.bin (if include_preproc_inputs)
    - auditlog.ndjson

    Returns a (possibly empty) list of absolute Paths.
    """
    root = Path(root).resolve()
    out: List[Path] = []

    # basic well-known files
    candidates = [
        root / 'engagement.json',
        root / 'policy.baseline.json',
        root / 'inputs.manifest.json',
        root / 'preproc.index.jsonl',
        root / 'auditlog.ndjson',
    ]
    for c in candidates:
        if c.exists():
            out.append(c.resolve())

    # preproc inputs
    preproc_dir = root / 'preproc'
    if include_preproc_inputs and preproc_dir.exists() and preproc_dir.is_dir():
        for child in sorted(preproc_dir.iterdir()):
            # include input.bin if present
            inp = child / 'input.bin'
            if inp.exists():
                out.append(inp.resolve())
            # also include metadata.json if present
            meta = child / 'metadata.json'
            if meta.exists():
                out.append(meta.resolve())

    # de-duplicate while preserving order
    seen = set()
    unique: List[Path] = []
    for p in out:
        if str(p) not in seen:
            seen.add(str(p))
            unique.append(p)
    return unique


def build_evidence_pack(root: Path, case_id: str, files: Optional[List[Path]] = None, out_dir: Path | None = None) -> Tuple[Path, str]:
    """
    Build a deterministic zip containing the provided files.

    - root: base directory that determines relative paths inside the zip
    - case_id: used in the zip filename
    - files: list of absolute Paths to include (must exist). If None, we attempt to auto-collect common case files under `root`.
    - out_dir: directory to write the zip (defaults to <root>/evidence)

    Returns (zip_path, sha256_hex)
    """
    root = Path(root).resolve()
    out_dir = Path(out_dir) if out_dir is not None else (root / 'evidence')
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    zip_name = f"evidence_pack_{case_id}_{ts}.zip"
    zip_path = out_dir / zip_name

    # If files is None or empty, auto-collect common case artifacts
    if not files:
        files = collect_case_files(root)

    # Build manifest entries (relative path -> sha256)
    manifest: Dict[str, Any] = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'case_id': case_id,
        'files': [],
    }

    # Normalize and filter existing files; store relative paths
    rel_entries: List[Tuple[str, Path, str]] = []
    for p in files:
        p = Path(p).resolve()
        if not p.exists():
            continue
        # compute relative path if inside root; else use basename
        try:
            rel = str(p.relative_to(root))
        except Exception:
            rel = p.name
        sha = _sha256_file(p)
        rel_entries.append((rel.replace('\\', '/'), p, sha))

    # sort by relative path lexicographically
    rel_entries.sort(key=lambda x: x[0])

    # create zip deterministically
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel, p, sha in rel_entries:
            # write file into zip with stored relative path
            zf.write(p, arcname=rel)
            manifest['files'].append({'path': rel, 'sha256': sha, 'size': p.stat().st_size})

        # finally add the manifest inside the zip
        manifest_bytes = json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=2).encode('utf-8')
        zf.writestr('evidence_manifest.json', manifest_bytes)

    # compute zip sha256
    zip_sha = _sha256_file(zip_path)
    (zip_path.with_suffix(zip_path.suffix + '.sha256')).write_text(zip_sha, encoding='utf-8')

    return zip_path, zip_sha
