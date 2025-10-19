# Preprocessing Specification

This document defines the concrete preprocessing outputs, layout and manifest fields expected by downstream detectors.

Date: 2025-10-18

## Goals

- Produce per-file canonical artifacts under the case workspace.
- Create a streaming-friendly manifest `inputs.manifest.ndjson` and a complementary `preproc.index.jsonl` for quick lookups.
- Provide hooks and directories for AST caches and disassembly caches.

## Workspace layout (created under case workspace root)

- `inputs.manifest.ndjson` (NDJSON): manifest records, one per logical input (including extracted files)
- `preproc.index.jsonl` (NDJSON): index of preprocessing operations, one line per input processed
- `preproc/`:
  - `<sha>/`
    - `input.bin` (canonical copy)
    - `metadata.json` (the manifest record for this sha)
- `extracted/`:
  - `<sha>/` (extracted contents of archive with same sha)
  - Notes: extracted files are placed under `extracted/<sha>/` where `<sha>` is
    the sha256 of the original input archive. Each extracted file is also
    represented as a manifest record with `origin` set to
    `extracted:<parent-archive-filename>`.
  - Extraction options:
    - `preserve_permissions` (default: true): when True, attempt to preserve
      Unix permission bits for members (ZIP external attributes or tar mode).
    - `move_extracted` (default: false): when True, extracted files are moved
      from a temporary extraction location into the `extracted/<sha>/` tree and
      intermediate files are removed where possible. This can reduce disk
      duplication when callers only need the extracted contents.
- `artifacts/ast/`:
  - `<sha>.json` (tree-sitter AST cache)
- `artifacts/disasm/`:
  - `<sha>.json` (capstone or other light disassembly cache)
- `artifacts/ghidra_inputs/`:
  - `<sha>/` (files prepared for ghidra_headless)
- `auditlog.ndjson`

## Manifest record (NDJSON line)

Each line is a JSON object with the following fields (see `schemas/manifest.schema.json`):

- id: string (sha256 hex)
- path: absolute original path
- relpath: relative path under the case workspace or extracted path
- size: integer
- mtime: integer (epoch seconds) or ISO8601 string [accept both, prefer epoch for schema]
- sha256: string
- mime: string
- language: string (detected language or 'unknown')
- is_binary: boolean
- origin: string (e.g. `local`, or `extracted:archive.zip`)
- extra: object optional for detector-specific hints (eg, `arch`, `endianness`)

Example line:

{"id":"f3b...","path":"C:/repo/contract.sol","relpath":"inputs/contract.sol","size":5432,"mtime":1697640000,"sha256":"f3b...","mime":"text/x-solidity","language":"solidity","is_binary":false,"origin":"local"}

## Index record (preproc.index.jsonl)

The index provides quick metadata useful for UI progress and detectors. Fields include:

- manifest_id
- input_path
- relpath
- sha256
- size
- mime
- language
- is_binary
- artifact_dir
- ts (ISO8601)

## Extraction rules

- Try `shutil.unpack_archive` first.
- Fallback to tarfile/zipfile detection.
- Extract into `extracted/<sha>/` and add each extracted file as a manifest record with `origin` set to `extracted:<parent-archive-filename>`.
- Support nested extraction up to a configurable depth (default 2).

## AST / Disasm hooks

- `preproc.build_ast_cache(shas)` should accept a list of manifest ids and persist JSON AST under `artifacts/ast/<sha>.json`.
- `preproc.build_disasm_cache(shas)` should create `artifacts/disasm/<sha>.json`.
- Implementations may be no-op until detectors are wired.

## Error handling

- Errors for individual files are recorded in the index/manifest `extra.error` and processing continues.
- Fatal workspace creation errors should be returned to the caller and surfaced to UI.

## Caching

- Per-case caching under `case_dir/.cache/`.
- Optionally reuse global cache under `uploads/.cache/` when enabled.

## Notes

- NDJSON is preferred for manifests to allow streaming ingestion for large cases.
- For reproducibility, artifact dirs are deterministic per sha.

**_ End of spec _**
