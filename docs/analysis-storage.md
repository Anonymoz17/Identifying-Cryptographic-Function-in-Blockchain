````markdown
# Analysis storage, layout, and conventions

Last updated: 2025-11-06

This document defines the recommended storage layout and conventions for
preprocessing outputs and detector artifacts used by the static-guided
dynamic detection pipeline. It is written to be practical and implementation
friendly: the runner, adapters and detectors should follow these rules so
artifacts are reproducible, auditable and easy to manage.

## Goals

- Keep canonical preprocessing outputs immutable and authoritative.
- Store derived detector artifacts, caches and traces separately under an
  `analysis/` area.
- Provide deterministic paths, simple helpers, and small metadata files
  (`.cache_meta.json`) to enable cache reuse and safe invalidation.
- Support safe concurrent runs (simple locking), atomic writes, and
  configurable retention policies.

## Directory layout (recommended)

Use an `analysis_base` (configurable) and store artifacts under:

- preproc/<file_hash>/
  - input.bin
  - metadata.json
- analysis/static/<file_hash>/
  - preproc/ # derived static preproc artifacts (strings, sections)
  - ghidra-export/ # cached Ghidra export (raw JSON) — optional
  - hints.json # full hints for dynamic harness (internal)
  - hints_public.json # redacted hints safe for public UI
  - static_results.json # packaged static-detection output
  - .cache_meta.json # small provenance + status file
- analysis/dynamic/<file_hash>/
  - dynamic_results.json
  - traces/ # sanitized traces, restricted access
  - .cache_meta.json
- analysis/merged/<file_hash>/
  - final_report.json
  - .cache_meta.json

This layout separates the canonical immutable input (preproc) from
analysis outputs and caches. The runner should accept `analysis_base` as
configuration and derive paths from it.

## File naming and primary identifier

- Primary identifier: `file_hash` — SHA256 of `input.bin` produced by the
  preprocessing stage.
- All output files must include `file_hash` inside their JSON payload and
  the payload must contain a `schema_version` and `generated_at` timestamp.

## `.cache_meta.json` (structure and purpose)

Each analysis folder should contain a `.cache_meta.json` summarizing the
run that produced the artifacts. This file is small and used for cache
validation, provenance and housekeeping.

Minimum recommended fields:

```json
{
  "file_hash": "...",
  "generated_at": "2025-11-06T12:34:56Z",
  "profile": "quick",
  "generator_version": "static-detect/0.1.0",
  "tool_versions": { "ghidra": "10.4.2", "frida": null },
  "status": "success", // success | failed | partial
  "ghidra_export": "ghidra-export/<file_hash>-functions.json",
  "notes": "optional short note"
}
```
````

Use `.cache_meta.json` to decide whether cached artifacts can be reused
when a run is requested. Reuse rules (recommended):

- Reuse if `status == success` AND `profile` and `generator_version` and
  `tool_versions` match the requested run (unless the user passes `--force`).
- If any invariant differs, either invalidate the cache or create a new
  versioned subdirectory (e.g., `v1/`, `v2/`). Simpler: invalidate and
  re-run if mismatch.

## Atomic writes and safe publishing

Writers should avoid partial files being visible to readers. Use a
two-step write:

1. Write to a temporary file in the same directory (e.g. `static_results.json.tmp`).
2. fs.rename / atomic move to final filename (`static_results.json`).

On POSIX and NTFS (same filesystem) a rename is atomic; this ensures
readers never see partially-written JSON.

## Locking and concurrency

Prevent concurrent runs that would stomp caches by using a simple per-<file_hash>
lock. Keep the locking strategy intentionally simple:

- Acquire: create `analysis/.../<file_hash>/.lock` containing `{pid, ts}`.
- If `.lock` exists and the PID is still alive (or timestamp is recent),
  the runner should either wait, fail, or return a message indicating
  the run is in progress.
- If `.lock` exists but is stale (older than a configured TTL), the runner
  may remove it and proceed (careful: detect races).

For robust multi-process coordination use OS-level advisory locks; the
simple file-lock approach above is acceptable for most CI/dev flows.

## Path helper functions (recommended API)

Implement small helpers in the static-detection package so all code uses
consistent paths:

- get_analysis_dir(file_hash, analysis_base, kind='static') -> str
- get_static_preproc_dir(file_hash, analysis_base) -> str
- get_ghidra_export_path(file_hash, analysis_base) -> str
- get_hints_path(file_hash, analysis_base, redact=False) -> str

These helpers keep wiring consistent and make it trivial to switch layouts
later or add cloud-backed URIs.

## Atomic-write helper and lock helper (pseudo-API)

- atomic_write(path, data_bytes): write to tmp + rename
- acquire_lock(path, timeout=None) -> context manager
- release_lock(path)

Keep these helpers small and testable.

## Indexing and discovery

Optionally maintain a small `analysis/index.json` (or lightweight DB) with
an entry per file_hash listing statuses and timestamps. This is helpful
for the UI and for quickly enumerating which analyses are present without
scanning deep directories.

Index schema (example):

```json
{
  "entries": {
    "<file_hash>": {"static": {"ts": "...", "status": "success"}, "dynamic": {...}, "merged": {...}}
  }
}
```

This index must be updated atomically and care taken to avoid contention.
If the index becomes a bottleneck, migrate to a small database (SQLite,
or a service-backed index).

## Retention and pruning

Provide a `prune` utility to clean old artifacts. Common policies:

- Keep `static_results.json` and `hints_public.json` forever (small).
- Prune `ghidra-export/` and `traces/` older than TTL (e.g., 30 days).
- Optionally move very old artifacts to cold/object storage.

Pruning should update `.cache_meta.json` with `status: pruned` or add a
`pruned_at` timestamp so index/clients know data was removed.

## Security & privacy

- Default behavior: do not persist raw buffers or potential secrets. Store
  hashed fingerprints (SHA256), entropy metrics, and sizes instead.
- Place traces and raw exports in restricted directories (`analysis/dynamic/*`)
  and enforce access control in UI/servers.
- Produce redacted `hints_public.json` for free-tier clients which excludes
  addresses and raw snippets.

## Cloud / object storage considerations

For large-scale deployments, store large blobs (ghidra-export, traces)
in object storage (S3) and keep small metadata locally. In that case:

- `analysis/static/<file_hash>/.cache_meta.json` contains URIs to S3 keys.
- The path helpers should return stable URIs when requested (s3://...).
- Provide a pluggable storage adapter (local filesystem or S3) with the
  same minimal API.

## Provenance and schema versioning

- Every artifact must include `schema_version` and `generator_version`.
- When a heuristic or scoring change is deployed, bump `generator_version`
  so old artifacts are still traceable.

## Example: what a runner should do (high level)

1. Acquire lock for file_hash.
2. Load preproc via `preproc_adapter.load_preproc(preproc_dir)`.
3. Check `.cache_meta.json` to decide reuse/force re-run.
4. Generate static preproc if missing (`static_preproc.generate_static_preproc`).
5. Ensure ghidra export exists (or run headless ghidra integration).
6. Run heuristics and scoring.
7. Atomically write `hints.json` and `static_results.json` and update `.cache_meta.json`.
8. Release lock.

## Minimal helpers to implement next

- `get_analysis_dir(file_hash, analysis_base, kind='static')`
- `atomic_write(path, bytes)`
- `acquire_lock(file_hash, analysis_base, timeout=120)` (context manager)
- `read_cache_meta(file_hash, analysis_base)` and `write_cache_meta(...)`

These helpers are low-risk and unlock safe, concurrent runs.

## Next steps for the team

1. Implement the path helpers, atomic write and lock helpers in the
   `auditor.detectors.static_detection` package.
2. Update the runner to use the helpers (atomic writes and lock usage).
3. Add a small pruning utility and optional `analysis/index.json` writer.
4. Implement the pluggable storage adapter (local + S3) if needed later.

---

Document author: pipeline design (adapted for the current repo layout).

```

```
