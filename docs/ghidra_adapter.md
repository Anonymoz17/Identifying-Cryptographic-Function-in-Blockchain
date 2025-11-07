# Ghidra Adapter (design & implementation plan)

This document captures the design, API contract, implementation plan, testing strategy,
and integration notes for the Ghidra headless adapter used by the static detection
pipeline (`src/auditor/detectors/static_detection/ghidra_adapter.py`).

## Purpose

- Run Ghidra headless (`analyzeHeadless`) in an opt-in fashion to export function-level
  metadata (names, addresses, sizes, prototypes, disassembly snippets) that heuristics
  can use to improve detection quality.
- Cache the export and surface a stable `read_ghidra_functions()` API to downstream
  heuristics.
- Be safe and testable: non-fatal when Ghidra is not available; unit-testable via
  mocking of subprocesses.

## Contract (inputs / outputs / error modes)

- Inputs:
  - `preproc_input` (path to `input.bin`)
  - `out_dir` (directory to write exports)
  - `file_hash` (identifier for naming/lookup)
  - `options` dict (keys: `force` bool, `timeout` int, `ghidra_install_dir` optional)
- Outputs:
  - `ensure_ghidra_export(...)` -> returns `export_path` (path to JSON functions file) or `None` if skipped.
  - `read_ghidra_functions(export_path)` -> list[dict] where each dict minimally contains:
    `{name, address, size, prototype, disasm?}`
- Error modes:
  - Missing Ghidra: return None (non-fatal) with a clear log message.
  - Headless process failure: return None and surface stderr in logs; runner may annotate `meta.errors`.
  - Timeout: raise `TimeoutError` (so runner can handle fallback or annotate failure).

## Design & API surface

Minimal public functions (file: `ghidra_adapter.py`):

- `find_analyze_headless(options) -> Optional[str]`

  - Locate Ghidra `analyzeHeadless` executable by checking `options['ghidra_install_dir']`, `GHIDRA_INSTALL_DIR` env var, and PATH.

- `build_headless_cmd(analyze_path, project_dir, script_path, input_path, out_dir, extra_args) -> list[str]`

  - Compose a safe command-line invocation for `analyzeHeadless` to run a small export script.

- `run_headless_export(cmd: list[str], timeout: int) -> (exitcode, stdout, stderr)`

  - Wrapper around `subprocess.run` with timeout, output capture, and clear error mapping.

- `ensure_ghidra_export(preproc_input: str, out_dir: str, file_hash: str, options: dict) -> Optional[str]`

  - High-level entrypoint used by `runner.py`. Checks cache, optionally runs headless export, writes export to `out_dir/<file_hash>-functions.json`, and returns the path or None.

- `read_ghidra_functions(export_path: str) -> list[dict]`
  - Parse the exporter JSON output and normalize it for heuristics.

## Headless exporter script

- The adapter will ship a minimal Ghidra script (Python/Jython) that when executed inside
  `analyzeHeadless` will iterate program functions and write a JSON file with the required fields.
- The script will be small and internally controlled (not loading user-provided scripts) to avoid
  arbitrary code execution.

## How to invoke `analyzeHeadless` with the bundled exporter

When the adapter writes the bundled exporter to `out_dir/ghidra_exporter.py` it will invoke
`analyzeHeadless` with the exporter filename and the intended JSON output path as the final
argument so the script can write directly to disk. A conservative, example invocation looks like:

```
<GHIDRA_INSTALL_DIR>/support/analyzeHeadless <project_dir> -import <input_bin> \
  -postScript ghidra_exporter.py -scriptPath <out_dir> -- <out_dir>/<file_hash>-functions.json
```

Notes on the example:

- `<project_dir>`: a temporary or per-run project directory (the adapter reuses `out_dir` by default).
- `-import <input_bin>`: instructs Ghidra to import the binary to be analyzed.
- `-postScript ghidra_exporter.py -scriptPath <out_dir>`: tells Ghidra to run the named script and where to find it.
- `-- <out_dir>/<file_hash>-functions.json`: pass-through argument(s) forwarded to the script; our exporter expects the last
  argument to be the absolute path to write the JSON file.

The adapter's `build_headless_cmd()` composes a similar argument list. Unit tests do not execute the real command;
they monkeypatch `run_headless_export()` to simulate the headless process and to write the expected JSON export file.

## Caching & provenance

- `ensure_ghidra_export` should first check for an existing `out_dir/<file_hash>-functions.json` and the
  `.cache_meta.json` produced by `results_packager.package_results`. If present and not `force`, return the cached path.
- When producing a new export, update `meta.ghidra_export` with the export path so it becomes part of
  the packaging provenance.

## Gating and opt-in behavior

- Adapter is opt-in. Discovery order for Ghidra is:
  1. `options.get('ghidra_install_dir')`
  2. environment variable `GHIDRA_INSTALL_DIR`
  3. search `PATH` for `analyzeHeadless` (best-effort)
- If not found, `ensure_ghidra_export` returns `None` and the runner continues with quick heuristics.

## Timeouts and safety

- The adapter must accept a `timeout` (seconds). Long-running exports should be cancellable. Default: 10 minutes.
- Capture stdout/stderr and persist them into `out_dir/ghidra-export.log` for troubleshooting.

## Testing strategy

- Unit tests (fast, mock-based):
  - `find_analyze_headless()` behavior with env/PATH mocks.
  - `build_headless_cmd()` produces reasonable arguments.
  - `run_headless_export()` uses `monkeypatch` to fake `subprocess.run` and tests timeout & error handling.
  - `ensure_ghidra_export()` using `monkeypatch` to fake successful `run_headless_export()` and a sample functions JSON written by the fake process; test cache and `force` paths.
  - `read_ghidra_functions()` parsing of a sample JSON file.
- Integration tests (optional, marked):
  - A slow test that runs `analyzeHeadless` against a small binary and asserts an export is produced. Skip unless `GHIDRA_INSTALL_DIR` present; mark with `@pytest.mark.integration`.

## Runner integration

- `runner.py` already calls `ghidra_adapter.ensure_ghidra_export(...)`. Ensure runner passes `options={'ghidra_install_dir': ..., 'force': ctx.force, 'timeout': 600}` and catches `TimeoutError` or other adapter exceptions, annotating `result.summary` or `meta` with the failure reason.

## CI and developer notes

- Keep unit tests mocked so CI does not require Ghidra.
- Add an `integration` pytest marker and document how to run integration tests locally:

  ```powershell
  $env:GHIDRA_INSTALL_DIR = 'C:\path\to\ghidra'
  pytest -q -m integration tests/test_ghidra_integration.py
  ```

## Security considerations

- Never run user-supplied Ghidra scripts. Only run the adapter's own exporter script.
- Exported JSON must be treated as untrusted input; sanitize or limit fields passed to heuristics.

## Implementation milestones (small PRs)

1. PR1 — Skeleton + discovery helpers + docs

   - Add `find_analyze_headless()` and `read_ghidra_functions()` (parsing only).
   - Unit tests mocking missing Ghidra and parsing.

2. PR2 — Command builder + run wrapper

   - Implement `build_headless_cmd()` and `run_headless_export()` and tests (mock `subprocess`).

3. PR3 — Export script & ensure_ghidra_export() with caching

   - Add exporter script, implement caching checks, write export file, wire into runner. Unit tests with monkeypatch to fake subprocess writing sample file.

4. PR4 — Integration test and docs
   - Add integration test (marked) and expand docs with example commands and troubleshooting notes.

## Estimated effort

- Small steps: PR1 (1 day), PR2 (1 day), PR3 (2–3 days), PR4 (1 day) depending on access to Ghidra for verification.

## Questions and choices for you

- Do you prefer the exporter script to live as a separate file under `src/.../ghidra_export.py` or be embedded as a string in `ghidra_adapter.py` and written to disk at runtime?
- Default timeout: is 10 minutes acceptable, or do you want a shorter default (e.g., 5 minutes)?

## Next step

If you want to proceed now I can implement PR1: add `ghidra_adapter.py` skeleton and unit tests (mocking missing Ghidra). Reply "start PR1" and I'll create the files and tests.

---

Document created on: 2025-11-06

## Installer scripts & Docker

This repository includes convenience installer scripts and a Dockerfile to
help developers and CI bring up a reproducible Ghidra-enabled environment:

- `tools/install-ghidra.ps1` — PowerShell installer that downloads and
  extracts a pinned Ghidra release (requires explicit `-AcceptLicense`).
- `tools/install-ghidra.sh` — Bash installer for Linux/macOS (requires
  `--accept-license`).
- `docker/ghidra.Dockerfile` — Dockerfile skeleton that installs OpenJDK,
  downloads Ghidra and sets `GHIDRA_INSTALL_DIR` for CI and reproducible runs.

See `docs/ghidra_installation.md` for step-by-step installation, checksums,
and CI usage patterns.
