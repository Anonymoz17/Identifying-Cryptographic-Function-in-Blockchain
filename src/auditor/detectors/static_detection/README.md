# Static Detection (skeleton)

This folder contains a skeleton implementation for the static-detection
auditor. Files are light-weight stubs intended to be implemented incrementally.

Overview of files

- `context.py` — dataclasses for RunContext / RunResult
- `runner.py` — StaticRunner orchestrator (main entrypoint)
- `preproc_adapter.py` — deterministic loader for preproc artifacts
- `static_preproc.py` — derived artifact generator (strings, constants, etc.)
- `ghidra_adapter.py` — ghidra export wrapper (integration-only)
- `heuristics/` — heuristics package (signature, instruction patterns, constants)
- `heuristics_manager.py` — run and aggregate heuristics
- `scoring.py` — deterministic score aggregation
- `hints_generator.py` — produce `hints.json` and redacted `hints_public.json`
- `results_packager.py` — write `static_results.json` and add provenance
- `cache.py` — write/read cache metadata
- `validator.py` — JSON schema validation wrapper
- `cli.py` — thin CLI scaffolding
- `README.md` — this file

Next steps

1. Implement and test `preproc_adapter.load_preproc`.
2. Implement `static_preproc.generate_static_preproc` quick path.
3. Add unit tests for heuristics and schema validation.

## Notes

- The pipeline uses a `file_hash` (64-character lowercase SHA256) as the canonical
  identifier for a run. `metadata.json` should include `file_hash` or `sha256` in
  lowercase hex; the loader enforces this and will raise on mismatches.
- `metadata.json` is read with `utf-8-sig` to tolerate accidental BOMs produced
  by some editors, but the file contents must otherwise be valid JSON.
