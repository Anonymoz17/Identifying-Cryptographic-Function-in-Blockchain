# Preprocessing Specification

This document defines the concrete preprocessing outputs, layout and manifest fields expected by downstream detectors.

# Preprocessing Specification (updated)

This document defines the preprocessing outputs, artifact layout and recent changes relevant to disassembly/mapping and detectors.

Date: 2025-10-19

## Goals

- Produce per-file canonical artifacts under the case workspace.
- Create a streaming-friendly manifest `inputs.manifest.ndjson` and a complementary `preproc.index.jsonl` for quick lookups.
- Provide hooks and directories for AST caches and disassembly caches.
- Record disassembly address→file-offset mappings (new in Oct 2025) so detectors can report file offsets for instruction-level detections.

## Workspace layout (created under case workspace root)

- `inputs.manifest.ndjson` (NDJSON): manifest records, one per logical input (including extracted files)
- `preproc.index.jsonl` (NDJSON): index of preprocessing operations, one line per input processed
- `preproc/`:
  - `<sha>/`
    - `input.bin` (canonical copy)
    - `metadata.json` (the manifest record for this sha)
- `extracted/`:
  - `<sha>/` (extracted contents of archive with same sha)
  - Notes: extracted files are placed under `extracted/<sha>/` where `<sha>` is the sha256 of the original input archive. Each extracted file is also represented as a manifest record with `origin` set to `extracted:<parent-archive-filename>`.
- `artifacts/ast/`:
  - `<sha>.json` (tree-sitter AST cache)
- `artifacts/disasm/`:
  - `<sha>.json` (Capstone/Capstone-like light disassembly cache containing `disasm`, `mappings` and `base_address`)
- `artifacts/ghidra_inputs/`:
  - `<sha>/` (files prepared for ghidra_headless)
- `auditlog.ndjson`

## Disassembly artifact: `artifacts/disasm/<sha>.json`

New (Oct 2025) spec for the disassembly artifact written by `preproc.build_disasm_cache`.

Top-level fields:

- `sha` (string) — manifest id
- `disasm` (list | null) — list of instruction objects or null when disassembly is not available
- `mappings` (list) — list of mapping objects `[{"address": <numeric>, "offset": <numeric>}, ...]`
- `base_address` (integer) — the numeric base address used during disassembly (0 when unknown)

Instruction object shape (example):

{
"addr": 4198400,
"mnemonic": "mov",
"op_str": "eax, ebx"
}

How to interpret `mappings`:

- `address` is the instruction virtual/linked address produced by the disassembler.
- `offset` is the corresponding byte offset relative to the `input.bin` file (computed as `address - base_address` when `base_address` is numeric).
- Consumers should prefer `mappings` to convert instruction addresses into file offsets for triage and evidence extraction.

How `base_address` is chosen (best-effort heuristic):

- ELF: use the ELF entry point (`e_entry`) when available.
- PE (Windows Portable Executable): attempt to parse DOS header `e_lfanew`, locate the PE Optional Header, and read `ImageBase` (PE32 or PE32+). A fallback scan for the `PE\x00\x00` signature is used when offsets are not where expected.
- Mach-O: best-effort scan of load commands (LC_SEGMENT / LC_SEGMENT_64) to collect segment `vmaddr` values and choose the smallest non-zero vmaddr as the `base_address`.
- If header parsing fails, `base_address` remains 0 and `mappings` will contain offsets equal to the disassembler addresses (still usable).

These heuristics are intentionally conservative and wrapped in try/except blocks; the implementation favors safe fallback over raising exceptions.

## Adapter and detector changes (summary of implemented work)

- Semgrep adapter: hardened to accept common Semgrep JSON shapes and added unit tests with mocked semgrep JSON output.
- Tree-sitter detector: implemented runtime parsing and AST-cache fallback; added capture-to-(line,col) conversion and query discovery across repository locations. New queries for Solidity and Go were added under `detectors/queries/`.
- YARA: added a canonical rulepack `detectors/yara/crypto.yar` and made the `YaraAdapter` robust to multiple rule directories and to the absence of `yara-python` at runtime (fallback to regex adapter when needed).
- Disassembly/Capstone:
  - `preproc.build_disasm_cache` was extended to compute `base_address` for ELF/PE/Mach-O where possible and to write `mappings` to `artifacts/disasm/<sha>.json`.
  - `src/detectors/disasm_adapter.py` (DisasmJsonAdapter) was updated to prefer artifact `mappings` to translate an instruction `address` to a `Detection.offset` (file byte offset). The adapter also accepts various instruction field name variants and supports pattern + mnemonic-based rule matching.

## Tests added/updated

- `tests/test_preproc_pe_macho_base.py` — unit tests that synthesize minimal PE and Mach-O headers and assert mapping offsets and reasonable `base_address` values. These tests monkeypatch a fake `capstone` runtime to control instruction addresses and validate offset computation.
- `tests/test_disasm_adapter_mapping.py` — verifies `DisasmJsonAdapter` uses the `mappings` array to compute `Detection.offset`.
- Existing disasm tests (`tests/test_disasm_cache.py`, `tests/test_disasm_wiring.py`, `tests/test_ast_disasm_mocked.py`) were left intact and pass with the new logic.
- Tree-sitter, YARA, and Semgrep related tests were implemented earlier as part of the static-detection work (see their individual test files in `tests/`).

Run tests (recommended):

```powershell
# run the new disasm/preproc tests only
pytest tests/test_preproc_pe_macho_base.py -q
pytest tests/test_disasm_adapter_mapping.py -q

# run entire test suite (might skip some integration tests if optional deps are missing)
pytest -q
```

If optional native dependencies (capstone, tree_sitter, yara-python) are not installed on the runner, some integration-style tests will either be skipped or use the repository's mocking strategy (most tests mock optional modules where appropriate).

## Files changed in this feature

- src/auditor/preproc.py — PE/Mach-O/ELF base_address detection; write `disasm`, `mappings`, `base_address` into `artifacts/disasm/<sha>.json` when capstone is available.
- src/detectors/disasm_adapter.py — DisasmJsonAdapter updated to prefer `mappings` and to normalize instruction fields; mnemonic support added.
- src/detectors/tree_sitter_detector.py — query lookup improvements and capture mapping to line/column.
- src/detectors/tree_sitter_utils.py — helper utilities for token normalization.
- src/detectors/adapter.py — YARA adapter fallbacks and other adapter hardening.
- detectors/queries/\*.scm — Tree-sitter queries for Solidity and Go.
- detectors/yara/crypto.yar — YARA crypto rulepack.
- tests/test_preproc_pe_macho_base.py — new tests verifying PE/Mach-O behavior.
- tests/test_disasm_adapter_mapping.py — mapping test.
- tools/run_tree_sitter_queries.py — small helper to run tree-sitter queries (unchanged)

## Guidance for consumers / detectors

- When producing `Detection` objects from disassembly, prefer the artifact `mappings` to translate an instruction `address` into a file `offset` for triage and evidence extraction. If `mappings` is absent, adapters should fall back to using the raw instruction address (best-effort) but mark offsets as uncertain.
- The `base_address` value is advisory and best-effort — do not rely on it being present for every binary.

## Next recommended steps

1. Document `mappings` and `base_address` formally in any detector adapter contracts (update `schemas/detector_result.schema.json` if you want to require `offset` semantics).
2. Add CI matrix entries to run integration jobs that install optional deps (capstone, tree-sitter, yara) so the integration tests run on at least one job.
3. Add more robust Mach-O fat-binary parsing and extra validation for malformed headers if you expect to preprocess arbitrary third-party binaries at scale.

## Changelog (high level)

- 2025-10-18: initial preprocessing spec and basic extraction/AST/disasm stubs.
- 2025-10-19: added PE/Mach-O base detection, `mappings` support and adapters/tests described above (see files changed list).

---

If you'd like, I can now:

- create a short entry in `CHANGELOG.md` that summarizes these changes for the project history, and/or
- open a PR branch with these edits and the new tests, or
- add a small example showing how a detector should prefer `mappings` when producing `Detection.offset` values.
