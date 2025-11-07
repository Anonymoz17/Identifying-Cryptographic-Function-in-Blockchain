# CHANGELOG — static_detection

All notable changes to the `static_detection` detector are recorded in this file.

## [Unreleased]

### Schema: tighten preproc metadata schema (2025-11-06)

- Change: `preproc.metadata.schema.json` now _requires_ a `schema_version` field and requires either `file_hash` or `sha256` (64-lowercase-hex). The schema lives at:

  `src/auditor/detectors/static_detection/schemas/preproc.metadata.schema.json`

- Motivation: make the preproc metadata contract explicit so downstream consumers (static analysis, ghidra exports, heuristics) can rely on canonical fields and enable deterministic processing.

- Backwards compatibility and migration guidance:

  1. The loader (`load_preproc`) will attempt schema validation only when the schema file is present (it is present now). If `jsonschema` is not installed, the loader surfaces a clear `RuntimeError` explaining how to enable strict validation.
  2. Producers of `metadata.json` should include `schema_version` (string) and either `file_hash` or `sha256` (the SHA256 hex of `input.bin`) to conform to the new schema.
  3. To ease rollout, tests and the adapter support stubbed validators during development; CI should be updated to install `jsonschema` and to fail on schema violations.

- Recommended next steps for gradual tightening:

  - Stage 1 (now): Require `schema_version` + file hash (this change). Keep `additionalProperties: true` to avoid breaking unrelated metadata fields.
  - Stage 2: Add constrained enums for fields like `arch` and `format` (e.g., `x86_64`, `aarch64`) and make commonly-used fields (like `arch`) recommended or required depending on usage.
  - Stage 3: Replace `additionalProperties: true` with explicit property lists and tight nested schemas for arrays of signatures/hints. Bump `schema_version` to `2.0` and update loader to validate by `schema_version` value.

- CI/Validator guidance:
  - Ensure `jsonschema` is installed in CI (add to `requirements-dev.txt` or CI steps) so schema validation runs during tests.
  - Add a small test that validates the fixtures in `tests/fixtures/` against the schema (this can initially be skipped in environments without `jsonschema`).
