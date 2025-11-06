# Static Detection — detailed pipeline

Last updated: 2025-11-06

This document describes the Static Detection module in detail. It is written
to fit the overall Static-Guided Dynamic Detection Pipeline: preproc -> static
-> dynamic (premium) -> merge. The static module is implemented as its own
auditor subpackage (currently `auditor/static-detection`) and must be modular,
well-documented, and easy to call from higher-level workflows.

Design goals

- Modular: clear subpackages/files for adapters, heuristics, schema and CLI.
- Reproducible: every output references canonical `file_hash` (preproc sha256).
- Cache-first: expensive analyses (Ghidra exports) cached on disk.
- API-friendly: expose simple function/CLI entrypoints for orchestration and tests.
- Free/premium aware: static outputs are produced for all users; dynamic is
  gated.

High-level flow (where static fits)

1. Intake / Preprocessing (existing): `preproc/<file_hash>/input.bin` and
   `preproc/<file_hash>/metadata.json` are produced by the preproc pipeline.
2. Static Detection (this module): read preproc artifacts, produce
   `analysis/static/<file_hash>/hints.json` and `analysis/static/<file_hash>/static_results.json`.
   Optionally cache raw Ghidra exports at `analysis/static/<file_hash>/ghidra-export/`.
3. Dynamic Detection (premium): guided by `hints.json`, Frida harness runs and
   writes `analysis/dynamic/<file_hash>/dynamic_results.json`.
4. Merger: combine static + dynamic (if present) into
   `analysis/merged/<file_hash>/final_report.json`.

Key contracts and invariants

- Primary identifier: `file_hash` (SHA256). All artifacts must include it.
- Schema versioning: every artifact includes `schema_version` and `timestamp`.
- Read-only preproc: static detection must never modify `preproc/` inputs.

Module layout (files and responsibilities)

- auditor/static-detection/

  - **init**.py

    - package exports, version

  - preproc_adapter.py

    - Responsibility: deterministic loading/validation of preproc artifacts.
    - API: load_preproc(preproc_dir) -> {file_hash, input_path, metadata}
    - Rationale: isolate parsing/validation so detectors are agnostic to
      preproc internal changes.

  - ghidra_adapter.py

    - Responsibility: produce and read Ghidra exports (headless runner wrapper).
    - API: run_ghidra_export(preproc_input, out_dir, file_hash, options) -> path
      (exports functions.json); read_ghidra_functions(path) -> dict.
    - Rationale: Ghidra runs are expensive and environment-dependent. Wrapping
      them allows retries, environment checks, and version pinning.

  - static_detector.py

    - Responsibility: orchestrate static analysis: call ghidra_adapter,
      run heuristics/signature matchers, produce `hints.json` and
      `static_results.json`.
    - API: run_static_detector(preproc_dir, analysis_base, options) -> dict
    - Rationale: central entrypoint, caching logic, schema validation,
      deterministic outputs for both free and premium flows.

  - heuristics/

    - Responsibility: collection of independent heuristic detectors.
    - Files (examples):
      - heuristics/signature.py (library signature matches)
      - heuristics/instruction_patterns.py (pattern detectors e.g., xor/rol loops)
      - heuristics/constants.py (high-entropy constant detection)
      - heuristics/call_graph.py (neighbour/context scoring helpers)
    - API style: each heuristic exposes a function heuristic(ghidra_export, metadata) -> List[Finding]
    - Rationale: keep heuristics small, testable, pluggable and composable.

  - schemas/

    - JSON schemas for: hints.json, static_results.json, plus any internal
      intermediate shapes.
    - Rationale: definitive contract between static and dynamic stages; CI
      validates outputs against schemas.

  - cache.py (or cache utilities inside ghidra_adapter)

    - Responsibility: disk-based caching helpers, TTLs, and cache-busting
      (force re-run) flags.

  - cli.py

    - Responsibility: small CLI wrappers for local/CI runs:
      - `static-detect run <preproc_dir> [--force] [--profile quick|full]`
      - `static-detect export-raw <file_hash>`
    - Rationale: makes it easy to run/CI-check static detection without
      forcing higher-level flow.

  - tests/
    - Unit tests for adapters, heuristics, schema validation, and a small
      integration test that uses a fixture `preproc/<fixture_hash>/`.

Outputs and their purpose

- hints.json

  - Primary purpose: guidance for the dynamic harness. Should be prioritized,
    include `id`, `type`, `address_or_range`, `confidence`, `reason_tags`.
  - Must be succinct and safe to expose to free users (no secrets).

- static_results.json
  - Detailed static findings, rationale, evidence paths (e.g., `ghidra-export`),
    confidence scores and suggested actions.

Quality & validation

- Every output is validated against its JSON schema before being written. Use
  `jsonschema` in tests/CI to validate sample outputs.
- Unit tests: one per heuristic, plus a small E2E static-only test that asserts
  both `hints.json` and `static_results.json` are created and conform to schemas.

Scoring and heuristics (high level)

- Signature matches (imports, known function bytes): high base confidence.
- Instruction-pattern detectors (rounds/loops, bitwise-heavy blocks): medium.
- Constants (S-box-like tables, high-entropy arrays): medium.
- Call-graph evidence (calls to known crypto import wrappers): boost score.
- Combine evidence using a deterministic scoring function producing 0.0–1.0
  confidence; keep weights configurable in `merge_config.json`.

Caching and performance

- Cache raw Ghidra exports under `analysis/static/<file_hash>/ghidra-export/`.
- If cached and `--force` not set, reuse existing artifacts to reduce cost.
- Provide `profile` option: `quick` for shallow heuristics (fast, fewer false
  positives), `full` for deeper analysis (slower but higher recall).

Security, privacy and gating

- Do not include any captured runtime data in static outputs.
- Static outputs must be safe to show to free users; redact anything that
  could be considered proprietary (full disassembly samples) unless in
  `ghidra-export/` (protected workspace caches).

Integration points and wiring

- `src/app.py` or auditor orchestration should call:
  - preproc (existing) -> static_detector.run_static_detector() -> optionally
    trigger dynamic if premium.
- The static detector should return an object with paths to produced artifacts
  so the orchestrator can pass necessary inputs to dynamic detector.

Developer notes & next work items

- Implement real `ghidra_adapter.run_ghidra_export` with environment checks
  (GHIDRA_INSTALL_DIR detection, version pinning, and script args).
- Implement heuristic modules incrementally and add tests per heuristic.
- Add an integration smoke test for static-only flow in CI.

References

- High-level pipeline doc: `docs/pipeline.md`
- Preproc: `src/auditor/setup_flow/preproc.py`

If you'd like, I can now:

- (A) implement a real `ghidra_adapter` that invokes `analyzeHeadless` and
  writes the export, or
- (B) add unit-test scaffolding for heuristics and schema validation.

Tell me which next step to take and I will proceed.

---

## Additional design details (collected from our discussion)

1. Static-specific preprocessing (detailed)

The static stage benefits from its own derived preprocessing artifacts. These
are deterministic, cached, and never mutate the canonical `preproc/<file_hash>`.
Store them under `analysis/static/<file_hash>/preproc/`.

- `normalized.bin` — flat/normalized image for analysis (optional, format-dependent).
- `sections.json` — section names, vaddrs, sizes, file offsets, flags.
- `headers.json` — file format, arch, bitness, endianness, entrypoint.
- `imports.json` — imported DLLs/symbols or PLT stubs.
- `exports.json` — exported symbols and ordinals (if present).
- `strings.json` — printable strings with offsets and counts.
- `constants.json` — candidate embedded tables and blobs with entropy scores.
- `entropy_map.json` — per-section/per-range entropy and histograms.

Purpose: these artifacts let heuristics run quickly and consistently, provide
evidence for scoring, and avoid running full Ghidra when a quick pass suffices.

2. Runner and typed context

Introduce a small orchestrator (`auditor/static-detection/runner.py`) and typed
context dataclasses (`auditor/static-detection/context.py`). The runner is the
single, stable API the rest of the system calls. It coordinates caching, stage
selection, retries, telemetry and gating.

Suggested dataclasses and fields

- RunContext

  - file_hash: str
  - preproc_dir: str
  - analysis_base: str
  - profile: Literal['quick','full']
  - force: bool
  - requested_by: Optional[str]
  - tool_versions: Dict[str,str]
  - timestamp: datetime

- RunResult
  - file_hash: str
  - hints_path: str
  - static_results_path: str
  - cached: bool
  - summary: Dict[str,Any]
  - errors: Optional[List[str]]

Runner responsibilities (concise)

- Validate `preproc_dir` using `preproc_adapter`.
- Ensure derived static preproc exists (generate if missing or `force=True`).
- Optionally run quick cue extraction to decide whether to run Ghidra.
- Ensure Ghidra export exists (cached) or run headless analysis.
- Run heuristics (parallel when possible) and aggregate findings.
- Generate `hints.json` (internal) and `hints_public.json` (redacted summary).
- Package `static_results.json`, validate schemas, write `.cache_meta.json`.
- Return a `RunResult` with artifact paths and a small summary.

3. Decomposed file/module map (one-to-one to the 9 steps)

- `context.py` — dataclasses (RunContext, RunResult, ToolVersions)
- `runner.py` — StaticRunner orchestrator (public `run(ctx) -> RunResult`)
- `static_preproc.py` — generates normalized.bin, sections.json, imports.json, strings.json, constants.json
- `cue_extractor.py` — quick capstone/radare2/byte-cue extractor for first-N-bytes fingerprints
- `ghidra_adapter.py` — ensure_ghidra_export(), read_ghidra_functions(); environment checks, retries
- `heuristics/` (signature.py, instruction_patterns.py, constants.py, call_graph.py) — each returns List[Finding]
- `heuristics_manager.py` — run and collect heuristic outputs (parallelizable)
- `scoring.py` — deterministic aggregation and contribution tracing
- `hints_generator.py` — produce `hints.json` and `hints_public.json` (redaction)
- `results_packager.py` — write `static_results.json`, add provenance, links to caches
- `cache.py` — read/write `.cache_meta.json`, TTLs and invalidate
- `validator.py` — jsonschema validation helpers
- `cli.py` — thin CLI to construct RunContext and call StaticRunner

Each file exposes small, testable functions (signatures included earlier in
this document). Keep public surface minimal: `StaticRunner.run(ctx)` and the
preproc/heuristic APIs for unit testing.

4. Serving and gating (practical rules)

- Free/public UI: serve `static_results.json` (findings, rationales). Optionally
  include `hints_count` and top reason_tags, but never precise addresses.
- Internal/premium: `hints.json` (full) and `ghidra-export/` can be used by the
  orchestrator to schedule dynamic Frida runs — access guarded by role check.
- Provide `hints_public.json` generated from `hints.json` that removes
  addresses/ranges and only contains counts/top-tags for UI display.

5. Caching, metadata, and reproducibility

- Write `.cache_meta.json` in `analysis/static/<file_hash>/` containing:
  - timestamp, generator_version, ghidra_version, heuristics_version, profile, tool_versions
- Use cache meta to decide re-run vs reuse; support `--force` to invalidate.
- Include generator and schema versions in each output for audit and
  repeatability.

6. Testing & CI recommendations

- Unit tests for each heuristic with small fixture binaries.
- Schema validation tests for `hints.json`, `static_results.json` and derived
  preproc schemas.
- Quick-profile smoke tests run in CI; mark Ghidra-dependent tests as
  integration-only and run in dedicated integration jobs.

7. Security & privacy rules (summary)

- Never store raw candidate keys/secret buffers in outputs by default — store
  hashes and entropy metrics. Raw captures required for debugging are opt-in
  and stored in protected locations.
- Log who requested dynamic runs and which hints were used. Enforce RBAC on
  hints access.

8. Next steps (practical)

- Create the scaffolding files (context.py, runner.py, static_preproc.py,
  cue_extractor.py, ghidra_adapter.py, heuristics_manager.py, scoring.py,
  hints_generator.py, results_packager.py, cache.py, validator.py, cli.py) as
  minimal stubs so we can iterate and add heuristics/tests incrementally.
- Implement `generate_static_preproc` (quick profile) as the first working
  module (parsers for sections/imports/strings/constants).
- Implement `hints_public.json` redaction logic and add schema placeholders.

If you want I can start by adding the scaffolding stubs (option A) or
implementing `static_preproc.py` (option B). Pick one and I will begin.
