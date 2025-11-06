# Static-Guided Dynamic Detection Pipeline

Last updated: 2025-11-06

## Purpose

This document defines a cleaned, prescriptive design and implementation plan for a Static-Guided Dynamic Detection Pipeline that uses Ghidra for static analysis and Frida for dynamic instrumentation. It assumes the existing preprocessing pipeline produces canonical artifacts under `preproc/<file_hash>/` and that the detection stages will be implemented anew (we will not reuse any existing static/dynamic detector code — the detection modules will be built fresh under `src/detection/`).

## Decisions confirmed

- Ghidra: recommend Ghidra 10.4.x (latest stable 10.x series). Detection modules will require `GHIDRA_INSTALL_DIR` (or `analyzeHeadless` on PATH). This version will be documented in `docs/optional-deps.md`.
- Frida: implement the spawn/harness (instrumented-spawn) mode in the first iteration (recommended). Support for attach mode will be added later as an advanced feature.
- Traces/storage: default to local disk under `analysis/dynamic/<file_hash>/traces/`. Storage will be pluggable (configurable S3 or other object store) later.
- Preprocessing: reuse the existing, modular preprocessing outputs (immutable canonical artifacts) as the single source of truth for detection. Detection modules will be independent and new.

Table of contents

- Executive summary
- Goals and constraints
- Where we are today (preprocessing summary)
- High-level pipeline (static → dynamic → merge)
- File layout and canonical identifiers
- Data contracts & JSON schemas (hints/results/merged)
- Static detection (Ghidra) — fresh implementation notes
- Dynamic detection (Frida) — spawn/harness-first notes
- Correlation & merging — algorithm and config
- Business gating (free static / premium dynamic)
- Security, privacy, and sandboxing
- Changes required in repo and code pointers
- Tests, CI, and quality gates
- Implementation roadmap (phased, prioritized)
- Risks & mitigations
- Next steps & questions

## Executive summary

We will build a cooperative Static-Guided Dynamic Detection Pipeline with three modular stages:

1. Static detection (Ghidra) — runs headless, recovers functions, produces prioritized hints (addresses, ranges, confidence)
2. Dynamic detection (Frida, premium) — uses static hints to instrument and trace targeted runtime behavior (spawn/harness mode initially)
3. Correlation & merging — aligns static + dynamic evidence into a final high-confidence report

Each stage will be implemented as new code under `src/detection/`. The preprocessing artifacts under `preproc/<file_hash>/` remain the canonical immutable inputs.

## Goals and constraints

- Reproducibility: every artifact references the canonical `file_hash` (preproc SHA256).
- Modularity: static, dynamic, and merge modules live under `src/detection/` with stable JSON contracts in `src/detection/schemas/`.
- Safety: dynamic runs execute only inside configured sandboxes/containers; raw secrets are not stored by default.
- Extensibility: the system will support additional detectors or instrumenters later.

## Where we are today (preprocessing summary)

The project already provides a modular preprocessing core that produces canonical artifacts under a case workspace:

- `preproc/<file_hash>/input.bin` — canonical file contents
- `preproc/<file_hash>/metadata.json` — size, mtime, detected type/format, arch, and provenance fields

Preprocessing is implemented in the repository (see `src/auditor/setup_flow/preproc.py`), and detectors will consume these artifacts without modifying preprocessing logic.

## High-level pipeline (static → dynamic → merge)

1. Preprocessing (existing and unchanged)

   - Input: original files, archives, etc.
   - Output: `preproc/<file_hash>/input.bin`, `metadata.json`

2. Static detection (Ghidra, fresh implementation)

   - Input: `preproc/<file_hash>/input.bin`, `metadata.json`
   - Output: `analysis/static/<file_hash>/hints.json`, `analysis/static/<file_hash>/static_results.json`

3. Dynamic detection (Frida, premium; spawn/harness-first)

   - Input: preproc artifacts + `analysis/static/<file_hash>/hints.json`
   - Output: `analysis/dynamic/<file_hash>/dynamic_results.json`, optional sanitized traces

4. Correlation & Merge
   - Input: static + dynamic outputs (dynamic optional)
   - Output: `analysis/merged/<file_hash>/final_report.json`

All outputs include `file_hash`, `schema_version`, `timestamp`, and provenance fields.

## File layout and canonical identifiers

Base layout (configurable base path):

- preproc/<file_hash>/

  - input.bin
  - metadata.json

- analysis/static/<file_hash>/

  - hints.json
  - static_results.json
  - ghidra-export/ (optional cached raw function exports)

- analysis/dynamic/<file_hash>/

  - dynamic_results.json
  - traces/ (sanitized snapshots, optional)

- analysis/merged/<file_hash>/
  - final_report.json

Primary identifier: SHA256 file hash produced by preprocessing.

## Data contracts & JSON schemas (summary)

We'll publish and validate JSON schemas under `src/detection/schemas/` for these artifacts. Brief shapes:

- hints.json: { file_hash, schema_version, language, timestamp, hints:[{id, type, name?, address_or_range, confidence, reason_tags, evidence_snippet?, call_graph_neighbors?}] }
- static_results.json: { file_hash, schema_version, timestamp, findings: [...], hints_path }
- dynamic_results.json: { file_hash, schema_version, timestamp, runs:[{hint_id, observed_calls, metrics,...}], traces_path }
- final_report.json: { file_hash, schema_version, timestamp, merged_findings:[{id, symbols, static_confidence, dynamic_confidence, merged_confidence, verdict}], weights, notes }

## Static detection (Ghidra) — fresh implementation notes

We will implement the static detector from scratch under `src/detection/` rather than reusing any previous static detector code.

Responsibilities:

- `ghidra_adapter.py`: discover `analyzeHeadless` (via `GHIDRA_INSTALL_DIR` or PATH), run Ghidra headless with our packaged export script, manage per-`file_hash` cache of raw exports, and read the resulting JSON export.
- `static_detector.py`: parse Ghidra exports, run layered heuristics (signatures, instruction-patterns, high-entropy constants, import matches), compute confidence scores, and write `hints.json` and `static_results.json`.

Schema versioning and profiles

- All static outputs include `schema_version` and `analysis_profile` (e.g., `quick` or `thorough`). The detector always writes the full canonical hints JSON; presentation/UI layers may redact fields for free users.

Caching

- Ghidra runs are expensive. Implement caching: if `analysis/static/<file_hash>/hints.json` exists and `force=False`, reuse it. Cache raw ghidra-export under `analysis/static/<file_hash>/ghidra-export/`.

## Dynamic detection (Frida) — spawn/harness-first notes

Approach for first iteration:

- Implement `frida_harness.py` and `dynamic_detector.py` under `src/detection/`.
- Mode: spawn/harness — the dynamic detector will run the target within a controlled wrapper process (no network by default), load generated Frida scripts that hook addresses or imported APIs from hints.json, and stream structured events back to the orchestrator.

Captured data and sanitization

- Do not persist raw buffers containing potential secrets. Store hashed fingerprints (SHA256), entropy metrics, sizes, and call counts by default. Allow opt-in for full capture.

Sandboxing

- Enforce default resource limits: wall-clock timeout (default 5 minutes), memory (default 512MB), and CPU constraints. These are configurable.

## Correlation & merging — algorithm and config

- Join keys: `file_hash` primary; use `hint.id` or address ranges as secondary. If dynamic evidence absent, final report will reflect static-only verdicts.
- Default weights: static=0.4, dynamic=0.6 (configurable in `src/detection/merge_config.json`).
- Merge rule (configurable): weighted average: merged_confidence = static_confidence*ws + dynamic_confidence*wd. Verdict thresholds documented in schema.

## Business gating (free static / premium dynamic)

- Static outputs are produced for all users (free). Dynamic runs are gated: promoted via CLI flag and validated server-side via roles/licensing.
- Enforcement points: `src/app.py` endpoints and CLI wrappers will check `roles.py` (or a license service) before queuing/executing dynamic jobs.

## Security, privacy, and sandboxing

- Always run dynamic instrumentation in isolated environments; no external network access by default.
- Sanitize traces: default storage stores only hashes and metadata. Full traces require explicit opt-in and stronger access controls.
- Audit logs record who triggered dynamic runs and when.

## Changes required in repo and code pointers (fresh implementation)

Add (new under `src/detection/`):

- `__init__.py`
- `preproc_adapter.py` — adapter to validate and load `preproc/<file_hash>/` artifacts
- `schemas/` — JSON schema files for hints, static_results, dynamic_results, final_report
- `ghidra_adapter.py` — programmatic wrapper for Ghidra headless runs and JSON export ingestion
- `static_detector.py` — orchestrator and heuristics for static hints/results
- `frida_harness.py` — Frida script builder and event listener
- `dynamic_detector.py` — orchestrates sandboxed Frida runs and writes dynamic_results.json
- `merger.py` — merge static + dynamic outputs into final_report.json
- `merge_config.json` — default weights and thresholds

Small edits / new wiring

- `src/app.py` — add CLI/API endpoints to invoke static/dynamic/merge workflows; dynamic entrypoints check license/role via `roles.py`.

External dependencies & docs

- Document Ghidra 10.4.x and how to set `GHIDRA_INSTALL_DIR` in `docs/optional-deps.md`.
- Document Frida installation (pip install frida-tools) and platform notes.

## Tests, CI, and quality gates

- Unit tests: validate schemas, static heuristics on small fixtures, adapter behaviors.
- Integration: dynamic tests are integration-only (require Frida/sandbox), run manually or in a specialized CI runner.

## Implementation roadmap (phased)

Phase 0 — Prep (1 day)

- Create `src/detection/` skeleton and JSON schema stubs. Implement `preproc_adapter.py` to validate preproc inputs.

Phase 1 — Static-first (2–4 days)

- Implement `ghidra_adapter.py` (headless invocation + JSON export ingestion) and `static_detector.py` (heuristics + hints.json output). Add schema tests.

Phase 2 — Merger & free flow (1 day)

- Implement `merger.py` that produces `analysis/merged/<file_hash>/final_report.json` when only static results exist.

Phase 3 — Dynamic prototype (Frida spawn) (3–6 days)

- Implement `frida_harness.py` and `dynamic_detector.py` (spawn/harness). Enforce sandbox limits and sanitize traces. Gate runs by license.

Phase 4 — Hardening & infra (ongoing)

- Add quotas, retention, optional external trace storage, monitoring, and additional heuristics.

## Risks & mitigations

- Dynamic instrumentation executes untrusted binaries — mitigate via sandboxing, no-network default, and strict limits.
- Ghidra automation may vary by version — pin recommended version and provide compatibility tests.
- False positives/negatives — provide explainable evidence and iterative tuning.

## Next steps & questions

Planned immediate action (I will start after your confirmation):

- Create the `src/detection/` package skeleton with `preproc_adapter.py` and schema stubs, and add documentation entries for Ghidra and Frida (based on the confirmed choices above).

Questions for you (confirmations):

1. Confirm Ghidra version recommendation: Ghidra 10.4.x (yes/no). (If no, specify preferred version.)
2. Confirm dynamic mode preference: spawn/harness-first (yes/no). (If no, specify attach-first.)
3. Confirm default sandbox limits: 5 minutes wall time, 512MB memory (yes/no). (If no, provide preferred defaults.)

Once you confirm the three items above I will implement the detection skeleton and preproc adapter.

---

Document author: pipeline design (revised per user request). This document intentionally avoids referencing any prior static/dynamic detector implementations in the repository — the detection code will be implemented anew under `src/detection/`.
