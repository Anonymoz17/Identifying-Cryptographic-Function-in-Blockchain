# Static-Guided Dynamic Detection Pipeline

Last updated: 2025-11-06

Purpose: Define a detailed design and implementation plan for a Static-Guided Dynamic Detection Pipeline that cooperatively uses Ghidra for static analysis and Frida for dynamic analysis to identify cryptographic functions in binaries/source. The document explains how this new pipeline uses existing preprocessing artifacts, the data contracts between stages, file layout, JSON contracts, file layout, schemas, implementation plan, and changes required (including Ghidra for static and Frida for dynamic).

Table of contents

- Executive summary
- Goals and constraints
- Where we are today (preprocessing summary)
- High-level pipeline (static → dynamic → merge)
- File layout and canonical identifiers
- Data contracts & JSON schemas (hints/results/merged)
- Static detection (Ghidra) — architecture and implementation notes
- Dynamic detection (Frida) — architecture and implementation notes
- Correlation & merging — algorithm and config
- Business gating (free static / premium dynamic)
- Security, privacy, and sandboxing
- Changes required in repo and code pointers
- Tests, CI, and quality gates
- Implementation roadmap (phased, prioritized)
- Risks & mitigations
- Next steps & questions

## Executive summary

We will implement a cooperative Static-Guided Dynamic Detection Pipeline. The preprocessing stage already produces canonical artifacts per input (canonical `input.bin`, `metadata.json`) keyed by SHA256. The static stage will run first using Ghidra to produce structured hints (function symbols, address ranges, confidence) saved to `analysis/static/<file_hash>/hints.json` and `static_results.json`. The dynamic stage uses Frida, guided by these hints, to instrument and trace runtime behavior for the same file and write `analysis/dynamic/<file_hash>/dynamic_results.json`. A merger module correlates and merges findings and produces `analysis/merged/final_report.json`.

Key decisions made up front

- Use Ghidra for static analysis (disassembly, function recovery, symbols, call graph). Ghidra will be automated via headless scripts (Ghidra headless analyzer) to extract function metadata and slices.
- Use Frida for dynamic instrumentation to hook functions or DLL/API calls at runtime based on hints. Frida supports many platforms and allows lightweight tracing.
- Keep preproc artifacts as the single canonical input and identity (sha256 file hash) across all stages.
- Free tier: only run Static (Ghidra) and emit static results + hints. Premium tier: run Guided Dynamic (Frida) and merge results.

## Goals and constraints

- Reproducibility: every run should be traceable back to the canonical preproc `<file_hash>`.
- Modularity: static, dynamic, and merge modules are separate packages with stable JSON contracts.
- Safety: dynamic runs happen in sandboxed environments; traces are sanitized for secrets.
- Extensibility: allow future detectors (e.g., tree-sitter for source, other instrumenters) while keeping Ghidra/Frida as primary.

## Where we are today (preprocessing summary)

The existing preprocessing pipeline already provides the essential canonical artifacts we need:

- Path: `preproc/<file_hash>/`
  - `input.bin` — canonical file content (binary or textual canonicalized form)
  - `metadata.json` — metadata including detected language, original filename, size, and preprocessing ingestion notes
  - `manifest` — (if present) listing source files and provenance

This design assumes those artifacts are immutable and present. The exact metadata keys will be inspected/validated by `preproc_adapter` (see Implementation Changes).

## High-level pipeline (static → dynamic → merge)

1. Preprocessing (existing)

   - Unchanged; static and dynamic read from `preproc/<file_hash>/`.

2. Static Detection (Ghidra)

   - Input: `preproc/<file_hash>/input.bin`, `metadata.json`
   - Output: `analysis/static/<file_hash>/hints.json`, `analysis/static/<file_hash>/static_results.json`
   - Purpose: generate prioritized hints (function addresses, name, line/byte ranges, confidence) that the dynamic step will use to focus instrumentation.

3. Dynamic Detection (Frida, PREMIUM)

   - Input: `preproc/<file_hash>/input.bin`, `analysis/static/<file_hash>/hints.json`
   - Output: `analysis/dynamic/<file_hash>/dynamic_results.json`
   - Purpose: instrument functions and API calls indicated by hints, collect runtime evidence (observed calls, argument sizes, entropy, calling patterns).

4. Correlation & Merge
   - Input: static_results.json + optional dynamic_results.json
   - Output: `analysis/merged/final_report.json`
   - Purpose: align findings by file hash and symbol/address and produce unified verdict and confidence.

All outputs must include the canonical `file_hash` and a `timestamp` and reference the `preproc/` path they were derived from.

## File layout and canonical identifiers

Canonical input and outputs will follow this directory structure at repository root (or configurable base path):

- preproc/<file_hash>/

  - input.bin
  - metadata.json

- analysis/static/<file_hash>/

  - hints.json
  - static_results.json
  - ghidra-export/ (optional: raw Ghidra script outputs, symbol maps)

- analysis/dynamic/<file_hash>/

  - dynamic_results.json
  - traces/ (optional: sanitized trace snapshots)

- analysis/merged/
  - final_report.json (or per-file under analysis/merged/<file_hash>/final_report.json)

Primary identifier: SHA256 file hash (string) — use the exact hash currently produced by preprocessing. All modules must read and write files using this identifier.

## Data contracts & JSON schemas (summary)

All modules exchange JSON artifacts. For the initial implementation we will include compact but explicit schemas (YAML/JSON files under `src/detection/schemas/`). The core shapes:

1. hints.json (guidance from static → dynamic)

{
"file_hash": "<sha256>",
"language": "<detected-language>",
"timestamp": "<ISO8601>",
"hints": [
{
"id": "h-1",
"type": "function|api_call|file_hash|constant",
"name": "optional symbol name",
"address_or_range": { "start": "0x401000", "end": "0x4011F0" },
"confidence": 0.0-1.0,
"reason_tags": ["aes-like-sequence","high-entropy-const"],
"evidence_snippet": "small snippet or summary",
"call_graph_neighbors": ["h-2", ...] // optional
}
]
}

2. static_results.json

{
"file_hash": "<sha256>",
"timestamp": "<ISO8601>",
"findings": [ { "id":"f-1", "symbol":"...", "kind":"suspicious_function", "confidence":0.75, "location": {"start":"0x..","end":"0x.."}, "explanation": "..." } ],
"hints_path": "analysis/static/<file_hash>/hints.json"
}

3. dynamic_results.json

{
"file_hash": "<sha256>",
"timestamp": "<ISO8601>",
"runs": [
{"hint_id":"h-1","observed_calls": [ {"api":"EVP_EncryptInit","args_sample":"...","arg_sizes":[...],"call_count":5 } ], "metrics": {"entropy_estimate":0.98, "likely_key_length":256}, "notes":"..." }
],
"traces_path": "analysis/dynamic/<file_hash>/traces/"
}

4. final_report.json

{
"file_hash":"<sha256>",
"timestamp":"<ISO8601>",
"merged_findings": [ { "id":"m-1","symbols":["f-1"],"static_confidence":0.75,"dynamic_confidence":0.92,"merged_confidence":0.88,"verdict":"likely" } ],
"weights":{"static":0.4,"dynamic":0.6},
"notes":"Produced by merger v1"
}

Schemas will be saved under `src/detection/schemas/` as `hints.schema.json`, `static_results.schema.json`, `dynamic_results.schema.json`, and `final_report.schema.json`. All detectors must validate outputs against these schemas before writing.

## Static detection (Ghidra) — architecture and implementation notes

Why Ghidra

- Ghidra provides robust disassembly, function recovery, signatures, and a headless analyzer mode that can be scripted. It's well-suited for recovering functions and extracting reliable address ranges and call graphs from binaries.

Components

- ghidra_worker.py (or ghidra_adapter.py)

  - Responsible for launching Ghidra headless analysis for a single `preproc/<file_hash>/input.bin`.
  - Exports: function list (name or synthetic id), start/end addresses, disassembly snippets, discovered imports (DLLs, syscalls), and preliminary tags (e.g., AES-like instruction sequences), plus call graph adjacency lists.

- static_detector.py
  - Reads preproc metadata, uses ghidra_worker to gather raw outputs, runs heuristic detectors (patterns, signature matches, high-entropy constants) to assign confidence scores, and builds `hints.json` and `static_results.json`.

Ghidra integration details

- Use headless analyzer with a small Java/Ghidra script (Ghidra's scripting API in Java or Python Jython). The script will:
  - Analyze binary, run default analyzers, recover functions.
  - For each function produce: function name (if present), or synthetic id, start/end addresses, disassembly sample (first N instructions), cross-references (XREFs), called imports, and recognized library signatures.
  - Optionally compute simple instruction patterns (e.g., repeated XOR chains, rotation + XOR sequences) and record counts. These patterns help produce reason_tags.

Output from ghidra_worker should be a compact JSON file (e.g., `ghidra-export/functions.json`) that static_detector will read.

Heuristics & scoring

- Heuristics are layered. Example hints of interest:
  - functions calling known crypto imports (libcrypto, mbedtls): high confidence.
  - functions containing sequences typical of block ciphers: medium-high confidence.
  - functions that operate on buffers with repeated rounds/loops and bitwise ops: medium confidence.
  - high-entropy embedded constants (possible S-boxes): medium confidence.

Score composition: start with base score from signature matches, then boost with supporting evidence (constants, call relationships) and penalize for small functions or lacking context.

Deliverables for first iteration (static)

- `src/detection/ghidra_adapter.py` — headless invocation wrapper and JSON exporter
- `src/detection/static_detector.py` — orchestrator that converts ghidra output to `hints.json` and `static_results.json`
- JSON schemas and unit tests validating outputs

## Dynamic detection (Frida) — architecture and implementation notes

Why Frida

- Frida enables runtime instrumentation across many platforms and languages. It's excellent for intercepting API calls and function entry/exit and collecting argument data without modifying the target binary permanently.

Components

- frida_harness.py (core)

  - Accepts `preproc/<file_hash>/input.bin`, a runtime execution strategy (spawn, attach, run test harness), and `analysis/static/<file_hash>/hints.json`.
  - Builds Frida scripts that hook function addresses or exported symbols indicated by hints. For each hook it captures call arguments, sizes, and optionally a small data sample (subject to privacy/safety rules).

- dynamic_detector.py
  - Orchestrates sandbox creation (container/VM), runs the target binary (or an instrumented test harness), loads Frida scripts, and collects instrumented events into `dynamic_results.json`.

Instrumentation modes

- Targeted hooking (preferred): use hint addresses to place Frida hooks on those addresses or exported names.
- API-level hooking: for imported crypto library functions (e.g., OpenSSL), hook those APIs globally rather than by address.
- Expand-to-neighbors: if hint confidence is low, expand to call-graph neighbors from ghidra hints up to depth N.

Sandboxing & execution

- Dynamic runs must be isolated: ephemeral container or lightweight VM with no network access by default.
- Provide helper runner for common file types: for native binaries run via a wrapper that launches the process and loads Frida; for interpreted languages provide an interpreter wrapper.

Data captured & sanitization

- Capture structured events: function_enter, function_exit, args (sizes and hashes), return values (sizes and hashes), call_count, timestamps.
- Do NOT store raw secrets in traces. Raw buffers must be hashed (e.g., SHA256) and entropy metrics recorded instead of raw bytes unless user opt-in.

Deliverables for first iteration (dynamic)

- `src/detection/frida_harness.py` — builds Frida scripts per hint and listens for events
- `src/detection/dynamic_detector.py` — orchestrates a minimal safe run using Frida; writes dynamic_results.json

## Correlation & merging — algorithm and config

Identification

- Primary join key: `file_hash` (always present)
- Secondary join: `hint.id` and `function address` (addresses published by static stage and used by dynamic hooks). If symbol names differ or not present, use address ranges.

Confidence merging (configurable)

- Default weights in `src/detection/merge_config.json`:

  - static_weight: 0.4
  - dynamic_weight: 0.6

- Base merging (simple weighted average):

  merged_confidence = static_confidence _ static_weight + dynamic_confidence _ dynamic_weight

- If dynamic evidence is missing, merged_confidence = static_confidence (free tier). If static evidence is missing and dynamic exists (rare), merged_confidence = dynamic_confidence.

Decision rules

- merged_confidence >= 0.85 => verdict: "likely"
- 0.6 <= merged_confidence < 0.85 => "possible"
- merged_confidence < 0.6 => "unlikely"

Outputs

- final_report.json must include the weights used, timestamp, and a human-readable rationale explaining how each finding was merged and where supporting evidence resides.

## Business gating (free static / premium dynamic)

Design

- Static-only results (hints + static_results) are produced for all users and can be served in the free tier.
- Dynamic runs (Frida instrumentation, traces) require a premium license or role and may incur compute/infra costs.

Enforcement surfaces

- CLI: `dynamic_detector` refuses to run unless `--license-token` or environment variable `DETECT_DYNAMIC=1` is set and validated by server or local license check.
- API: `src/app.py` endpoints that trigger dynamic runs must check user roles/flags in `roles.py` or the auth system (existing code has `roles.py`). If missing, return HTTP 402 or 403.
- UI/UX: show static results to free users, and a CTA to run dynamic verification for premium users.

Quota & resource accounting

- Track dynamic runs per user and enforce quotas; add run metadata to a persistent store (e.g., database) to avoid DoS.

## Security, privacy, and sandboxing

Dynamic runs execute untrusted binaries. Security requirements:

- Always run dynamic instrumentation in an isolated environment (container or VM) with disabled network unless explicitly allowed.
- Limit CPU, memory, ephemeral disk, and wall-clock time (configurable runtime limit, e.g., 5 minutes default).
- Sanitize captured traces: do not persist raw buffers containing potential keys; instead store hashed fingerprints (SHA256) and entropy metrics. Provide opt-in for full capture.
- Audit logging: log who started dynamic runs and what hints were used.

## Changes required in repo and code pointers

Files & modules to add (initial):

- src/detection/**init**.py
- src/detection/preproc_adapter.py — helpers to read preproc artifacts and validate metadata
- src/detection/schemas/\*.json — JSON schemas for the artifacts
- src/detection/ghidra_adapter.py — wrapper to run Ghidra headless and export functions
- src/detection/static_detector.py — orchestrator that produces hints.json + static_results.json
- src/detection/frida_harness.py — builds Frida scripts and listener
- src/detection/dynamic_detector.py — orchestrates dynamic runs and writes dynamic_results.json
- src/detection/merger.py — merges static + dynamic into final_report.json
- docs/pipeline.md (this document)

Small edits to existing files

- `src/app.py` — add API endpoints or CLI wiring to run static/dynamic/merge workflows. Ensure role check for dynamic run.
- `roles.py` — add `can_run_dynamic_detection` helper mapped to license/role storage.

Config files to add

- `src/detection/merge_config.json` — default weights and thresholds
- `requirements-dev.txt` or `pyproject.toml` updates to mention `frida` tooling or a note to install Frida separately (Frida is typically installed via pip or system packages). Ghidra is an external Java-based tool; document required Ghidra version and installation path in `docs/optional-deps.md`.

Notes on external dependencies and environment

- Ghidra: requires Java and Ghidra installation. Use Ghidra headless script runner. Document how to install Ghidra and set `GHIDRA_HOME`.
- Frida: requires Python `frida` and `frida-tools`, and host support for attaching to processes. Document how to install it and any platform-specific notes.

## Tests, CI, and quality gates

Quality gates

- Build: run flake8/black/type checks if applicable. Ensure new modules import cleanly.
- Lint/typecheck: minimal.
- Tests: pytest tests to validate JSON schemas and small E2E smoke tests.

Suggested tests

- Schema validation tests: generate sample outputs and validate against JSON schemas.
- Static detector unit tests: use a small sample binary fixture (checked into `tests/fixtures`) and assert `hints.json` has expected keys.
- Dynamic detector smoke test: use a tiny controlled test program that calls a simple crypto API (or a Python test harness) to run Frida-based tracing in CI if Frida can run in CI; otherwise mark as integration tests run manually.

CI notes

- Keep heavy dynamic instrumentation tests out of regular CI unless CI environment supports Frida and sandboxing. Mark them as integration-only.

## Implementation roadmap (phased)

Phase 0 — Preparations (1–2 days)

- Add `docs/pipeline.md` (this file).
- Add detection package skeleton and JSON schema files.
- Add `preproc_adapter` which validates `preproc/<file_hash>/` inputs.

Phase 1 — Static-first (2–5 days)

- Implement `ghidra_adapter.py` with a simple headless script that exports functions for a binary.
- Implement `static_detector.py` that produces `hints.json` and `static_results.json` using simple heuristics.
- Add unit tests for schema validation and a fixture static run.

Phase 2 — Merger (1–2 days)

- Implement `merger.py` that can merge static-only results into `final_report.json` for free users.
- Add CLI and `app.py` wiring to run static→merge automatically.

Phase 3 — Dynamic prototype with Frida (3–7 days)

- Implement `frida_harness.py` and `dynamic_detector.py` with a safe, local-only mode.
- Implement sandbox wrapper for a target run and capture events.
- Add config gating and a license/role check.

Phase 4 — Hardening, tests, infra (ongoing)

- Add sanitization, quotas, logging, RBAC, and more fingerprints and heuristics.
- Add integration tests and optional cloud-runner for premium dynamic jobs.

## Risks & mitigations

- Risk: dynamic instrumentation runs untrusted code and causes harm.

  - Mitigation: sandboxing, no-network default, quotas and timeouts.

- Risk: Ghidra headless automation may break across versions.

  - Mitigation: pin Ghidra versions in docs and provide a compatibility test harness.

- Risk: false positives/negatives.

  - Mitigation: produce explainable evidence; allow manual review; tune heuristics.

- Risk: dynamic runs are expensive.
  - Mitigation: use hints to reduce scope; gating to premium users; rate-limiting.

## Next steps & questions

Planned immediate actions (I can start these now if you approve):

- Create `src/detection/` package skeleton with JSON schemas and `preproc_adapter.py`.
- Implement `static_detector.py` stub that runs Ghidra via `ghidra_adapter.py` and outputs `hints.json` (static-only flow).
- Add `merger.py` that merges static-only results into `final_report.json` for free users.

Questions for you

1. Do we have a preferred Ghidra version and where will Ghidra be installed on dev/CI machines? If not, I will document a recommended stable version (e.g., Ghidra 10.x or latest LTS) and require `GHIDRA_HOME` environment variable.
2. For Frida, do you want us to support both native process attach and running instrumented harnesses (spawn) in the first iteration? I recommend implementing the spawn/harness mode first (safer to control inputs), then attach mode later.
3. For traces and storage: do you have a storage policy for traces (e.g., S3, local disk), retention period, or compliance rules that I should design for in advance? If not, I'll default to local `analysis/dynamic/<file_hash>/traces/` with a configuration option for external storage.

If you give the go-ahead I'll implement the package skeleton and the static detector stub next (Phase 0→1), produce unit tests for schema validation, and wire basic CLI commands into `src/app.py`.

---

Document author: automated design assistant (instructions provided by user). Comments and review welcome; we will refine this document into smaller design tickets as soon as you approve the high-level plan.
