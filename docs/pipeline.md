# Pipeline overview — preprocessing, detectors, and outputs

This document summarizes the preprocessing, detector, and merging pipeline implemented in this repository as of the current branch. It lists the artifact layout, NDJSON output contracts (schemas), optional native integrations, and CLI tools that consume/produce these artifacts.

## High level

- Input: a manifest of input items (arbitrary files) with a `sha256` identifier and optional metadata.
- Preprocessing: `src/auditor/preproc.py` produces per-sha artifact directories and two NDJSON files:
  - `preproc.index.jsonl` (index entries written during processing)
  - `inputs.manifest.ndjson` (manifest of processed inputs)
- AST & disasm caches: optional caches are written to `artifacts/ast/<sha>.json` and `artifacts/disasm/<sha>.json`.
- Detectors (adapters): a pluggable adapter API consumes the manifest and scans files; adapters currently implemented include regex, binary-regex, semgrep-lite, yara (optional), and others under `src/detectors/`.
- Runner & merge: `tools/run_detectors.py` runs configured adapters, writes `detector_results.ndjson`, and can merge/dedupe detections using engine weights.
- Summary: `tools/summarize_detections.py` produces CSV/JSON or console summaries grouped by rule.

## Artifact layout (workdir root)

- `preproc/` — per-sha artifact directories (one directory per input sha):
  - `preproc/<sha>/input.bin` — canonical copy of input
  - `preproc/<sha>/metadata.json` — metadata for the input
- `extracted/<sha>/` — files extracted from archives
- `artifacts/ast/<sha>.json` — cached AST JSON (when Tree-sitter available)
- `artifacts/disasm/<sha>.json` — cached disassembly (when Capstone available)
- `preproc.index.jsonl` — NDJSON index of items created while preprocessing
- `inputs.manifest.ndjson` — NDJSON manifest produced by preprocessing
- `detector_results.ndjson` — NDJSON detector output produced by adapters/runner

## Data contracts (NDJSON schemas)

The repository includes JSON Schema files under `schemas/` which describe the expected shape of common NDJSON outputs:

Use `jsonschema` (optional dev dependency) to validate generated NDJSON lines in tests or CI.

## Optional native integrations

See `docs/optional-deps.md` for install notes and developer instructions.

## Tools

## Quick validation examples

Validate a manifest line against the manifest schema (requires `jsonschema`):

```py
from jsonschema import validate
import json

schema = json.load(open('schemas/inputs.manifest.schema.json'))
line = json.loads(open('inputs.manifest.ndjson').read().splitlines()[0])
validate(line, schema)
```

## Notes

- The project intentionally keeps native integrations optional and the code includes fallbacks so the core workflows continue to function without tree-sitter, capstone, or yara installed.
- If you plan to run the full test matrix and integration tests, install the optional dev dependencies as described in `docs/optional-deps.md`.

# CryptoScope pipeline (draft)

This document describes the high-level pipeline, data contracts (NDJSON), preprocessing outputs, and how the downstream detectors (YARA, Semgrep, Tree-sitter, Capstone, Ghidra, Frida) will consume the artifacts produced by preprocessing.

Date: 2025-10-18

## 1. Goals

- Detect and identify cryptographic functions and related API use in blockchain systems to support security auditors.
- Prioritize Ethereum (Solidity/EVM), Bitcoin (C/C++), and Cosmos (Go) ecosystems.
- Be practical: produce reusable preprocessing artifacts that make static and optional dynamic detectors fast and reliable.

## 2. Target scope (MVP)

- Source languages: C, C++, Go, Python, JavaScript/TypeScript, Rust, Solidity (.sol).
- Binary types: ELF, PE, Mach-O, WebAssembly (.wasm), EVM bytecode (treated as special binary text or blob).
- Platforms: Linux, macOS, Windows native binaries.

## 3. High-level pipeline

[Preprocessing]

- Inventory files
- Extract archives
- Compute hashes and file metadata
- Language & MIME detection
- Produce AST caches (Tree-sitter) for supported languages (optional, cached)
- Produce small disassembly caches for binaries (Capstone) and prepare Ghidra inputs
- Write `inputs.manifest.json` and `preproc.index.jsonl` (NDJSON)

[Static Detectors]

The static detection stage runs a set of detectors that operate only on artifacts produced by preprocessing (raw bytes, extracted files, source files, AST caches, and light disassembly). Below are recommended adapters, how they consume preproc outputs, expected outputs, configuration and operational notes.

YARA

- Purpose: fast byte-pattern and file/section-based matching across raw binaries, extracted files, and concatenated blobs (archives). Useful for fingerprinting known crypto constants, magic sequences, and protocol markers.
- Inputs: `preproc/<sha>/input.bin`, files under `extracted/<sha>/`, and any non-text binary blobs in `inputs/`.
- Output: `detector_result` entries with `detector: "yara"`, `rule_id`, `match`, `offset`, `confidence` and optional `metadata` (e.g., yara variables or tag labels).
- Config:
  - Rulesets should be packaged under `detectors/yara/` or referenced by path in runner config.
  - Support both compiled rules (.yarac) and source .yar files. When YARA is not installed, the adapter should optionally fall back to a best-effort byte regex engine (less feature-rich).
- Notes:
  - Prefer tagging rules with `meta` fields: `meta: {"category":"crypto","confidence":0.9}` and use those when merging confidences.
  - For archive scanning, expand and scan each extracted member; tag results with `origin: "archive_member"` and `member_relpath`.

Semgrep

- Purpose: source-linguistic pattern matching using language-aware rules. Good for API usage, high-level crypto idioms, and insecure patterns in high-level languages (e.g., Python, JS, Go, Solidity).
- Inputs: source files listed in `inputs.manifest.ndjson` with `is_binary:false` and `language` hints.
- Output: `detector_result` entries with `detector: "semgrep"`, `rule_id`, `match`, `line`, `relpath`, `snippet`, and `confidence`.
- Config:
  - Ship a curated ruleset under `detectors/semgrep-rules/` and allow runner config to point to external rulepacks or remote repos.
  - Use Semgrep's JSON output and convert its matches into the repository `DetectorResult` schema.
- Notes:
  - Use the `language` field from the manifest to pick language-specific rule subsets.
  - For large repos, run semgrep in streaming mode (file-by-file) to avoid memory spikes.

Tree-sitter detectors

- Purpose: robust, language-aware AST matching for precise structural checks (e.g., function signatures, call graphs within a translation unit, Solidity AST patterns).
- Inputs: `artifacts/ast/<id>.json` produced by preprocessing (Tree-sitter AST caches).
- Output: `detector_result` entries with `detector: "tree-sitter"`, `rule_id`, `node_path` or `range`, `snippet`, and `confidence`.
- Config:
  - Implement detectors as small scripts under `detectors/tree-sitter/` that consume cached AST JSON and emit NDJSON lines.
  - Provide a lightweight query DSL or reuse tree-sitter query files (`queries/*.scm`) where possible.
- Notes:
  - AST caches must include source mapping (row/col) to easily produce code snippets and line numbers.
  - Cache invalidation: include `parser_version` and `grammar_commit` in AST cache metadata so detectors can re-run when grammars change.

Capstone / Lightweight disasm scanners

- Purpose: small instruction-level pattern detection for binaries without running a full binary analysis; suitable for short instruction sequences and typical crypto primitives (e.g., AES rounds, XOR loops, modular multiply idioms).
- Inputs: `artifacts/disasm/<id>.json` produced by preprocessing (Capstone-lite JSON) and `preproc/<id>/input.bin` offsets.
- Output: `detector_result` entries with `detector: "disasm"` (or `capstone`), `rule_id`, `address`/`offset`, `snippet` (instruction text), `confidence`.
- Config:
  - Keep disassembly shallow (function-level export optional) and focus on short signature sequences.
  - Provide architecture hints from preproc (e.g., `arch`, `bits`, `endian`) to guide Capstone. If not provided, attempt auto-detection.
- Notes:
  - For position-independent code, provide relative offsets and include the mapping from disasm `address` to `input.bin` offset.
  - Store basic function boundaries where possible to help link matches to higher-level detections.

Ghidra headless (optional)

- Purpose: heavyweight, graph-based detection using function-level exports, call-graph, and data-flow information. Useful for complex crypto function identification and CFG-pattern matching.
- Inputs: preprocessing should prepare `artifacts/ghidra_inputs/<id>/` with canonical copies and a per-input `metadata.json` describing architecture, loader hints and any symbol information.
- Output: `artifacts/ghidra_exports/<id>.json` and `detector_result` NDJSON lines annotated with `detector: "ghidra"`, `function_name` (if available), `func_addr`, `rule_id`, `confidence`, and optionally exported graph/summary metadata.
- Config & operation:
  - Keep Ghidra headless runs optional and directory-isolated. Running ghidra headless is an expensive CI/offline job; do not run by default in the interactive UI unless explicitly requested.
  - Provide a `tools/ghidra_headless_runner.py` wrapper (or a documented `ghidra` job) that consumes `artifacts/ghidra_inputs/` and writes `artifacts/ghidra_exports/`.
- Notes:
  - Document required Java/Ghidra versions in `docs/optional-deps.md` and provide example headless command lines.
  - For reproducibility, persist the Ghidra analysis script(s) used (e.g., under `detectors/ghidra/scripts/`) and check them into the repository.

Common output conventions

- All adapters should emit NDJSON lines that conform to `schemas/detector_result.schema.json` (use `detector` field to identify adapter). Include these fields where possible:
  - `detector`, `rule_id`, `file_id` (manifest id / sha256), `relpath`, `match`, `offset`/`address`/`line`, `snippet`, `confidence`, `metadata` (dict), `timestamp`.
- Confidence merging recommendation: each adapter may set a base confidence in the emitted record (0.0-1.0). The evidence fusion step will compute combined confidence = 1 - Π(1 - c_i) when grouping correlated matches.
- Tagging: include `tags` and `category` keys (e.g., `{"category":"crypto","tags":["symmetric","aes"]}`) to help merging and prioritization.

Developer notes

- Optional dependencies: document YARA, Semgrep, Tree-sitter CLI bindings, Capstone Python bindings, and Ghidra in `docs/optional-deps.md` with install hints.
- Adapter pattern: detectors live under `detectors/` and implement a small adapter interface: consume a manifest/inputs, produce `detector_result` NDJSON. See `detectors/README.md` (create if missing) for the interface contract.

[Dynamic Detectors] (optional/premium)

- Frida-based instrumentation for native processes (Windows/macOS/Linux)
- Capture crypto API calls, parameters, memory artifacts
- Optional sandboxing (external tooling)

[Evidence Fusion]

- Merge detections into consolidated NDJSON results (dedupe, aggregate confidence)
- Emit final `detections.ndjson` and append auditlog events

## 4. Preprocessing contract (inputs / outputs)

Inputs

- A list of file paths or a root folder (scope). The UI will pass the scope string(s) and options (recurse, follow symlinks, max size).

- Outputs (written under case workspace)
- `inputs.manifest.ndjson` — canonical manifest (NDJSON preferred for streaming large inventories)
  - `preproc.index.jsonl` — per-file preproc records (NDJSON)
- `preproc.index.jsonl` — per-file preproc records (NDJSON)
- `inputs/` — canonical copies (or links) of files used by detectors
- `extracted/` — contents of extracted archives (preserve mapping)
- `artifacts/ast/` — tree-sitter AST caches (per manifest id)
- `artifacts/disasm/` — per-binary disasm caches (Capstone JSON)
- `artifacts/ghidra_inputs/` — optional files to run against ghidra_headless
- `auditlog.ndjson` — sequential audit events (preproc.started, inputs.ingested, preproc.completed, etc.)

Error handling

- File-level parse errors are recorded in `preproc.index.jsonl` and processing continues.
- Workspace creation or permission errors abort and surface to the UI.

Caching

- Per-case caches under `case_dir/.cache/` and optional global cache under `uploads/.cache/` to reuse ASTs and heavier artifacts.

## 5. NDJSON data contracts (summary)

- Manifest entry (see `schemas/manifest.schema.json`): inventory line per file with id (sha256), path, relpath, size, mtime, mime, language, is_binary, origin.
- DetectorResult (see `schemas/detector_result.schema.json`): single detection line with detector, file_id, match, offset/range, snippet, confidence, metadata, timestamp.
- AuditLog event (see `schemas/auditlog.schema.json`): audit trail events appended as NDJSON.

Examples

Manifest example line (NDJSON):

```
{"id":"f3b...","path":"C:/repo/contract.sol","relpath":"inputs/contract.sol","size":5432,"mtime":"2025-10-18T13:00:00Z","mtime_epoch":1697640000,"sha256":"f3b...","mime":"text/x-solidity","language":"solidity","is_binary":false,"origin":"local"}
```

DetectorResult example:

```
{"id":"d-123","detector":"yara","file_id":"f3b...","relpath":"inputs/contract.sol","match":"crypto_xor_pattern","rule_id":"XOR_001","offset":104,"line":32,"snippet":"xor r0,r1","confidence":0.85,"timestamp":"2025-10-18T13:00:00Z"}
```

AuditLog example:

```
{"event":"preproc.completed","timestamp":"2025-10-18T13:05:00Z","actor":"auditor_ui","details":{"index_lines":1234}}
```

## 6. Detector mapping (how detectors read preprocessing outputs)

- YARA: consumes raw bytes under `inputs/` and `extracted/`. Use `manifest.id` to tag results.
- Semgrep: consumes source files and language hint from `manifest` to select rulesets.
  - A Semgrep CLI adapter is available (`src/detectors/semgrep_adapter.py`) which runs `semgrep --json` and converts results into DetectorResult lines. The runner `tools/run_detectors.py` can configure it via a config file.
- Tree-sitter detectors: consume `artifacts/ast/{id}.json` produced by preproc.
- Capstone/Light disasm: consume `artifacts/disasm/{id}.json`.
  - A disasm adapter is available (`src/detectors/disasm_adapter.py`) which consumes Capstone JSON caches or falls back to binary regex scanning.
- Ghidra headless: preproc places `artifacts/ghidra_inputs/{id}`; a separate headless Ghidra job runs and outputs `artifacts/ghidra_exports/{id}.json`.
  - The repo includes a small runner `tools/ghidra_headless_runner.py` and adapter `src/detectors/ghidra_adapter.py` that expect Ghidra to produce JSON exports under `artifacts/ghidra_exports/`.
- Frida: runtime instrumentation targets taken from preproc heuristics (binaries with crypto imports or named functions). Frida traces are merged as DetectorResult entries with `detector:frida`.

## 7. Ghidra headless recommended approach

- For complex CFG-based detections, run `analyzeHeadless` (ghidra_headless) in a separate process or CI job. Preproc should prepare canonical copies and metadata in `artifacts/ghidra_inputs/` and optionally launch ghidra if configured with a path to `ghidra_headless`.
- Keep Ghidra runs optional by default because Ghidra requires a Java environment and can be slow.

## 8. Dynamic / Frida design notes (premium)

- Provide a Frida adapter that accepts a target binary path and a hook-set. The adapter runs Frida, captures API calls and arguments, and emits `detector_result`-like NDJSON lines (detector:frida).
- For the MVP, focus on native POSIX/Windows/macOS processes; mobile will be considered later.

## 9. Evidence fusion / merging rules (summary)

- Group detector outputs by file_id and overlapping ranges.
- Compute combined confidence = 1 - Π(1 - c_i) and aggregate evidence array.
- Annotate merged result with `sources` listing contributing detectors.

## 10. Next implementation steps (priority)

1. Formalize NDJSON JSON Schema files (`schemas/*.json`).
2. Ensure `preprocess_items` writes `preproc.index.jsonl` and `inputs.manifest.json` with required fields. Add hooks for AST/disasm caching.
3. Implement `preproc.extract_artifacts()` with nested extraction and tests.
4. Add small Tree-sitter integration for Solidity/Go/C/JS and persist AST caches.
5. Add Capstone disassembly caching for binaries and a Ghidra input exporter.

## 11. Notes / open questions

- Confirm exact YARA and Semgrep rulesets to bundle vs. fetch dynamically.
- Confirm whether `inputs.manifest.json` should be NDJSON or a single JSON array (both supported; NDJSON preferred for streaming large manifests).

---

End of draft pipeline document. After you confirm this direction I will add the JSON Schema files and update the preprocessing code to emit the required fields and artifacts.
