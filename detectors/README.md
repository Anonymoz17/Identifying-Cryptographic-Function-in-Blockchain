This directory is a documentation/shim for detector adapters used by the auditor pipeline.

Adapter contract

- Implement a class that inherits from `src.detectors.adapter.BaseAdapter` and implement `scan_files(self, files: Iterable[str]) -> Iterable[Detection]`.
- Yield `Detection` dataclass instances (see `src/detectors/adapter.py`) with fields:
  - `path` (str): absolute or relative path to the matched file (typically `preproc/<sha>/input.bin` or extracted member path).
  - `offset` (Optional[int]): byte offset or character offset where the match occurs.
  - `rule` (str): rule identifier (short string) to identify the detection.
  - `details` (dict): arbitrary key/value map with additional detection metadata (e.g., `snippet`, `meta`, `tags`, `match_bytes`, `confidence`).
  - `engine` (Optional[str]): adapter engine name (e.g., `yara`, `binary-regex`, `semgrep-lite`, `capstone`).

Runner integration

- The runner (`src.detectors.runner`) will call `scan_files` and collect `Detection` objects. It then serializes detections to NDJSON using `write_ndjson_detections`.
- The NDJSON format produced contains keys: `path`, `offset`, `rule`, `details`, `engine`, and automatically lifts `tags`, `meta`, `rule_file`, `rule_namespace` to top-level. It also computes a `confidence` score using engine defaults or `details['confidence']`.

Best practices for auditors

- Use `manifest.id` (sha256) and `artifact_dir` mapping in `preproc` outputs to tag results. Prefer scanning `preproc/<sha>/input.bin` and emitting `path` values that the runner will later convert to `file_id` or be post-processed into `detector_result` schema.
- Include human-readable `snippet` and `line`/`address` where possible to help triage.
- Provide `meta` and `tags` to categorize results (e.g., `{"category":"crypto","tags":["aes","symmetric"]}`).

Examples

- See `src/detectors/adapter.py` for small reference adapters: `RegexAdapter`, `SimpleSemgrepAdapter`, `YaraAdapter`, and `BinaryRegexAdapter`.

YARA rules

- YARA rules live in `detectors/yara/` and are used by `YaraAdapter` if `yara-python` is installed.
- Rules should include `meta` fields (author, description, confidence) and conservative regexes with word boundaries.
- To run only the YARA integration test locally (skips unless yara-python installed):

```powershell
pytest -q tests/test_yara_adapter_integration.py
```

Testing

- Provide small sample inputs under `tests/fixtures/detectors/` and unit tests that exercise `scan_files` and verify NDJSON output shape.

Optional: adding a new detector

1. Add a new module under `src/detectors/` or a small wrapper in `detectors/` that constructs your adapter and registers it with `tools/run_detectors.py`.
2. Ensure the adapter gracefully degrades when optional native dependencies are missing (e.g., fallback to a pure-Python heuristic).
3. Document required optional dependencies in `docs/optional-deps.md` and add tests marked as optional when required.
