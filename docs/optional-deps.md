Optional native and dev dependencies

This project supports several optional native and development-time dependencies that enable extra functionality (AST parsing, disassembly, YARA integration, JSON schema validation for tests). They are not required to run the core application but are recommended for developers and CI when running the full test suite or enabling advanced features.

Recommended dev extras (add to your virtualenv):

- jsonschema >= 4.0.0

  - Used by tests that validate AST JSON against a schema.
  - Install: pip install jsonschema

- PyYAML >= 6.0
  - Used by CLI helpers that load YAML configs.
  - Install: pip install PyYAML

Optional native integrations (may require additional system tooling):

- tree-sitter

  - Used to produce AST caches for source files (Solidity, Go). The Python package is `tree_sitter` and some languages require a compiled language bundle.
  - Install (pip): pip install tree_sitter
  - For language grammars, the repo includes instructions to build a shared languages library (tree_sitter_langs.so). See Tree-sitter docs.

- capstone

  - Used to disassemble binaries for lightweight disassembly caches.
  - Install: pip install capstone

- yara-python

  - Optional YARA integration used by the YARA adapter and optional integration tests.
  - Install: pip install yara-python

- semgrep

  - Useful for source-level pattern scanning (Semgrep CLI). Not required for core unit tests.
  - Install (pip): pip install semgrep

  - The repository includes a `SemgrepCliAdapter` (see `src/detectors/semgrep_adapter.py`) which invokes the `semgrep` CLI and converts results into the NDJSON detector shape.

- ghidra (headless)

  - Optional heavy-weight analysis used by the Ghidra adapter. Requires a Ghidra distribution and a Java runtime.
  - Ghidra is run outside Python (analyzeHeadless). See `detectors/README.md` and `docs/pipeline.md` for recommended inputs/outputs and example runner scripts.

  - A minimal wrapper exists at `tools/ghidra_headless_runner.py` which iterates `artifacts/ghidra_inputs/` and expects a Ghidra script to produce JSON exports under `artifacts/ghidra_exports/`.

Notes

- Tests that require these optional dependencies are marked to skip when the dependency is not present (e.g. tests/test_yara_integration_optional.py).
- If you want to run the full test suite including integration tests, install the dev extras before running pytest:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pip install tree_sitter capstone yara-python
pytest -q
```

- If you encounter build errors installing `tree_sitter` or `capstone`, consult the upstream project documentation for system prerequisites (C compiler, libtool, etc.).
