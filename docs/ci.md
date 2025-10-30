CI and local test instructions

This project includes a GitHub Actions workflow at `.github/workflows/ci.yml`
that runs linting (ruff/isort/black) and the pytest suite across several
Python versions. The workflow also exercises an optional matrix job that
installs Capstone so the code paths that use Capstone are exercised when
enabled.

Running tests locally

Create and activate a virtual environment, then install dev requirements:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

Run the test suite:

```powershell
pytest -q
```

Enable Capstone locally

To exercise Capstone-backed disassembly paths locally, install Capstone
into your dev environment:

```powershell
pip install capstone
pytest tests/test_disasm_aarch64.py -q
```

Notes

- The CI workflow intentionally includes an extra matrix job that installs
  Capstone to exercise the optional code path but the main test jobs do
  not require it. This keeps CI fast while still validating both code
  paths.

Mock Ghidra exports in CI / local tests

- The repository includes a mock Ghidra export under `tools/ghidra/mock_exports/example_functions.json` and a helper script `tools/consume_ghidra_mock.py` that copies the mock into a case workspace under `artifacts/ghidra_exports/<sha>/`.
- The integration tests use this mock so CI does not require a local Ghidra installation. If you want to run the full Ghidra headless exporter locally, follow `tools/ghidra/README.md`.

Running the mock-based integration test locally (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
# Copy mock exports into your case and run detectors (example case path below)
python .\tools\consume_ghidra_mock.py --case .\tools\case_demo\CASE-001
$env:PYTHONPATH='.'; python .\tools\run_detectors_local.py --case .\tools\case_demo\CASE-001
pytest -q tests/test_integration_ghidra.py -q
```
