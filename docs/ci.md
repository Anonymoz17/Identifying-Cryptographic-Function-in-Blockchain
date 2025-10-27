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
