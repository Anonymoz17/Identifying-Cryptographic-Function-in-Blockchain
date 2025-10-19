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

YARA integration tests (optional)

We provide a small GitHub Actions workflow that runs only the YARA
integration tests. The workflow is located at
`.github/workflows/integration-yara.yml` and performs the following steps:

- checks out the repository
- sets up Python (3.11)
- installs dev dependencies from `requirements-dev.txt`
- installs `yara-python` and runs `pytest -q tests/test_yara_adapter_integration.py`

Notes and OS-specific considerations:

- Building `yara-python` may require native build tools on some runners
  (compilers, libtool). The Ubuntu runners typically work well. On
  Windows you may need to provide a prebuilt wheel or adjust the job to
  use a Linux runner.
- If `yara-python` fails to install in CI, consider:
  - using a prebuilt wheel in the job, or
  - running the job on `ubuntu-latest`, or
  - caching a built wheel artifact.

Adding more rulesets

- The `detectors/yara/` directory is the canonical place for rule packs.
- When adding more rulesets, include unit tests that validate each rule's
  intended positive and negative matches. Add integration tests that run
  a small sample of the rules in CI to catch regressions.
