# Contributing

Thank you for contributing! This document explains how to set up a development environment, run tests and linters, and prepare a PR.

## Quick start

1. Create and activate a virtual environment (PowerShell):

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

2. Install Git hooks:

```powershell
pre-commit install
```

3. Run all checks locally:

```powershell
pre-commit run --all-files
pytest -q
```


## Formatting & linting

We use `black`, `isort`, and `ruff` to enforce consistent style. `pre-commit` will format and lint files automatically on commit. If you need to run them manually:

```powershell
# format
black .
# sort imports
isort --profile black .
# lint (ruff)
ruff check .
```

If `pre-commit` autofixes things you don't expect, run `git stash --keep-index` then `pre-commit run --all-files` to see changes.

## Tests

Run tests with `pytest`:

```powershell
pytest -q
```

Write tests in the `tests/` directory. Aim for deterministic tests that don't depend on external services.

## Adding dependencies

- Add runtime dependencies to `requirements.txt`.
- Add dev/test dependencies to `requirements-dev.txt`.
- For reproducible installs in CI, create a pinned lock file (optional):

```powershell
pip-compile --output-file=requirements-lock.txt requirements.txt
pip-compile --output-file=requirements-dev-lock.txt requirements-dev.txt
```

CI uses `requirements-dev.txt` to install linters and test tools.

## Branches & PRs

- Work on feature branches (e.g., `feat/xxx`), bugfix branches (`fix/xxx`) or hygiene branches (`chore/xxx`).
- Create small, focused PRs with descriptive titles. Include screenshots and test instructions for UI changes.
- The CI pipeline runs linting and tests automatically. Fix any failures before requesting review.

## Coding style

- Prefer small functions and modules.
- Use `pathlib.Path` for filesystem paths.
- Keep imports grouped and sorted (isort + black handle this).

## Running the UI locally

This project uses `customtkinter` for the GUI. On Windows ensure `tkinter` is available (standard on many Python installers). To run the app locally:

```powershell
python app.py
```

## Optional maintenance tasks

- To regenerate pinned requirements: `pip-compile` (pip-tools).
- To run all formatters and linters and automatically commit formatting fixes, you can run:

```powershell
black . && isort --profile black . && ruff check --fix . && git add -A && git commit -m "chore: apply formatters"
```

## Questions

If you're unsure about anything, open an issue or ask in the PR discussion.
