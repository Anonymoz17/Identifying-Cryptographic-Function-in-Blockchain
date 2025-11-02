from __future__ import annotations

from pathlib import Path
from typing import Optional

from .setupcontext import SetupContext


class PathValidationError(Exception):
    pass


def _is_root_dir(p: Path) -> bool:
    try:
        # On Windows p.anchor is like 'C:\', on POSIX it's '/'
        return p.resolve() == Path(p.resolve().anchor)
    except Exception:
        return False


def path_validation(ctx: SetupContext) -> SetupContext:
    """Validate and normalize paths in SetupContext.

    Checks performed:
      - scope exists and is a directory and readable
      - workdir exists or can be created and is writable
      - case_dir (workdir/case_id) is created and writable
      - forbid scanning root drives if configured
      - set derived paths (case_dir, preproc_dir, manifest_path)

    Raises PathValidationError on fatal failures.
    """
    scope = Path(ctx.scope)
    workdir = Path(ctx.workdir)

    try:
        scope = scope.resolve()
    except Exception as e:
        raise PathValidationError(f"Scope path resolution failed: {e}")

    # basic existence and type checks
    if not scope.exists():
        raise PathValidationError(f"Scope does not exist: {scope}")
    if not scope.is_dir():
        raise PathValidationError(f"Scope is not a directory: {scope}")

    # forbid root scans when configured
    if ctx.config.forbid_root and _is_root_dir(scope):
        raise PathValidationError(f"Refusing to scan root path: {scope}")

    # readability check: attempt to iterate a tiny sample
    try:
        _ = next(scope.iterdir())
    except StopIteration:
        # empty directory is OK
        pass
    except PermissionError:
        raise PathValidationError(f"No permission to read scope: {scope}")
    except Exception:
        # best-effort: allow other read errors to proceed but warn
        pass

    # Normalize and assign
    ctx.scope = scope

    # Ensure workdir exists or can be created
    try:
        workdir = workdir.resolve()
    except Exception:
        # fallback to cwd
        workdir = Path.cwd()

    # create case_dir
    case_dir = workdir / ctx.case_id
    try:
        case_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        raise PathValidationError(f"Could not create case directory {case_dir}: {e}")

    # check writability
    testfile = case_dir / ".write_test"
    try:
        with testfile.open("w") as f:
            f.write("x")
        testfile.unlink()
    except Exception:
        raise PathValidationError(f"Case directory not writable: {case_dir}")

    # derived paths
    preproc_dir = case_dir / "preproc"
    manifest_path = case_dir / "inputs.manifest.ndjson"

    ctx.workdir = workdir
    ctx.case_dir = case_dir
    ctx.preproc_dir = preproc_dir
    ctx.manifest_path = manifest_path

    return ctx
