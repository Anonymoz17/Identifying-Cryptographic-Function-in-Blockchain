from __future__ import annotations

from pathlib import Path
from typing import Optional

from .setupcontext import SetupContext
from .setupmessages import Notifier


class PathValidationError(Exception):
    pass


def _is_root_dir(p: Path) -> bool:
    try:
        # On Windows p.anchor is like 'C:\', on POSIX it's '/'
        return p.resolve() == Path(p.resolve().anchor)
    except Exception:
        return False


def path_validation(ctx: SetupContext, notifier: Optional[Notifier] = None) -> SetupContext:
    """Validate and normalize paths in SetupContext.

    Checks performed:
      - scope exists and is a directory and readable
      - workdir exists or can be created and is writable
      - case_dir (workdir/case_id) is created and writable
      - forbid scanning root drives if configured
      - set derived paths (case_dir, preproc_dir, manifest_path)

    Raises PathValidationError on fatal failures.
    """
    if notifier is None:
        notifier = Notifier()

    notifier.info(f"Starting path validation", path=str(ctx.scope))

    orig = Path(ctx.scope)
    workdir = Path(ctx.workdir)

    # 1) Existence
    notifier.info("Checking existence of scope", path=str(orig))
    if not orig.exists():
        notifier.warn("Scope does not exist", path=str(orig))
        raise PathValidationError(f"Scope does not exist: {orig}")

    # 2) Type (must be directory)
    notifier.info("Checking scope is a directory", path=str(orig))
    if not orig.is_dir():
        notifier.warn("Scope is not a directory", path=str(orig))
        raise PathValidationError(f"Scope is not a directory: {orig}")

    # 3) Resolution: normalize path
    notifier.info("Resolving and normalizing scope path", path=str(orig))
    try:
        scope = orig.resolve()
    except Exception as e:
        notifier.warn("Scope path resolution failed", path=str(orig), details={"error": str(e)})
        raise PathValidationError(f"Scope path resolution failed: {e}")

    notifier.ok("Scope resolved", path=str(scope))

    # forbid root scans when configured
    if ctx.config.forbid_root and _is_root_dir(scope):
        notifier.warn("Refusing to scan root path", path=str(scope))
        raise PathValidationError(f"Refusing to scan root path: {scope}")

    # 4) Traversal prevention: reject explicit traversal components
    if ".." in orig.parts:
        notifier.warn("Scope contains traversal components ('..')", path=str(orig))
        raise PathValidationError(f"Scope contains traversal components: {orig}")

    # 5) Symlink safety: check ancestor symlinks don't escape mount/anchor
    try:
        for ancestor in orig.parents:
            if ancestor.exists() and ancestor.is_symlink():
                target = ancestor.resolve()
                if target.anchor != scope.anchor:
                    notifier.warn("Symlink ancestor resolves outside mount/anchor", path=str(ancestor), details={"target": str(target)})
                    raise PathValidationError(f"Symlink ancestor {ancestor} resolves outside allowed area: {target}")
    except PathValidationError:
        raise
    except Exception:
        notifier.warn("Symlink safety check encountered an error; continuing", path=str(orig))

    # 6) Permissions: ensure readability by trying to iterate a sample
    notifier.info("Checking readability of scope", path=str(scope))
    try:
        _ = next(scope.iterdir())
    except StopIteration:
        notifier.info("Scope is empty (no entries)", path=str(scope))
    except PermissionError:
        notifier.warn("No permission to read scope", path=str(scope))
        raise PathValidationError(f"No permission to read scope: {scope}")
    except Exception:
        notifier.warn("Error reading scope (continuing)", path=str(scope))

    # Assign normalized scope back into context
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
        notifier.warn("Could not create case directory", path=str(case_dir), details={"error": str(e)})
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

    notifier.ok("Case prepared", path=str(case_dir), details={
        "preproc_dir": str(preproc_dir),
        "manifest_path": str(manifest_path),
    })

    return ctx
