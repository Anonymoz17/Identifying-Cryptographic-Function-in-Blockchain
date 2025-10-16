"""File handling utilities moved under src/ for packaging."""

import datetime
import io
import mimetypes
import os
import re
import shutil
import time
import urllib.request
import zipfile
from pathlib import Path

try:
    import magic  # type: ignore

    _HAS_MAGIC = True
except Exception:
    _HAS_MAGIC = False


class FileHandler:
    def __init__(self, upload_dir="uploads"):
        self.upload_dir = (
            Path(upload_dir) if not isinstance(upload_dir, Path) else upload_dir
        )
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def handle_input(self, input_path: str) -> dict:
        input_path = (input_path or "").strip()
        if not input_path:
            raise ValueError("Empty input.")

        if input_path.startswith(("http://", "https://")):
            if "github.com/" in input_path:
                return self._handle_github_repo(input_path)
            raise ValueError(
                "Only GitHub repo URLs are supported for HTTP(S) sources in this app."
            )

        p = Path(input_path)
        if p.is_file():
            return self._handle_file(p)

        raise ValueError(f"Unsupported input: {input_path}")

    def _handle_file(self, filepath: Path) -> dict:
        filename = filepath.name

        stored_path = self.upload_dir / filename
        base = stored_path.with_suffix("")
        ext = stored_path.suffix
        i = 1
        while stored_path.exists():
            stored_path = self.upload_dir / f"{base.name}({i}){ext}"
            i += 1
        shutil.copy2(str(filepath), str(stored_path))

        if _HAS_MAGIC:
            try:
                mime = magic.from_file(str(stored_path), mime=True)
            except Exception:
                mime = (
                    mimetypes.guess_type(str(stored_path))[0]
                    or "application/octet-stream"
                )
        else:
            mime = (
                mimetypes.guess_type(str(stored_path))[0] or "application/octet-stream"
            )

        category = categorize_file(str(stored_path), mime)

        return {
            "filename": stored_path.name,
            "filetype": mime,
            "category": category,
            "size": stored_path.stat().st_size,
            "uploaded_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "stored_path": str(stored_path),
        }

    def _handle_github_repo(self, url: str) -> dict:
        m = re.search(r"github\.com/([^/]+)/([^/]+)", url)
        if not m:
            raise ValueError("Invalid GitHub URL.")
        owner = m.group(1)
        repo = m.group(2).replace(".git", "")

        branch = "main"
        m2 = re.search(r"/tree/([^/]+)", url)
        if m2:
            branch = m2.group(1)
        m3 = re.search(r"@([A-Za-z0-9._\-\/]+)$", url)
        if m3:
            branch = m3.group(1)

        zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"

        try:
            with urllib.request.urlopen(zip_url) as resp:
                data = resp.read()
        except Exception as e:
            raise ValueError(f"Failed to download repo ZIP: {e}") from e

        ts = int(time.time())
        dest_dir = os.path.join(self.upload_dir, f"{repo}-{branch}-{ts}")
        os.makedirs(dest_dir, exist_ok=True)

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(dest_dir)
        except Exception as e:
            raise ValueError(f"Failed to extract ZIP: {e}") from e

        inner_dirs = [
            os.path.join(dest_dir, d)
            for d in os.listdir(dest_dir)
            if os.path.isdir(os.path.join(dest_dir, d))
        ]
        root_path = inner_dirs[0] if len(inner_dirs) == 1 else dest_dir

        return {
            "filename": f"{repo}-{branch}.zip",
            "filetype": "application/zip",
            "category": "archive-zip",
            "size": len(data),
            "uploaded_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "stored_path": root_path,
            "source": {
                "type": "github",
                "url": url,
                "owner": owner,
                "repo": repo,
                "branch": branch,
            },
        }


def categorize_file(path: str, mime_type: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".exe", ".dll") or "dosexec" in (mime_type or ""):
        return "binary-pe"
    if ext in (".so", ".elf") or "x-executable" in (mime_type or ""):
        return "binary-elf"
    if "mach" in (mime_type or ""):
        return "binary-mach-o"
    if ext == ".py":
        return "source-python"
    if ext == ".c":
        return "source-c"
    if ext == ".cpp":
        return "source-cpp"
    if ext == ".rs":
        return "source-rust"
    if ext == ".go":
        return "source-go"
    if ext == ".java":
        return "source-java"
    if ext == ".js":
        return "source-js"
    if ext == ".ts":
        return "source-ts"
    if ext == ".zip":
        return "archive-zip"
    if ext == ".tar":
        return "archive-tar"
    if ext in (".tgz", ".tar.gz"):
        return "archive-tgz"

    return "unknown"


# -------- Drag & Drop (Tk / tkinterdnd2) -------------------------------------


def parse_drop_data(data: str):
    # noqa: C901 - simple parser; refactor if growth demands
    r"""
    Convert tkdnd event data -> list of paths/URLs.
    Works with `{C:\My File.txt}` and plain tokens.
    Use a raw docstring so backslashes (Windows paths) don't create
    invalid escape sequence warnings.
    """
    if not data:
        return []

    # Quick URL path
    if data.startswith(("http://", "https://", "file://")):
        return [data]

    # Simple, explicit parser: tokens are either braced {like this} or
    # whitespace-separated. This avoids regex portability issues.
    out = []
    buf = []
    in_brace = False
    i = 0
    while i < len(data):
        ch = data[i]
        if in_brace:
            if ch == "}":
                token = "".join(buf)
                buf = []
                in_brace = False
                # strip file:// prefix if present
                if token.startswith("file://"):
                    token = token.replace("file://", "", 1)
                    # Windows file:// may have leading /C:/
                    if token.startswith("/") and len(token) > 3 and token[2] == ":":
                        token = token[1:]
                out.append(token)
            else:
                buf.append(ch)
        else:
            if ch == "{":
                # start braced token
                in_brace = True
                # flush any accumulated plain token
                if buf:
                    out.append("".join(buf))
                    buf = []
            elif ch.isspace():
                if buf:
                    out.append("".join(buf))
                    buf = []
            else:
                buf.append(ch)
        i += 1

    # final flush
    if buf:
        out.append("".join(buf))

    return out or [data]


def ensure_tkdnd_loaded(tk_interp) -> str:  # noqa: C901
    """
    Load the tkdnd Tcl package into 'tk_interp'.
    Returns the version string (e.g., '2.9.4') if available, else raises.
    """
    try:
        ver = tk_interp.eval("package require tkdnd")
        if ver:
            return ver
    except Exception:
        pass

    try:
        import tkinterdnd2 as _tkdnd  # type: ignore

    except Exception as e:
        raise RuntimeError(f"tkinterdnd2 not importable: {e}") from e

    base_dir = os.path.dirname(_tkdnd.__file__)

    candidates = []
    for root, _dirs, files in os.walk(base_dir):
        files_lower = [f.lower() for f in files]
        if "pkgindex.tcl" in files_lower or any(
            f.startswith("libtkdnd") and f.endswith(".dll") for f in files_lower
        ):
            candidates.append(root)

    def score(p):
        pl = p.replace("\\", "/").lower()
        win = any(pl.endswith(s) for s in ("win-x64", "win-x86", "win-arm64"))
        return (0 if win else 1, len(p))

    candidates.sort(key=score)

    # 1) try Tcl package path
    for root in candidates:
        try:
            tk_interp.eval(f"lappend auto_path {{{root}}}")
        except Exception:
            pass
    try:
        ver = tk_interp.eval("package require tkdnd")
        if ver:
            return ver
    except Exception:
        pass

    # 2) direct DLL load (Windows)
    dll_names = (
        "libtkdnd2.9.4.dll",
        "tkdnd2.9.4.dll",
        "libtkdnd2.9.3.dll",
        "tkdnd2.9.3.dll",
    )
    for root in candidates:
        for dll in dll_names:
            dll_path = os.path.join(root, dll)
            if os.path.isfile(dll_path):
                try:
                    tk_interp.eval(f"load {{{dll_path}}} tkdnd")
                    ver = tk_interp.eval("package provide tkdnd") or "loaded"
                    return ver
                except Exception:
                    pass

    raise RuntimeError(f"Could not load tkdnd; searched: {candidates}")


class FileDropController:
    """
    Glue between a Tk/CTk widget (target) and FileHandler.
    Creates a drop target and feeds meta to your callbacks.
    """

    def __init__(
        self,
        target_widget,
        file_handler: FileHandler,
        on_processed,
        on_status=None,
        on_border=None,
    ):
        self.widget = target_widget
        self.tk = target_widget.tk
        self.fh = file_handler
        self.on_processed = on_processed
        self.on_status = on_status or (lambda msg, error=False: None)
        self.on_border = on_border or (lambda color: None)

        # Import tkinterdnd2 lazily
        try:
            import tkinterdnd2 as _tkdnd  # type: ignore

            self.DND_FILES = _tkdnd.DND_FILES
            self.DND_TEXT = _tkdnd.DND_TEXT
        except Exception as e:
            raise RuntimeError(
                f"Drag & drop unavailable: tkinterdnd2 import failed: {e}"
            ) from e

        # Load tkdnd package into Tcl
        ver = ensure_tkdnd_loaded(self.tk)
        self.on_status(f"tkdnd {ver} loaded, DnD ready.")

        # Register as a drop target
        try:
            self.widget.drop_target_register(self.DND_FILES, self.DND_TEXT)
            self.widget.dnd_bind("<<DragEnter>>", self._on_drag_enter)
            self.widget.dnd_bind("<<DragLeave>>", self._on_drag_leave)
            self.widget.dnd_bind("<<Drop>>", self._on_drop)
        except Exception as e:
            raise RuntimeError(f"Drag & drop unavailable: {e}") from e

    # --- DnD event handlers
    def _on_drag_enter(self, _evt):
        try:
            self.on_border("#888")
        except Exception:
            pass

    def _on_drag_leave(self, _evt):
        try:
            self.on_border(None)
        except Exception:
            pass

    def _on_drop(self, event):
        data = getattr(event, "data", "")
        paths = parse_drop_data(data)
        for p in paths:
            try:
                meta = self.fh.handle_input(p)
                self.on_processed(meta)
            except Exception as e:
                self.on_status(str(e), error=True)


def open_file_picker(parent, file_handler: FileHandler, on_processed, on_status=None):
    """
    Open a file/directory picker dialog and feed selected paths to FileHandler.

    Expected usage (from UI):
        open_file_picker(self, self.fh, self._on_processed, self._set_status)

    - parent: a Tk/CTk widget used as the dialog parent
    - file_handler: instance of FileHandler
    - on_processed: callback(meta: dict) called for each successfully processed input
    - on_status: optional callback(message: str, error: bool=False)
    """
    try:
        from tkinter import filedialog
    except Exception as e:
        if on_status:
            on_status(f"File dialog unavailable: {e}", error=True)
        return

    # Attempt to allow selecting directories as well as files. Many Tk dialogs
    # don't support mixed selection; show a simple file selection first and
    # fall back to directory chooser if Cancelled.
    try:
        # Allow multiple selection of files
        root = parent
        # If parent is a CTk widget, try to use its tk root
        if hasattr(parent, "tk"):
            root = parent

        paths = filedialog.askopenfilenames(parent=root, title="Choose files")
        if not paths:
            # try directory chooser
            d = filedialog.askdirectory(parent=root, title="Choose folder")
            if d:
                paths = (d,)
        for p in paths:
            try:
                meta = file_handler.handle_input(p)
                on_processed(meta)
            except Exception as e:
                if on_status:
                    on_status(str(e), error=True)
    except Exception as e:
        if on_status:
            on_status(str(e), error=True)
