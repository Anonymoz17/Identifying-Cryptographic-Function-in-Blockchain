# file_handler.py
import os
import re
import shutil
import datetime
import mimetypes
import urllib.request
import zipfile
import io
import time

# Optional MIME detector (python-magic / python-magic-bin)
try:
    import magic  # type: ignore
    _HAS_MAGIC = True
except Exception:
    _HAS_MAGIC = False


# -------- Core file handling --------------------------------------------------

class FileHandler:
    """
    Handles uploads into ./uploads and detects basic metadata.
    Now also supports GitHub repo URLs:
      - https://github.com/<owner>/<repo>
      - https://github.com/<owner>/<repo>/tree/<branch>
      - https://github.com/<owner>/<repo>@<branch>
    Downloads ZIP from codeload.github.com and extracts to uploads/.
    """
    def __init__(self, upload_dir="uploads"):
        self.upload_dir = upload_dir
        os.makedirs(upload_dir, exist_ok=True)

    def handle_input(self, input_path: str) -> dict:
        """
        Accepts:
          - Local files: absolute/relative path to a file.
          - GitHub URLs (see formats above).
        Returns a metadata dict including:
          - filename, filetype (MIME), category, size, uploaded_at, stored_path
          - source info for GitHub (owner/repo/branch)
        """
        input_path = (input_path or "").strip()
        if not input_path:
            raise ValueError("Empty input.")

        # --- GitHub repo URL support ---
        if input_path.startswith(("http://", "https://")):
            if "github.com/" in input_path:
                return self._handle_github_repo(input_path)
            raise ValueError("Only GitHub repo URLs are supported for HTTP(S) sources in this app.")

        # Local file path
        if os.path.isfile(input_path):
            return self._handle_file(input_path)

        raise ValueError(f"Unsupported input: {input_path}")

    # ---- Local file path handling -------------------------------------------
    def _handle_file(self, filepath: str) -> dict:
        filename = os.path.basename(filepath)

        # Ensure unique target name inside uploads/
        stored_path = os.path.join(self.upload_dir, filename)
        base, ext = os.path.splitext(stored_path)
        i = 1
        while os.path.exists(stored_path):
            stored_path = f"{base}({i}){ext}"
            i += 1

        shutil.copy2(filepath, stored_path)

        # MIME type detection
        if _HAS_MAGIC:
            try:
                mime = magic.from_file(stored_path, mime=True)
            except Exception:
                mime = mimetypes.guess_type(stored_path)[0] or "application/octet-stream"
        else:
            mime = mimetypes.guess_type(stored_path)[0] or "application/octet-stream"

        category = categorize_file(stored_path, mime)

        return {
            "filename": os.path.basename(stored_path),
            "filetype": mime,
            "category": category,
            "size": os.path.getsize(stored_path),
            "uploaded_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "stored_path": stored_path,
        }

    # ---- GitHub repo URL handling -------------------------------------------
    def _handle_github_repo(self, url: str) -> dict:
        """
        Downloads a GitHub repository ZIP for the selected branch and extracts it.

        Supported URL forms:
          - https://github.com/<owner>/<repo>
          - https://github.com/<owner>/<repo>/tree/<branch>
          - https://github.com/<owner>/<repo>@<branch>

        Returns metadata with 'stored_path' pointing to the extracted folder.
        """
        import re

        m = re.search(r"github\.com/([^/]+)/([^/]+)", url)
        if not m:
            raise ValueError("Invalid GitHub URL.")
        owner = m.group(1)
        repo = m.group(2).replace(".git", "")

        # Branch detection
        branch = "main"
        m2 = re.search(r"/tree/([^/]+)", url)
        if m2:
            branch = m2.group(1)
        m3 = re.search(r"@([A-Za-z0-9._\-\/]+)$", url)
        if m3:
            branch = m3.group(1)

        # Build codeload URL for ZIP
        # Note: This fetches the whole branch. (Subdir filtering can be added later if needed.)
        zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"

        # Download ZIP (in-memory)
        try:
            with urllib.request.urlopen(zip_url) as resp:
                data = resp.read()
        except Exception as e:
            raise ValueError(f"Failed to download repo ZIP: {e}")

        # Extract to uploads/<repo>-<branch>-<ts>/
        ts = int(time.time())
        dest_dir = os.path.join(self.upload_dir, f"{repo}-{branch}-{ts}")
        os.makedirs(dest_dir, exist_ok=True)

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(dest_dir)
        except Exception as e:
            raise ValueError(f"Failed to extract ZIP: {e}")

        # GitHub zips usually unpack to a single top-level folder: repo-branch/
        inner_dirs = [os.path.join(dest_dir, d) for d in os.listdir(dest_dir) if os.path.isdir(os.path.join(dest_dir, d))]
        root_path = inner_dirs[0] if len(inner_dirs) == 1 else dest_dir

        return {
            "filename": f"{repo}-{branch}.zip",
            "filetype": "application/zip",
            "category": "archive-zip",
            "size": len(data),
            "uploaded_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "stored_path": root_path,  # <-- folder your scanner should walk
            "source": {"type": "github", "url": url, "owner": owner, "repo": repo, "branch": branch},
        }


def categorize_file(path: str, mime_type: str) -> str:
    ext = os.path.splitext(path)[1].lower()

    # Binaries
    if ext in (".exe", ".dll") or "dosexec" in (mime_type or ""):
        return "binary-pe"
    if ext in (".so", ".elf") or "x-executable" in (mime_type or ""):
        return "binary-elf"
    if "mach" in (mime_type or ""):
        return "binary-mach-o"

    # Source
    if ext == ".py":   return "source-python"
    if ext == ".c":    return "source-c"
    if ext == ".cpp":  return "source-cpp"
    if ext == ".rs":   return "source-rust"
    if ext == ".go":   return "source-go"
    if ext == ".java": return "source-java"
    if ext == ".js":   return "source-js"
    if ext == ".ts":   return "source-ts"

    # Archives
    if ext == ".zip":  return "archive-zip"
    if ext == ".tar":  return "archive-tar"
    if ext in (".tgz", ".tar.gz"): return "archive-tgz"

    return "unknown"


# -------- Drag & Drop (Tk / tkinterdnd2) -------------------------------------

def parse_drop_data(data: str):
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

    parts = re.findall(r"\{([^}]*)\}|([^\s]+)", data)
    out = []
    for brace, plain in parts:
        token = brace or plain
        if token.startswith("file://"):
            token = token.replace("file://", "", 1)
            if token.startswith("/") and len(token) > 3 and token[2] == ":":
                token = token[1:]
        out.append(token)
    return out or [data]


def ensure_tkdnd_loaded(tk_interp) -> str:
    """
    Load the tkdnd Tcl package into 'tk_interp'.
    Returns the version string (e.g., '2.9.4') if available, else raises.
    """
    try:
        ver = tk_interp.eval('package require tkdnd')
        if ver:
            return ver
    except Exception:
        pass

    try:
        import tkinterdnd2 as _tkdnd  # type: ignore
    except Exception as e:
        raise RuntimeError(f"tkinterdnd2 not importable: {e}")

    base_dir = os.path.dirname(_tkdnd.__file__)

    candidates = []
    for root, _dirs, files in os.walk(base_dir):
        files_lower = [f.lower() for f in files]
        if "pkgindex.tcl" in files_lower or any(f.startswith("libtkdnd") and f.endswith(".dll") for f in files_lower):
            candidates.append(root)

    def score(p):
        pl = p.replace("\\", "/").lower()
        win = any(pl.endswith(s) for s in ("win-x64", "win-x86", "win-arm64"))
        return (0 if win else 1, len(p))

    candidates.sort(key=score)

    # 1) try Tcl package path
    for root in candidates:
        try:
            tk_interp.eval(f'lappend auto_path {{{root}}}')
        except Exception:
            pass
    try:
        ver = tk_interp.eval('package require tkdnd')
        if ver:
            return ver
    except Exception:
        pass

    # 2) direct DLL load (Windows)
    dll_names = ("libtkdnd2.9.4.dll", "tkdnd2.9.4.dll", "libtkdnd2.9.3.dll", "tkdnd2.9.3.dll")
    for root in candidates:
        for dll in dll_names:
            dll_path = os.path.join(root, dll)
            if os.path.isfile(dll_path):
                try:
                    tk_interp.eval(f'load {{{dll_path}}} tkdnd')
                    ver = tk_interp.eval('package provide tkdnd') or "loaded"
                    return ver
                except Exception:
                    pass

    raise RuntimeError(f"Could not load tkdnd; searched: {candidates}")


class FileDropController:
    """
    Glue between a Tk/CTk widget (target) and FileHandler.
    Creates a drop target and feeds meta to your callbacks.
    """

    def __init__(self, target_widget, file_handler: FileHandler,
                 on_processed, on_status=None, on_border=None):
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
            raise RuntimeError(f"Drag & drop unavailable: tkinterdnd2 import failed: {e}")

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
            raise RuntimeError(f"Drag & drop unavailable: {e}")

    # --- DnD event handlers
    def _on_drag_enter(self, _evt):
        self.on_border("#1a73e8")

    def _on_drag_leave(self, _evt):
        self.on_border("#9aa0a6")

    def _on_drop(self, evt):
        self.on_border("#34a853")
        items = parse_drop_data(evt.data)
        if not items:
            self.on_status("Nothing dropped.", error=True)
            self.on_border("#9aa0a6")
            return
        for item in items:
            self._handle_one(item)
        try:
            self.widget.after(250, lambda: self.on_border("#9aa0a6"))
        except Exception:
            self.on_border("#9aa0a6")

    def _handle_one(self, item: str):
        try:
            meta = self.fh.handle_input(item)
            self.on_processed(meta)
            shown = meta.get("filename") or os.path.basename(meta.get("stored_path", "")) or item
            self.on_status(f"Loaded: {shown}")
        except Exception as e:
            self.on_status(f"Error: {e}", error=True)


# Plain file dialog fallback (no tkdnd required)
def open_file_picker(parent_widget, file_handler: FileHandler, on_processed, on_status=None):
    from tkinter import filedialog
    on_status = on_status or (lambda msg, error=False: None)
    paths = filedialog.askopenfilenames(parent=parent_widget, title="Select files to upload")
    for p in paths or []:
        try:
            meta = file_handler.handle_input(p)
            on_processed(meta)
            shown = meta.get("filename") or os.path.basename(meta.get("stored_path", "")) or p
            on_status(f"Loaded: {shown}")
        except Exception as e:
            on_status(f"Error: {e}", error=True)
