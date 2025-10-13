import os
import re
import glob
import shutil
import datetime
import tempfile
import mimetypes


try:
    import magic  # python-magic / python-magic-bin
    _HAS_MAGIC = True
except Exception:
    _HAS_MAGIC = False


# -------- Core file handling --------------------------------------------------

class FileHandler:
    """Copy uploads into ./uploads and detect basic metadata."""
    def __init__(self, upload_dir="uploads"):
        self.upload_dir = upload_dir
        os.makedirs(upload_dir, exist_ok=True)

    #handle file input errors
    def handle_input(self, input_path: str) -> dict:
        input_path = input_path.strip()
        if input_path.startswith(("http://", "https://")):
            raise ValueError("HTTP/HTTPS not implemented in this minimal sample.")

        if os.path.isfile(input_path):
            return self._handle_file(input_path)

        raise ValueError(f"Unsupported input: {input_path}")

    def _handle_file(self, filepath: str) -> dict:
        filename = os.path.basename(filepath)


        stored_path = os.path.join(self.upload_dir, filename)
        base, ext = os.path.splitext(stored_path)
        i = 1
        while os.path.exists(stored_path):
            stored_path = f"{base}({i}){ext}"
            i += 1
        shutil.copy2(filepath, stored_path)

        # MIME
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
    if ext == ".py": return "source-python"
    if ext == ".c":  return "source-c"
    if ext == ".cpp": return "source-cpp"
    if ext == ".rs": return "source-rust"
    if ext == ".go": return "source-go"
    if ext == ".java": return "source-java"

    # Archives
    if ext == ".zip": return "archive-zip"

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
        import tkinterdnd2 as _tkdnd
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
            import tkinterdnd2 as _tkdnd
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
