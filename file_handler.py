import os
import re
import glob
import datetime
import tempfile
import shutil
import requests
import mimetypes

# --- Optional: libmagic for reliable MIME ---
try:
    import magic  # python-magic or python-magic-bin
    _HAS_MAGIC = True
except Exception:
    _HAS_MAGIC = False

# --- Optional: OS-level drag & drop via tkinterdnd2 ---
try:
    from tkinterdnd2 import DND_FILES, DND_TEXT
    HAS_DND = True
except Exception:
    DND_FILES = DND_TEXT = None
    HAS_DND = False


class FileHandler:
    """Save uploads and detect type/category for local files or GitHub URLs."""

    def __init__(self, upload_dir="uploads"):
        self.upload_dir = upload_dir
        os.makedirs(upload_dir, exist_ok=True)

    def handle_input(self, input_path: str) -> dict:
        """Decides whether input is a local file or a GitHub URL and returns metadata."""
        input_path = input_path.strip()
        if input_path.startswith(("http://", "https://")):
            return self._handle_github(input_path)
        if os.path.isfile(input_path):
            return self._handle_file(input_path)
        raise ValueError(f"Unsupported input: {input_path}")

    def _handle_file(self, filepath: str) -> dict:
        """Copy file into uploads/ and detect MIME + category."""
        filename = os.path.basename(filepath)

        # Copy to uploads (avoid collisions)
        stored_path = os.path.join(self.upload_dir, filename)
        base, ext = os.path.splitext(stored_path)
        i = 1
        while os.path.exists(stored_path):
            stored_path = f"{base}({i}){ext}"
            i += 1
        shutil.copy2(filepath, stored_path)

        # Detect MIME
        if _HAS_MAGIC:
            try:
                filetype = magic.from_file(stored_path, mime=True)
            except Exception:
                filetype = mimetypes.guess_type(stored_path)[0] or "application/octet-stream"
        else:
            filetype = mimetypes.guess_type(stored_path)[0] or "application/octet-stream"

        category = self._categorize_file(stored_path, filetype)

        return {
            "filename": os.path.basename(stored_path),
            "filetype": filetype,
            "category": category,
            "size": os.path.getsize(stored_path),
            "uploaded_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "stored_path": stored_path,
        }

    def _categorize_file(self, filepath: str, mime_type: str) -> str:
        """Map extension/MIME to a normalized category string."""
        ext = os.path.splitext(filepath)[1].lower()

        # Compiled Binaries
        if ext in [".elf", ".so", ".a"] or "x-executable" in mime_type:
            return "binary-elf"
        if ext in [".exe", ".dll", ".lib"] or "application/x-dosexec" in mime_type or "dosexec" in mime_type:
            return "binary-pe"
        if ext in [".dylib"] or "mach" in mime_type:
            return "binary-mach-o"

        # Source Code
        if ext == ".c": return "source-c"
        if ext == ".cpp": return "source-cpp"
        if ext == ".go": return "source-go"
        if ext == ".rs": return "source-rust"
        if ext == ".py": return "source-python"
        if ext in [".js", ".ts"]: return "source-js"
        if ext == ".java": return "source-java"

        # Archives
        if ext == ".zip": return "archive-zip"

        return "unknown"

    def _handle_github(self, url: str) -> dict:
        """Download main/master branch zip into uploads/ and return metadata."""
        repo_name = url.rstrip("/").split("/")[-1]
        candidates = [
            f"{url.rstrip('/')}/archive/refs/heads/main.zip",
            f"{url.rstrip('/')}/archive/refs/heads/master.zip",
        ]
        content = None
        for zip_url in candidates:
            r = requests.get(zip_url, timeout=30)
            if r.status_code == 200:
                content = r.content
                break
        if content is None:
            raise ValueError(f"Could not download GitHub repo (main/master): {url}")

        fd, tmpfile = tempfile.mkstemp(suffix=".zip", dir=self.upload_dir)
        with os.fdopen(fd, "wb") as f:
            f.write(content)

        return {
            "repo_url": url,
            "repo_name": repo_name,
            "stored_path": tmpfile,
            "category": "github-repo",
            "downloaded_at": datetime.datetime.now().isoformat(timespec="seconds"),
        }


# ------------ Drag & Drop + Picker Integration (UI-agnostic hooks) ------------

def parse_drop_data(data: str):
    """
    Robustly parse tkdnd data strings into a list of files/URLs.
    Handles:
      - "{C:\\My File.exe}" "{D:\\another one.dll}"
      - /home/user/a.out /home/user/b.out
      - file:///C:/path/with/spaces.bin
      - http(s) URLs
    """
    if not data:
        return []
    data = data.strip()

    # Pure URL text?
    if data.startswith("http://") or data.startswith("https://"):
        return [data]

    parts = re.findall(r"\{([^}]*)\}|([^\s]+)", data)
    items = []
    for brace, plain in parts:
        token = brace or plain
        if not token:
            continue
        if token.startswith("file://"):
            token = token.replace("file://", "", 1)
            # Windows: /C:/... -> C:/...
            if token.startswith("/") and len(token) > 3 and token[2] == ":":
                token = token[1:]
        items.append(token)
    return items or [data]


class FileDropController:
    """
    Encapsulates DnD bindings and file picker, calling FileHandler and
    UI callbacks you supply.

    Usage (inside your UI):
        controller = FileDropController(
            target_widget=self.dnd,
            file_handler=self.file_handler,
            on_processed=self._add_result_row,    # called with meta dict
            on_status=self._set_status,           # called with (msg, error=False)
            on_border=self._set_border            # called with (color_str)
        )
        # Optional fallback button:
        # some_button.configure(command=controller.open_file_dialog)
    """
    def __init__(self, target_widget, file_handler: FileHandler,
                 on_processed, on_status=None, on_border=None):
        self.widget = target_widget
        self.fh = file_handler
        self.on_processed = on_processed
        self.on_status = on_status or (lambda msg, error=False: None)
        self.on_border = on_border or (lambda color: None)

        if HAS_DND:
            try:
                self._ensure_tkdnd_loaded()              # load tkdnd once
                self.widget.drop_target_register(DND_FILES, DND_TEXT)
                self.widget.dnd_bind("<<DragEnter>>", self._on_drag_enter)
                self.widget.dnd_bind("<<DragLeave>>", self._on_drag_leave)
                self.widget.dnd_bind("<<Drop>>", self._on_drop)
            except Exception as e:
                # Surface the error so the UI can fall back to a file picker
                raise RuntimeError(f"Drag & drop unavailable: {e}")

    def _ensure_tkdnd_loaded(self):
        """Find tkdnd in the tkinterdnd2 package and load it into Tcl."""
        interp = self.widget.tk
        # If already available, nothing to do.
        try:
            interp.eval('package require tkdnd')
            return
        except Exception:
            pass

        import tkinterdnd2 as _tkdnd
        base_dir = os.path.dirname(_tkdnd.__file__)

        # Search any folder under tkinterdnd2 that contains pkgIndex.tcl
        candidates = [base_dir]
        candidates.extend(glob.glob(os.path.join(base_dir, 'tkdnd*')))
        # Walk recursively in case of different layouts
        for root, _dirs, files in os.walk(base_dir):
            if 'pkgIndex.tcl' in files and root not in candidates:
                candidates.append(root)

        found_any = False
        for p in candidates:
            if os.path.isfile(os.path.join(p, 'pkgIndex.tcl')):
                interp.eval(f'lappend auto_path {{{p}}}')
                found_any = True

        try:
            interp.eval('package require tkdnd')
        except Exception as e:
            details = f"searched: {', '.join(candidates)}"
            if not found_any:
                details += " (no pkgIndex.tcl found)"
            raise RuntimeError(f"could not load tkdnd; {details}") from e

    # ---- Public: file dialog fallback ----
    def open_file_dialog(self):
        from tkinter import filedialog
        paths = filedialog.askopenfilenames(title="Select files to upload")
        for p in paths:
            self._handle_one(p)

    # ---- Internal DnD handlers ----
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

    # ---- Core processing ----
    def _handle_one(self, item: str):
        try:
            meta = self.fh.handle_input(item)
            self.on_processed(meta)
            shown = meta.get("filename") or meta.get("repo_name") or os.path.basename(meta.get("stored_path", ""))
            self.on_status(f"Loaded: {shown}")
        except Exception as e:
            self.on_status(f"Error: {e}", error=True)


def open_file_picker(parent_widget, file_handler: FileHandler, on_processed, on_status=None):
    """Pure file dialog fallback that never touches tkdnd."""
    if on_status is None:
        on_status = lambda msg, error=False: None
    from tkinter import filedialog
    paths = filedialog.askopenfilenames(parent=parent_widget, title="Select files to upload")
    for p in paths or []:
        try:
            meta = file_handler.handle_input(p)
            on_processed(meta)
            shown = meta.get("filename") or meta.get("repo_name") or os.path.basename(meta.get("stored_path", ""))
            on_status(f"Loaded: {shown}")
        except Exception as e:
            on_status(f"Error: {e}", error=True)
