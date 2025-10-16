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
