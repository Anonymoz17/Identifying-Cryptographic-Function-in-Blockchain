# src/pages/dashboard.py
"""
CryptoScope Dashboard Page
--------------------------------
- Unified with ui.theme (no inline colors)
- Integrated analysis & export preview
- Scrollable on small screens
- Back to Landing button only
"""

import json
import time
from typing import Any, Dict, List, Optional
from tkinter import filedialog, messagebox

import customtkinter as ctk
from ui.theme import (
    BG, CARD_BG, BORDER, TEXT, MUTED,
    PRIMARY, PRIMARY_H, OUTLINE_BR, OUTLINE_H,
    HEADING_FONT, BODY_FONT
)

try:
    from ..file_handler import FileDropController, open_file_picker
except ImportError:
    from file_handler import FileDropController, open_file_picker


class DashboardPage(ctk.CTkScrollableFrame):
    """Dashboard — file upload, GitHub analysis, and JSON preview."""

    def __init__(self, master, switch_page, file_handler):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page
        self.fh = file_handler
        self._selected_meta: Optional[Dict[str, Any]] = None
        self._export_payload: Optional[Dict[str, Any]] = None

        # === Header ===
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(16, 0))

        title = ctk.CTkLabel(header, text="Dashboard", font=HEADING_FONT, text_color=TEXT)
        subtitle = ctk.CTkLabel(
            header,
            text="Upload files or analyze directly from GitHub repositories.",
            font=("Segoe UI", 12),
            text_color=MUTED,
        )
        title.grid(row=0, column=0, sticky="w")
        subtitle.grid(row=1, column=0, sticky="w")

        logout_btn = ctk.CTkButton(
            header,
            text="Logout",
            width=84,
            height=30,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: self.winfo_toplevel().logout(),
        )
        header.grid_columnconfigure(0, weight=1)
        logout_btn.grid(row=0, column=1, rowspan=2, sticky="e")

        # === Upload Section ===
        upload_card = ctk.CTkFrame(self, corner_radius=12, border_width=1,
                                   border_color=BORDER, fg_color=CARD_BG)
        upload_card.pack(fill="x", padx=22, pady=(16, 10))

        ctk.CTkLabel(upload_card, text="Analyze by Upload", font=HEADING_FONT, text_color=TEXT)\
            .grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(upload_card, text="Drop a source folder/file or choose from disk.",
                     font=BODY_FONT, text_color=MUTED)\
            .grid(row=1, column=0, sticky="w", padx=16)

        body = ctk.CTkFrame(upload_card, fg_color="transparent")
        body.grid(row=2, column=0, sticky="ew", padx=16, pady=(6, 16))
        body.grid_columnconfigure(1, weight=1)

        self.drop_area = ctk.CTkFrame(
            body, width=480, height=150,
            corner_radius=10, border_width=1, border_color=BORDER, fg_color=BG
        )
        self.drop_area.grid(row=0, column=0, sticky="w")
        self.drop_area.grid_propagate(False)

        self.drop_label = ctk.CTkLabel(self.drop_area, text="Drag & drop here",
                                       font=("Segoe UI", 14, "bold"), text_color=TEXT)
        self.drop_label.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(self.drop_area, text="Supported: local files or GitHub URLs",
                     font=("Segoe UI", 11), text_color=MUTED)\
            .place(relx=0.5, rely=0.5, y=22, anchor="center")

        ctk.CTkButton(
            body, text="Choose files…",
            width=150, height=36,
            corner_radius=8,
            fg_color=PRIMARY, hover_color=PRIMARY_H,
            text_color=BG,
            command=lambda: open_file_picker(
                self, self.fh, self._on_processed, self._set_status
            )
        ).grid(row=0, column=1, padx=(12, 0), sticky="e")

        # === Divider ===
        divider = ctk.CTkFrame(self, fg_color="transparent")
        divider.pack(fill="x", padx=22, pady=(10, 8))
        ctk.CTkFrame(divider, height=1, fg_color=BORDER)\
            .pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkLabel(divider, text="or", font=BODY_FONT, text_color=MUTED)\
            .pack(side="left")
        ctk.CTkFrame(divider, height=1, fg_color=BORDER)\
            .pack(side="left", fill="x", expand=True, padx=(10, 0))

        # === GitHub Section ===
        gh_card = ctk.CTkFrame(self, corner_radius=12, border_width=1,
                               border_color=BORDER, fg_color=CARD_BG)
        gh_card.pack(fill="x", padx=22, pady=(4, 8))

        ctk.CTkLabel(gh_card, text="Analyze from GitHub repo URL",
                     font=HEADING_FONT, text_color=TEXT)\
            .grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(gh_card, text="Example: https://github.com/bitcoin/bitcoin",
                     font=BODY_FONT, text_color=MUTED)\
            .grid(row=1, column=0, sticky="w", padx=16)

        gh_row = ctk.CTkFrame(gh_card, fg_color="transparent")
        gh_row.grid(row=2, column=0, sticky="ew", padx=16, pady=(4, 16))
        gh_card.grid_columnconfigure(0, weight=1)

        self.gh_entry = ctk.CTkEntry(
            gh_row, placeholder_text="Paste GitHub URL…",
            height=36, corner_radius=8,
            fg_color=BG, border_color=BORDER,
            border_width=1, text_color=TEXT
        )
        self.gh_entry.pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            gh_row, text="Analyze",
            width=120, height=36,
            corner_radius=8,
            fg_color=PRIMARY, hover_color=PRIMARY_H,
            text_color=BG,
            command=self._on_github_analyze
        ).pack(side="left", padx=(12, 0))

        # === Details Box ===
        self.details = ctk.CTkFrame(
            self, corner_radius=12, border_width=1,
            border_color=BORDER, fg_color=CARD_BG
        )
        self.details.pack(fill="x", padx=22, pady=(10, 6))
        self._build_details_grid()

        # === JSON Preview ===
        self.results_card = ctk.CTkFrame(
            self, corner_radius=12, border_width=1,
            border_color=BORDER, fg_color=CARD_BG
        )
        self.results_card.pack(fill="both", expand=True, padx=22, pady=(6, 10))

        ctk.CTkLabel(self.results_card, text="Analysis Results / Export Preview",
                     font=HEADING_FONT, text_color=TEXT)\
            .grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))

        self.preview = ctk.CTkTextbox(
            self.results_card, corner_radius=10,
            fg_color=BG, text_color=TEXT,
            border_color=BORDER, border_width=1,
            wrap="none", height=220
        )
        self.preview.grid(row=1, column=0, sticky="nsew", padx=16, pady=(4, 12))
        self.results_card.grid_rowconfigure(1, weight=1)
        self.results_card.grid_columnconfigure(0, weight=1)

        btn_row = ctk.CTkFrame(self.results_card, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="e", padx=16, pady=(0, 14))
        ctk.CTkButton(
            btn_row, text="Export JSON…",
            height=34, corner_radius=8,
            fg_color=PRIMARY, hover_color=PRIMARY_H,
            text_color=BG,
            command=self._export_json_from_preview
        ).pack(side="right")

        # === Footer ===
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=22, pady=(8, 16))

        self.status = ctk.CTkLabel(footer, text="", font=BODY_FONT, text_color=TEXT)
        self.status.pack(side="left")

        ctk.CTkButton(
            footer, text="⬅ Back to Landing",
            height=36, corner_radius=8,
            fg_color="transparent",
            border_width=1, border_color=OUTLINE_BR,
            hover_color=OUTLINE_H, text_color=TEXT,
            command=lambda: self.switch_page("landing")
        ).pack(side="right")

        # DnD Controller
        try:
            self._dnd = FileDropController(
                target_widget=self.drop_area,
                file_handler=self.fh,
                on_processed=self._on_processed,
                on_status=self._set_status,
                on_border=self._set_drop_border,
            )
        except Exception as e:
            self._set_status(f"Drag & drop unavailable: {e}", True)

    # === Helper Methods ===
    def _set_drop_border(self, color: str):
        try:
            self.drop_area.configure(border_color=color)
        except Exception:
            pass

    def _set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, text_color=("red" if error else TEXT))

    def _build_details_grid(self):
        """Display file metadata in 2-column layout."""
        grid = self.details
        fields = ["Name", "Type", "Size", "Added", "Path"]
        self._detail_labels = {}
        for i, key in enumerate(fields):
            label = ctk.CTkLabel(grid, text=f"{key}:", font=BODY_FONT, text_color=MUTED)
            value = ctk.CTkLabel(grid, text="—", font=BODY_FONT, text_color=TEXT)
            label.grid(row=i // 2, column=(i % 2) * 2, sticky="e", padx=(14, 4), pady=(6, 4))
            value.grid(row=i // 2, column=(i % 2) * 2 + 1, sticky="w", padx=(0, 14), pady=(6, 4))
            self._detail_labels[key.lower()] = value

    # === Processing ===
    def _on_processed(self, meta: Dict[str, Any]):
        self._selected_meta = meta
        self._show_details(meta)
        self._set_status(f"Loaded: {meta.get('filename') or meta.get('url') or 'item'}")

        try:
            result = self._run_analysis(meta)
            self._export_payload = self._build_export_payload([meta], result)
            self._show_export_preview(self._export_payload)
        except Exception as e:
            self._set_status(f"Analysis failed: {e}", True)

    def _on_github_analyze(self):
        url = (self.gh_entry.get() or "").strip()
        if not url:
            self._set_status("Enter a GitHub URL.", True)
            return
        meta = {
            "filename": url.split("/")[-1] or "repo",
            "filetype": "text/uri-list",
            "category": "github-url",
            "url": url,
        }
        self._on_processed(meta)

    def _run_analysis(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        path = meta.get("stored_path") or meta.get("url")
        if not path:
            return {"summary": "No file path.", "findings": []}
        self._set_status("Running analysis…")
        self.update_idletasks()
        time.sleep(1)
        fake = {"file": meta.get("filename"), "detected_crypto": ["AES"], "notes": "Placeholder result."}
        return {"summary": "Analysis complete.", "findings": [fake]}

    def _show_details(self, meta: Dict[str, Any]):
        self._detail_labels["name"].configure(text=meta.get("filename", "—"))
        self._detail_labels["type"].configure(text=meta.get("filetype", meta.get("category", "—")))
        self._detail_labels["size"].configure(text=str(meta.get("size", "—")))
        self._detail_labels["added"].configure(text=meta.get("uploaded_at", "—"))
        self._detail_labels["path"].configure(text=meta.get("stored_path", meta.get("url", "—")))

    def _build_export_payload(self, metas, analysis_result):
        return {
            "summary": analysis_result.get("summary", ""),
            "findings": analysis_result.get("findings", []),
            "inputs": [
                {k: m.get(k) for k in ("filename", "filetype", "category", "size", "uploaded_at", "stored_path")}
                for m in metas
            ],
        }

    def _show_export_preview(self, payload):
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", json.dumps(payload, indent=2))
        self.preview.configure(state="disabled")
        self._set_status("Analysis finished successfully. Preview updated.")

    def _export_json_from_preview(self):
        if not self._export_payload:
            self._set_status("Nothing to export yet.", True)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All Files", "*.*")],
            title="Save export JSON",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._export_payload, f, indent=2)
        self._set_status(f"Exported to: {path}")
        messagebox.showinfo("Export JSON", f"Saved:\n{path}")
