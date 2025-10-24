# src/pages/dashboard.py
from typing import Any, Dict, Optional, List
import json
import time
from tkinter import messagebox, filedialog
import customtkinter as ctk

try:
    from ..file_handler import FileDropController, open_file_picker
except ImportError:
    from file_handler import FileDropController, open_file_picker

# === Landing Theme Colors ===
BG = "#0D1117"        # Background
CARD_BG = "#161B22"   # Card background
BORDER = "#21262D"    # Border
TEXT = "#C9D1D9"      # Primary text
MUTED = "#8B949E"     # Muted text
PRIMARY = "#2EA043"   # Accent green
PRIMARY_H = "#238636" # Hover accent
OUTLINE_BR = "#30363D"
OUTLINE_H = "#2D333B"


class DashboardPage(ctk.CTkFrame):
    """Dashboard — Landing theme + 2-column file details grid."""

    def __init__(self, master, switch_page, file_handler):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page
        self.fh = file_handler
        self._selected_meta: Optional[Dict[str, Any]] = None
        self._export_payload: Optional[Dict[str, Any]] = None

        # ---- Layout ----
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Scrollable area
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 60))
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        # Sticky footer
        self.footer = ctk.CTkFrame(self, fg_color="#161B22", height=56)
        self.footer.grid(row=1, column=0, sticky="ew")
        self.footer.grid_columnconfigure(0, weight=1)

        # ---------- Header ----------
        header = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(16, 0))

        title = ctk.CTkLabel(
            header, text="Dashboard", font=("Segoe UI", 28, "bold"), text_color=TEXT
        )
        subtitle = ctk.CTkLabel(
            header,
            text="Upload or analyze your project. Results appear automatically below.",
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

        # ---------- Upload Area ----------
        upload_card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        upload_card.pack(fill="x", padx=22, pady=(16, 10))

        ctk.CTkLabel(
            upload_card,
            text="Analyze by Upload",
            font=("Segoe UI", 18, "bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(
            upload_card,
            text="Drag & drop files here or choose from disk.",
            font=("Segoe UI", 12),
            text_color=MUTED,
        ).grid(row=1, column=0, sticky="w", padx=16)

        body = ctk.CTkFrame(upload_card, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=16, pady=(6, 16))
        upload_card.grid_columnconfigure(0, weight=1)

        # Drag & Drop zone
        self.drop_area = ctk.CTkFrame(
            body,
            width=480,
            height=150,
            corner_radius=10,
            border_width=1,
            border_color=BORDER,
            fg_color="#0D1117",
        )
        self.drop_area.grid(row=0, column=0, sticky="nsew")
        self.drop_area.grid_propagate(False)

        self.drop_label = ctk.CTkLabel(
            self.drop_area,
            text="🡇  Drag & Drop Files",
            font=("Segoe UI", 14, "bold"),
            text_color=TEXT,
        )
        self.drop_label.place(relx=0.5, rely=0.45, anchor="center")

        ctk.CTkLabel(
            self.drop_area,
            text="Supported: local source files or GitHub repositories",
            font=("Segoe UI", 11),
            text_color=MUTED,
        ).place(relx=0.5, rely=0.65, anchor="center")

        pick_btn = ctk.CTkButton(
            body,
            text="Choose Files…",
            width=150,
            height=36,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=lambda: open_file_picker(
                self, self.fh, self._on_processed, self._set_status
            ),
        )
        pick_btn.grid(row=0, column=1, padx=(12, 0), sticky="e")
        body.grid_columnconfigure(0, weight=1)

        # ---------- GitHub Area ----------
        gh_card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        gh_card.pack(fill="x", padx=22, pady=(6, 8))

        ctk.CTkLabel(
            gh_card,
            text="Analyze from GitHub Repository",
            font=("Segoe UI", 16, "bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 2))
        ctk.CTkLabel(
            gh_card,
            text="Example: https://github.com/bitcoin/bitcoin",
            font=("Segoe UI", 11),
            text_color=MUTED,
        ).grid(row=1, column=0, sticky="w", padx=16)

        gh_row = ctk.CTkFrame(gh_card, fg_color="transparent")
        gh_row.grid(row=2, column=0, sticky="ew", padx=16, pady=(6, 16))
        gh_card.grid_columnconfigure(0, weight=1)

        self.gh_entry = ctk.CTkEntry(
            gh_row,
            placeholder_text="Paste GitHub URL…",
            height=36,
            corner_radius=8,
            fg_color="#0D1117",
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
        )
        self.gh_entry.pack(side="left", fill="x", expand=True)

        gh_btn = ctk.CTkButton(
            gh_row,
            text="Analyze",
            width=120,
            height=36,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=self._on_github_analyze,
        )
        gh_btn.pack(side="left", padx=(12, 0))

        # ---------- FILE DETAILS (2-column grid) ----------
        self.details_card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        self.details_card.pack(fill="x", padx=22, pady=(10, 8))
        ctk.CTkLabel(
            self.details_card,
            text="File Details",
            font=("Segoe UI", 16, "bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 8))

        # Two-column layout
        grid = ctk.CTkFrame(self.details_card, fg_color="transparent")
        grid.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=16, pady=(0, 12))
        for i in range(2):
            grid.grid_columnconfigure(i, weight=1)

        def add_detail(row, col, label_text, var_name):
            frame = ctk.CTkFrame(grid, fg_color="#0D1117", corner_radius=8)
            frame.grid(row=row, column=col, sticky="ew", padx=6, pady=4)
            label = ctk.CTkLabel(
                frame, text=label_text, font=("Segoe UI", 10, "bold"), text_color=MUTED
            )
            label.pack(anchor="w", padx=10, pady=(4, 0))
            value = ctk.CTkLabel(
                frame, text="—", font=("Segoe UI", 11), text_color=TEXT
            )
            value.pack(anchor="w", padx=10, pady=(0, 6))
            setattr(self, var_name, value)

        add_detail(0, 0, "Name", "dv_name")
        add_detail(0, 1, "Type", "dv_type")
        add_detail(1, 0, "Size", "dv_size")
        add_detail(1, 1, "Added", "dv_added")
        add_detail(2, 0, "Path", "dv_path")

        # ---------- RESULTS ----------
        self.results_card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        self.results_card.pack(fill="both", expand=True, padx=22, pady=(10, 20))

        ctk.CTkLabel(
            self.results_card,
            text="Analysis Results / Export Preview",
            font=("Segoe UI", 16, "bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))

        self.preview = ctk.CTkTextbox(
            self.results_card,
            corner_radius=8,
            fg_color="#0D1117",
            text_color="#D1D5DB",
            border_color=BORDER,
            border_width=1,
            wrap="none",
            height=240,
        )
        self.preview.grid(row=1, column=0, sticky="nsew", padx=16, pady=(4, 12))
        self.results_card.grid_rowconfigure(1, weight=1)
        self.results_card.grid_columnconfigure(0, weight=1)

        btn_row = ctk.CTkFrame(self.results_card, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="e", padx=16, pady=(0, 14))

        self.export_btn = ctk.CTkButton(
            btn_row,
            text="Export JSON…",
            width=140,
            height=34,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=self._export_json_from_preview,
        )
        self.export_btn.pack(side="right")

        # ---------- FOOTER ----------
        self.status = ctk.CTkLabel(
            self.footer, text="", font=("Segoe UI", 11), text_color=TEXT
        )
        self.status.pack(side="left", padx=20)

        self.back_btn = ctk.CTkButton(
            self.footer,
            text="⬅ Back to Landing",
            width=160,
            height=36,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: self.switch_page("landing"),
        )
        self.back_btn.pack(side="right", padx=(10, 20))

        # ---- DnD setup ----
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

    # ---------- Logic ----------
    def _set_drop_border(self, color: str):
        try:
            self.drop_area.configure(border_color=color)
        except Exception:
            pass

    def _set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, text_color=("red" if error else TEXT))

    def _on_processed(self, meta: Dict[str, Any]):
        self._selected_meta = meta
        self._show_details(meta)
        self._set_status(f"Loaded: {meta.get('filename', 'item')}")
        try:
            result = self._run_analysis(meta)
            self._export_payload = self._build_export_payload([meta], result)
            self._show_preview(self._export_payload)
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

    def _show_details(self, meta: Dict[str, Any]):
        self.dv_name.configure(text=meta.get("filename", "—"))
        self.dv_type.configure(text=meta.get("filetype", meta.get("category", "—")))
        size = meta.get("size")
        self.dv_size.configure(text=(f"{size} bytes" if isinstance(size, int) else "—"))
        self.dv_added.configure(text=meta.get("uploaded_at", "—"))
        self.dv_path.configure(text=meta.get("stored_path", meta.get("url", "—")))

    def _run_analysis(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        self._set_status("Running analysis…")
        self.update_idletasks()
        time.sleep(1.0)
        fake = {
            "file": meta.get("filename"),
            "type": meta.get("category"),
            "detected_crypto": ["AES", "SHA-256"],
            "notes": "Placeholder result",
        }
        return {"summary": "Analysis complete.", "findings": [fake]}

    def _build_export_payload(self, metas: List[Dict[str, Any]], res: Dict[str, Any]):
        return {"summary": res.get("summary", ""), "findings": res.get("findings", []), "inputs": metas}

    def _show_preview(self, payload: Dict[str, Any]):
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", json.dumps(payload, indent=2))
        self.preview.configure(state="disabled")
        self._set_status("Analysis finished successfully.")

    def _export_json_from_preview(self):
        if not self._export_payload:
            self._set_status("Nothing to export yet.", True)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Save export JSON",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._export_payload, f, indent=2)
        messagebox.showinfo("Export JSON", f"Saved:\n{path}")
        self._set_status(f"Exported to: {path}")

    def reset_ui(self):
        self._selected_meta = None
        self._export_payload = None
        for attr in ("dv_name", "dv_type", "dv_size", "dv_added", "dv_path"):
            getattr(self, attr).configure(text="—")
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.configure(state="disabled")
        self.gh_entry.delete(0, "end")
        self._set_status("")
