"""moved from pages/analysis.py"""

import json
import os
from tkinter import filedialog
from typing import Any, Dict, List

import customtkinter as ctk


class AnalysisPage(ctk.CTkFrame):
    """
    Minimal Analysis page:
    - Reads uploaded file metadata from DashboardPage (no analysis engine yet).
    - Shows a table of files + a placeholder "Run Analysis" that just updates status.
    - Includes "Export (JSON)" to save the current inputs as a draft payload.
    - Responsive sizing similar to DashboardPage.
    """

    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        # Title + status
        self.title = ctk.CTkLabel(content, text="Analysis", font=("Roboto", 64))
        self.title.pack(pady=(12, 4))

        self.status = ctk.CTkLabel(content, text="")
        self.status.pack(pady=(0, 6))

        # Files table
        self.table = ctk.CTkScrollableFrame(
            content,
            corner_radius=12,
            border_width=1,
            border_color="#cdd5e0",
            fg_color=("#f7f9fc", "#121212"),
        )
        self.table.pack(padx=24, pady=(8, 6), fill="both", expand=True)

        self._add_table_header()

        # Actions row
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(pady=(4, 0))

        self.run_btn = ctk.CTkButton(
            actions, text="Run Analysis (placeholder)", command=self._run_analysis
        )
        self.run_btn.pack(pady=(0, 6))

        self.export_btn = ctk.CTkButton(
            actions, text="Export Inputs (JSON)", command=self._export_json
        )
        self.export_btn.pack(pady=(0, 6))

        # Sticky bottom bar
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=1, column=0, sticky="ew", padx=24, pady=(4, 10))
        bottom.grid_columnconfigure(0, weight=0)
        bottom.grid_columnconfigure(1, weight=1)
        bottom.grid_columnconfigure(2, weight=0)

        self.back_btn = ctk.CTkButton(
            bottom,
            text="Back to Dashboard",
            command=lambda: self.switch_page("dashboard"),
        )
        self.back_btn.grid(row=0, column=0, sticky="w")

        self._compact_height_threshold = 720
        self._last_title_size = None

        # Add a Back to Landing button below everything
        self.back_to_landing = ctk.CTkButton(
            self,
            text="⬅ Back to Landing",
            height=32,
            corner_radius=8,
            fg_color="transparent",
            hover_color="#1F2937",
            border_width=1,
            border_color="#374151",
            text_color="#E5E7EB",
            command=lambda: self.switch_page("landing"),
        )
        self.back_to_landing.grid(row=2, column=0, pady=(6, 12))


    # ---------- Lifecycle hooks ----------
    def on_enter(self):
        """Reload the files from Dashboard whenever we land here."""
        self._reload_from_dashboard()

    def reset_ui(self):
        """Clear table & status."""
        self._set_status("")
        try:
            for w in self.table.winfo_children():
                w.destroy()
        except Exception:
            pass
        self._add_table_header()

    # ---------- Internals ----------
    def _add_table_header(self):
        header = ctk.CTkFrame(self.table, fg_color="transparent")
        header.pack(fill="x", padx=8, pady=(6, 4))
        cols = ("Name", "Category", "MIME/Type", "Size (bytes)", "Stored Path / Note")
        for i, col in enumerate(cols):
            ctk.CTkLabel(header, text=col, font=("Roboto", 14, "bold")).grid(
                row=0, column=i, sticky="w", padx=(8, 12)
            )
            header.grid_columnconfigure(i, weight=(2 if i == 4 else 1))

    def _add_row(self, meta: Dict[str, Any]):
        row = ctk.CTkFrame(self.table, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=2)

        name = (
            meta.get("filename") or os.path.basename(meta.get("stored_path", "")) or "-"
        )
        category = meta.get("category", "-")
        mime = meta.get("filetype", "-")
        size = str(meta.get("size", "-"))
        stored = meta.get("stored_path") or "-"

        values = (name, category, mime, size, stored)
        for i, val in enumerate(values):
            ctk.CTkLabel(row, text=str(val)).grid(
                row=0, column=i, sticky="w", padx=(8, 12), pady=2
            )
            row.grid_columnconfigure(i, weight=(2 if i == 4 else 1))

    def _reload_from_dashboard(self):
        self.reset_ui()
        app = self.winfo_toplevel()
        dash = getattr(app, "_pages", {}).get("dashboard")
        uploaded: List[Dict[str, Any]] = getattr(dash, "uploaded", []) if dash else []
        if not uploaded:
            self._set_status(
                "No files yet. Add files on Dashboard and click Analyze.", error=False
            )
            return
        for meta in uploaded:
            self._add_row(meta)
        self._set_status(f"{len(uploaded)} file(s) ready for analysis.")

    def _run_analysis(self):
        """
        Placeholder action: this is where you'll call your actual pipeline later.
        For now, just show a success message.
        """
        app = self.winfo_toplevel()
        if not getattr(app, "auth_token", None):
            self._set_status("Please log in first.", error=True)
            return

        dash = getattr(app, "_pages", {}).get("dashboard")
        uploaded: List[Dict[str, Any]] = getattr(dash, "uploaded", []) if dash else []

        if not uploaded:
            self._set_status(
                "Nothing to analyze. Please add files on Dashboard.", error=True
            )
            return

        # TODO: integrate real pipeline; for now just pretend we did work.
        self._set_status("Analysis complete (demo). Results view coming soon.")

    def _export_json(self):
        """
        Export the current 'inputs' (uploaded list) to a JSON file.
        Useful during FYP to show a report-like artifact before the engine is ready.
        """
        app = self.winfo_toplevel()
        dash = getattr(app, "_pages", {}).get("dashboard")
        uploaded: List[Dict[str, Any]] = getattr(dash, "uploaded", []) if dash else []

        payload = {
            "title": "CryptoScope Analysis Inputs (Draft)",
            "count": len(uploaded),
            "items": uploaded,
        }

        path = filedialog.asksaveasfilename(
            title="Export Inputs as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="analysis_inputs.json",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            self._set_status(f"Exported to {os.path.basename(path)}")
        except Exception as e:
            self._set_status(f"Failed to export: {e}", error=True)

    def _set_status(self, text: str, error: bool = False):
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    # ---------- Responsive layout ----------
    def on_resize(self, w, h):
        if not self.winfo_exists():
            return

        # Title scaling similar to Dashboard
        new_size = max(28, min(84, int(64 * (h / 900.0))))
        if self._last_title_size != new_size:
            self._last_title_size = new_size
            try:
                self.title.configure(font=("Roboto", new_size))
            except Exception:
                pass

        # Button sizing
        btn_w = max(120, min(220, int(w * 0.12)))
        btn_h = max(36, min(56, int(h * 0.05)))
        for b in (self.run_btn, self.export_btn, self.back_btn):
            try:
                b.configure(width=btn_w, height=btn_h)
            except Exception:
                pass

        # Table height target (mirrors Dashboard approach)
        target_h = max(160, min(520, int(h * 0.34)))
        try:
            self.table.configure(height=target_h)
        except Exception:
            pass
