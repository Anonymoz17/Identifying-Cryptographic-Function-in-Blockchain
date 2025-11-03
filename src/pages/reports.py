# src/pages/reports.py
"""
CryptoScope Reports Page
--------------------------------
- Unified with ui.theme
- Displays and exports analysis reports (JSON / PDF)
- Reads from app memory or file
- Back to Landing + Logout included
"""

import json
from tkinter import filedialog, messagebox

import customtkinter as ctk

from ui.theme import (
    BG,
    BORDER,
    CARD_BG,
    HEADING_FONT,
    MUTED,
    OUTLINE_BR,
    OUTLINE_H,
    PRIMARY,
    PRIMARY_H,
    TEXT,
)


class ReportsPage(ctk.CTkFrame):
    def __init__(
        self,
        master,
        switch_page,
        get_role=None,
        export_json_cb=None,
        export_pdf_cb=None,
    ):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page
        self.get_role = get_role
        self.export_json_cb = export_json_cb
        self.export_pdf_cb = export_pdf_cb
        self._payload = None

        # ===== Header =====
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(16, 6))

        title = ctk.CTkLabel(header, text="Reports", font=HEADING_FONT, text_color=TEXT)
        subtitle = ctk.CTkLabel(
            header,
            text="View and export previous cryptographic analysis results.",
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

        # ===== Report Preview Card =====
        main = ctk.CTkFrame(
            self,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        main.pack(fill="both", expand=True, padx=22, pady=(10, 16))
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            main,
            text="Analysis Report Preview",
            font=HEADING_FONT,
            text_color=TEXT,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))

        self.textbox = ctk.CTkTextbox(
            main,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            wrap="none",
        )
        self.textbox.grid(row=1, column=0, sticky="nsew", padx=16, pady=(4, 14))
        self._load_from_app_memory()

        # ===== Actions =====
        actions = ctk.CTkFrame(main, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="e", padx=16, pady=(0, 14))
        actions.grid_columnconfigure(0, weight=1)

        ctk.CTkButton(
            actions,
            text="Load JSON File…",
            height=34,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color=BG,
            command=self._load_from_file,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            actions,
            text="Export JSON Again",
            height=34,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color=BG,
            command=self._export_json,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            actions,
            text="Export PDF (coming soon)",
            height=34,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=self._export_pdf_placeholder,
        ).pack(side="left", padx=(0, 8))

        # Back to Landing
        ctk.CTkButton(
            actions,
            text="⬅ Back to Landing",
            height=34,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: self.switch_page("landing"),
        ).pack(side="right")

    # ===== Internal Functions =====
    def _load_from_app_memory(self):
        """If Dashboard stored the last export payload, display it."""
        app = self.winfo_toplevel()
        payload = getattr(app, "last_export_payload", None)
        if isinstance(payload, dict):
            self._payload = payload
            formatted = json.dumps(payload, indent=2)
            self.textbox.insert("1.0", formatted)
            self.textbox.configure(state="disabled")

    def _load_from_file(self):
        """Load any .json report from disk."""
        path = filedialog.askopenfilename(
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._payload = data
            self.textbox.configure(state="normal")
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", json.dumps(data, indent=2))
            self.textbox.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to open JSON:\n{e}")

    def _export_json(self):
        """Trigger the export callback or re-save the current payload."""
        if callable(self.export_json_cb):
            self.export_json_cb()
            return
        if not self._payload:
            messagebox.showinfo("Nothing to Export", "No report is loaded.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All Files", "*.*")],
            title="Save JSON Report",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._payload, f, indent=2)
        messagebox.showinfo("Export JSON", f"Saved:\n{path}")

    def _export_pdf_placeholder(self):
        """Placeholder for PDF export."""
        messagebox.showinfo(
            "Export PDF",
            "PDF export will be available in a future update.",
        )
