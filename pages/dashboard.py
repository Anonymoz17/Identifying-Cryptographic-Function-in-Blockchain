# pages/dashboard.py
import os
import customtkinter as ctk
from file_handler import FileHandler, FileDropController, open_file_picker

class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, switch_page, file_handler: FileHandler):
        super().__init__(master)
        self.switch_page = switch_page
        self.file_handler = file_handler
        self.uploaded = []

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        self.title = ctk.CTkLabel(content, text="Dashboard", font=("Roboto", 72))
        self.title.pack(pady=(12, 4))

        self.status = ctk.CTkLabel(content, text="")
        self.status.pack(pady=(0, 6))

        # Drop zone — softer background + subtle border (window-like)
        self.dnd = ctk.CTkFrame(
            content,
            corner_radius=16,
            border_width=1,
            border_color="#cdd5e0",
            fg_color=("#f5f7fb", "#1a1a1a"),  # light / dark
        )
        self.dnd.pack(padx=24, pady=6, fill="x")
        self.dnd.pack_propagate(False)

        self.dz_label = ctk.CTkLabel(
            self.dnd,
            text=("Drag & Drop files here\n"
                  "• Local file paths (e.g., .exe, .so, .zip, .py)\n"
                  "• GitHub repo URLs (not implemented in this sample)"),
            font=("Roboto", 24),
            justify="center",
        )
        self.dz_label.place(relx=0.5, rely=0.5, anchor="center")

        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(pady=(6, 0))

        # Existing Analyze button
        self.analyze_btn = ctk.CTkButton(actions, text="Analyze", width=160, height=40, command=self._analyze)
        self.analyze_btn.pack()

        # NEW: Try Advisor (beta) button — safe additive route
        self.advisor_btn = ctk.CTkButton(
            actions,
            text="✨ Try Advisor (beta)",
            width=160,
            height=40,
            command=lambda: self.switch_page("advisor")
        )
        self.advisor_btn.pack(pady=(6, 0))

        # NEW: Auditor quick access
        self.auditor_btn = ctk.CTkButton(
            actions,
            text="🛡️ Auditor",
            width=160,
            height=40,
            command=lambda: self.switch_page("auditor")
        )
        self.auditor_btn.pack(pady=(6, 0))

        # Results area — light pane feel
        self.results = ctk.CTkScrollableFrame(
            content, corner_radius=12,
            border_width=1, border_color="#cdd5e0",
            fg_color=("#f7f9fc", "#121212")
        )
        self.results.pack(padx=24, pady=(8, 6), fill="both", expand=True)
        self._add_results_header()

        below_results = ctk.CTkFrame(content, fg_color="transparent")
        below_results.pack(pady=(0, 8))
        self.browse_btn = ctk.CTkButton(
            below_results, text="Browse files…", width=160, height=40,
            command=lambda: open_file_picker(
                self, self.file_handler, self._add_result_row, self._set_status
            )
        )
        self.browse_btn.pack()

        # Try DnD
        try:
            self.ctrl_zone = FileDropController(
                target_widget=self.dnd,
                file_handler=self.file_handler,
                on_processed=self._add_result_row,
                on_status=self._set_status,
                on_border=self._set_border,
            )
            try:
                self.ctrl_label = FileDropController(
                    target_widget=self.dz_label,
                    file_handler=self.file_handler,
                    on_processed=self._add_result_row,
                    on_status=self._set_status,
                    on_border=self._set_border,
                )
            except Exception:
                pass
        except Exception as e:
            self._add_browse_fallback(str(e))

        # Sticky bottom bar with compact duplicates for tiny windows
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=1, column=0, sticky="ew", padx=24, pady=(4, 10))
        bottom.grid_columnconfigure(0, weight=0)
        bottom.grid_columnconfigure(1, weight=1)
        bottom.grid_columnconfigure(2, weight=0)
        bottom.grid_columnconfigure(3, weight=0)

        self.compact_browse_btn = ctk.CTkButton(
            bottom, text="Browse files…",
            command=lambda: open_file_picker(
                self, self.file_handler, self._add_result_row, self._set_status
            )
        )
        self.compact_analyze_btn = ctk.CTkButton(bottom, text="Analyze", command=self._analyze)

        # NEW (compact): Advisor quick access
        self.compact_advisor_btn = ctk.CTkButton(
            bottom, text="✨ Advisor",
            command=lambda: self.switch_page("advisor")
        )

        # NEW (compact): Auditor quick access
        self.compact_auditor_btn = ctk.CTkButton(
            bottom, text="🛡️ Auditor",
            command=lambda: self.switch_page("auditor")
        )

        self._compact_visible = False

        self.logout_btn = ctk.CTkButton(bottom, text="Logout", command=self._logout)
        self.logout_btn.grid(row=0, column=3, sticky="e")

        self._results_min_h = 120
        self._results_max_h = 480
        self._compact_height_threshold = 720
        self._compact_force = False

    def _logout(self):
        app = self.winfo_toplevel()
        app.logout()

    def reset_ui(self):
        self.uploaded.clear()
        self._set_status("")
        self._set_border("#cdd5e0")
        try:
            for w in self.results.winfo_children():
                w.destroy()
        except Exception:
            pass
        self._add_results_header()

    def _add_browse_fallback(self, reason: str):
        self._set_status(f"Drag & drop unavailable: {reason}", error=True)

    def _set_border(self, color: str):
        self.dnd.configure(border_color=color)

    def _set_status(self, text: str, error: bool = False):
        low = (text or "").lower()
        if low.startswith("tkdnd") or "dnd ready" in low:
            return
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    def _add_results_header(self):
        header = ctk.CTkFrame(self.results, fg_color="transparent")
        header.pack(fill="x", padx=8, pady=(6, 4))
        for i, col in enumerate(("Name", "Category", "MIME/Type", "Size (bytes)", "Stored Path / Note")):
            ctk.CTkLabel(header, text=col, font=("Roboto", 14, "bold")).grid(
                row=0, column=i, sticky="w", padx=(8, 12))
        for i in range(5):
            header.grid_columnconfigure(i, weight=(2 if i == 4 else 1))

    def _add_result_row(self, meta: dict):
        app = self.winfo_toplevel()
        tier = getattr(app, "current_user_role", "free")
        self.uploaded.append(meta)
        row = ctk.CTkFrame(self.results, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=2)

        name = meta.get("filename") or os.path.basename(meta.get("stored_path", "")) or "-"
        category = meta.get("category", "-")
        mime = meta.get("filetype", "-")
        size = str(meta.get("size", "-"))
        stored = meta.get("stored_path") or "-"

        for i, val in enumerate((name, category, mime, size, stored)):
            ctk.CTkLabel(row, text=str(val)).grid(row=0, column=i, sticky="w", padx=(8, 12), pady=2)
            row.grid_columnconfigure(i, weight=(2 if i == 4 else 1))

        self._set_status(f"Logged in as {tier.upper()}")

    def _analyze(self):
        app = self.winfo_toplevel()
        if not getattr(app, "auth_token", None):
            self._set_status("Please log in first.", error=True); return
        tier = getattr(app, "current_user_role", "free")
        if tier == "free" and len(self.uploaded) > 1:
            self._set_status("Free tier: analyze 1 file at a time. Upgrade to analyze multiple.", error=True)
            return
        self.switch_page("analysis")

    def _toggle_compact_actions(self, show: bool):
        if show == self._compact_visible:
            return
        if show:
            self.compact_browse_btn.grid(row=0, column=0, sticky="w")
            # NEW: place Advisor in the middle stretch column
            self.compact_advisor_btn.grid(row=0, column=1, sticky="w", padx=(8, 8))
            self.compact_analyze_btn.grid(row=0, column=2, sticky="e", padx=(8, 8))
        else:
            try: self.compact_browse_btn.grid_forget()
            except Exception: pass
            try: self.compact_advisor_btn.grid_forget()
            except Exception: pass
            try: self.compact_analyze_btn.grid_forget()
            except Exception: pass
        self._compact_visible = show

    def on_resize(self, w, h):
        if not self.winfo_exists():
            return
        # title font bucket
        new_size = max(28, min(84, int(72 * (h / 900.0))))
        if getattr(self, "_last_title_size", None) != new_size:
            self._last_title_size = new_size
            try:
                self.title.configure(font=("Roboto", new_size))
            except Exception:
                pass

        dz_w = max(520, min(1400, int(w * 0.72)))
        dz_h = max(180, min(380, int(h * 0.28)))
        try:
            self.dnd.configure(width=dz_w, height=dz_h)
            dz_label_size = max(16, min(28, int(24 * (h / 900.0))))
            self.dz_label.configure(font=("Roboto", dz_label_size))
        except Exception:
            return  # tearing down

        btn_w = max(120, min(220, int(w * 0.12)))
        btn_h = max(36,  min(56,  int(h * 0.05)))
        # include new advisor buttons in resize pass
        for b in (
            self.analyze_btn, self.browse_btn, self.compact_analyze_btn,
            self.compact_browse_btn, self.logout_btn, self.advisor_btn, self.compact_advisor_btn
        ):
            try:
                b.configure(width=btn_w, height=btn_h)
            except Exception:
                pass

        target_h = max(getattr(self, "_results_min_h", 120),
                       min(getattr(self, "_results_max_h", 480), int(h * 0.30)))
        try:
            self.results.configure(height=target_h)
        except Exception:
            pass

        show_compact = getattr(self, "_compact_force", False) or (h < getattr(self, "_compact_height_threshold", 720))
        try:
            self._toggle_compact_actions(show_compact)
        except Exception:
            pass
