from typing import Any, Dict, Optional

import customtkinter as ctk

from file_handler import FileDropController, open_file_picker

# --- Color system (dark UI) ---
BG = "#0B0F1A"  # page
CARD_BG = "#111827"
BORDER = "#1F2937"
MUTED = "#9CA3AF"
TEXT = "#E5E7EB"

PRIMARY = "#22C55E"  # green
PRIMARY_H = "#16A34A"

SECONDARY = "#334155"  # slate
SECONDARY_H = "#1F2937"

OUTLINE_BG = "transparent"
OUTLINE_BR = "#334155"
OUTLINE_TX = TEXT
OUTLINE_H = "#243244"


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, switch_page, file_handler):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page
        self.fh = file_handler

        # ---------- Header ----------
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(16, 0))

        title = ctk.CTkLabel(
            header, text="Dashboard", font=("Segoe UI", 28, "bold"), text_color=TEXT
        )
        subtitle = ctk.CTkLabel(
            header,
            text="Upload a project or analyze directly from a GitHub repository URL.",
            font=("Segoe UI", 12),
            text_color=MUTED,
        )
        title.grid(row=0, column=0, sticky="w", pady=(2, 0))
        subtitle.grid(row=1, column=0, sticky="w", pady=(0, 6))

        logout_btn = ctk.CTkButton(
            header,
            text="Logout",
            width=74,
            height=28,
            corner_radius=8,
            fg_color=OUTLINE_BG,
            hover_color=OUTLINE_H,
            text_color=OUTLINE_TX,
            border_width=1,
            border_color=OUTLINE_BR,
            command=self._logout,
        )
        # (Auditor quick access and results area are added later below.)
        header.grid_columnconfigure(0, weight=1)
        logout_btn.grid(row=0, column=1, rowspan=2, sticky="e")

        # ---------- Upload card ----------
        upload_card = ctk.CTkFrame(
            self,
            corner_radius=16,
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
            text="Drop a source folder/file or choose from disk.",
            font=("Segoe UI", 12),
            text_color=MUTED,
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 8))

        body = ctk.CTkFrame(upload_card, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=16, pady=(6, 16))
        upload_card.grid_columnconfigure(0, weight=1)

        # smaller drag zone
        self.drop_area = ctk.CTkFrame(
            body,
            width=480,
            height=150,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=BG,
        )
        self.drop_area.grid(row=0, column=0, sticky="w")
        self.drop_area.grid_propagate(False)

        self.drop_label = ctk.CTkLabel(
            self.drop_area,
            text="Drag & drop here",
            font=("Segoe UI", 14, "bold"),
            text_color=TEXT,
        )
        self.drop_label.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(
            self.drop_area,
            text="Supported: local files, or paste a GitHub URL below",
            font=("Segoe UI", 11),
            text_color=MUTED,
        ).place(relx=0.5, rely=0.5, y=22, anchor="center")

        pick_btn = ctk.CTkButton(
            body,
            text="Choose files…",
            width=150,
            height=36,
            corner_radius=10,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=lambda: open_file_picker(
                self, self.fh, self._on_processed, self._set_status
            ),
        )
        pick_btn.grid(row=0, column=1, padx=(12, 0), sticky="e")

        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)

        # ---------- Divider "or" ----------
        or_row = ctk.CTkFrame(self, fg_color="transparent")
        or_row.pack(fill="x", padx=22, pady=(6, 8))
        ctk.CTkFrame(or_row, height=1, fg_color=BORDER).pack(
            side="left", fill="x", expand=True, padx=(0, 10)
        )
        ctk.CTkLabel(or_row, text="or", font=("Segoe UI", 11), text_color=MUTED).pack(
            side="left"
        )
        ctk.CTkFrame(or_row, height=1, fg_color=BORDER).pack(
            side="left", fill="x", expand=True, padx=(10, 0)
        )

        # ---------- GitHub card ----------
        gh_card = ctk.CTkFrame(
            self,
            corner_radius=16,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        gh_card.pack(fill="x", padx=22, pady=(4, 8))

        ctk.CTkLabel(
            gh_card,
            text="Analyze from GitHub repo URL",
            font=("Segoe UI", 16, "bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(
            gh_card,
            text="Examples: https://github.com/bitcoin/bitcoin  •  …/tree/branch  •  …@branch",
            font=("Segoe UI", 11),
            text_color=MUTED,
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 6))

        gh_row = ctk.CTkFrame(gh_card, fg_color="transparent")
        gh_row.grid(row=2, column=0, sticky="ew", padx=16, pady=(4, 16))
        gh_card.grid_columnconfigure(0, weight=1)

        self.gh_entry = ctk.CTkEntry(
            gh_row,
            placeholder_text="Paste GitHub URL…",
            height=36,
            width=520,
            corner_radius=10,
            fg_color=BG,
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
            corner_radius=10,
            fg_color=SECONDARY,
            hover_color=SECONDARY_H,
            text_color=TEXT,
            command=self._on_github_analyze,
        )
        gh_btn.pack(side="left", padx=(12, 0))

        # ---------- Details box (single card) ----------
        self.details = ctk.CTkFrame(
            self,
            corner_radius=16,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        self.details.pack(fill="x", padx=22, pady=(10, 6))
        for i in range(2):
            self.details.grid_columnconfigure(i, weight=(0 if i == 0 else 1))

        def _kv(row, key_text, attr_name):
            k = ctk.CTkLabel(
                self.details,
                text=key_text,
                font=("Segoe UI", 11, "bold"),
                text_color="#D1D5DB",
            )
            v = ctk.CTkLabel(
                self.details, text="—", font=("Segoe UI", 11), text_color=TEXT
            )
            k.grid(
                row=row,
                column=0,
                sticky="w",
                padx=(14, 10),
                pady=(10 if row == 0 else 6, 0),
            )
            v.grid(
                row=row,
                column=1,
                sticky="w",
                padx=(0, 14),
                pady=(10 if row == 0 else 6, 0),
            )
            setattr(self, attr_name, v)

        _kv(0, "Name:", "dv_name")
        _kv(1, "Type:", "dv_type")
        _kv(2, "Size:", "dv_size")
        _kv(3, "Added:", "dv_added")
        _kv(4, "Path:", "dv_path")
        ctk.CTkFrame(self.details, height=12, fg_color="transparent").grid(
            row=5, column=0, columnspan=2
        )

        # ---------- Footer actions ----------
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", padx=22, pady=(10, 20))

        self.status = ctk.CTkLabel(
            actions, text="", font=("Segoe UI", 11), text_color=TEXT
        )
        self.status.pack(side="left")

        spacer = ctk.CTkFrame(actions, fg_color="transparent")
        spacer.pack(side="left", expand=True, fill="x")

        self.try_beta = ctk.CTkButton(
            actions,
            text="Try beta",
            height=36,
            corner_radius=10,
            fg_color=OUTLINE_BG,
            hover_color=OUTLINE_H,
            text_color=OUTLINE_TX,
            border_width=1,
            border_color=OUTLINE_BR,
            command=lambda: self.switch_page("advisor"),
        )
        self.try_beta.pack(side="right")

        self.analyze_btn = ctk.CTkButton(
            actions,
            text="Analyze",
            height=36,
            corner_radius=10,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=self._go_analyze,
        )
        self.analyze_btn.pack(side="right", padx=(10, 8))
        # NEW (compact): Auditor quick access (use footer 'actions' frame)
        self.compact_auditor_btn = ctk.CTkButton(
            actions, text="🛡️ Auditor", command=lambda: self.switch_page("auditor")
        )
        self._compact_visible = False

        # Logout in footer (pack to the right so it lines up with other action buttons)
        self.logout_btn = ctk.CTkButton(actions, text="Logout", command=self._logout)
        self.logout_btn.pack(side="right", padx=(8, 0))

        back_btn = ctk.CTkButton(
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
        back_btn.pack(side="bottom", pady=10)

        # selection holder
        self._selected_meta: Optional[Dict[str, Any]] = None

        # DnD wiring
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

    # ---- helpers ----
    def _set_drop_border(self, color: str):
        try:
            self.drop_area.configure(border_color=color)
        except Exception:
            pass

    def _set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, text_color=("red" if error else TEXT))

    def _show_details(self, meta: Dict[str, Any]):
        self.dv_name.configure(text=meta.get("filename", "—"))
        self.dv_type.configure(text=meta.get("filetype", meta.get("category", "—")))
        size = meta.get("size")
        self.dv_size.configure(text=(f"{size} bytes" if isinstance(size, int) else "—"))
        self.dv_added.configure(text=meta.get("uploaded_at", "—"))
        self.dv_path.configure(text=meta.get("stored_path", meta.get("url", "—")))

    def _on_processed(self, meta: Dict[str, Any]):
        self._selected_meta = meta
        self._show_details(meta)
        self._set_status(f"Loaded: {meta.get('filename') or meta.get('url') or 'item'}")

    def _handle_github_url(self, url: str) -> Dict[str, Any]:
        return {
            "filename": url.split("/")[-1] or "repo",
            "filetype": "text/uri-list",
            "category": "github-url",
            "size": 0,
            "uploaded_at": "",
            "stored_path": "",
            "url": url,
        }

    def _on_github_analyze(self):
        url = (self.gh_entry.get() or "").strip()
        if not url:
            self._set_status("Enter a GitHub repository URL.", True)
            return
        try:
            meta = self._handle_github_url(url)
            self._on_processed(meta)
        except Exception as e:
            self._set_status(f"GitHub URL error: {e}", True)

    def _go_analyze(self):
        if not self._selected_meta:
            self._set_status("Please choose a file or paste a GitHub URL first.", True)
            return
        app = self.winfo_toplevel()
        app.current_scan_meta = self._selected_meta
        self.switch_page("analysis")

    def _logout(self):
        try:
            self.winfo_toplevel().logout()
        except Exception:
            pass

    # external hooks
    def reset_ui(self):
        self._selected_meta = None
        for v in (
            self.dv_name,
            self.dv_type,
            self.dv_size,
            self.dv_added,
            self.dv_path,
        ):
            v.configure(text="—")
        try:
            self.gh_entry.delete(0, "end")
        except Exception:
            pass
        self._set_status("")

    def on_enter(self):
        pass

    def on_resize(self, w, h):
        pass
