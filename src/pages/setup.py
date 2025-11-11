# setup.py  — centered form, lazy progress, console toggle (theme-driven)
from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from typing import Optional

import customtkinter as ctk

# --- auditor / pipeline imports (unchanged app logic) ---
from auditor.workspace import Workspace
from auditor.setup_flow.setupcontext import SetupContext
from auditor.setup_flow.runner import run_pipeline
from auditor.setup_flow.setupmessages import Notifier, Message
from auditor.setup_flow.output import get_default_workdir, is_within_default

try:
    from auditor.auditlog import AuditLog  # noqa: F401
except Exception:
    AuditLog = None  # type: ignore

FORM_WIDTH = 900  # <- set this to your previous card width (e.g., 880/900/960)


# --- unified theme ---
from ui.theme import (
    BG,
    CARD_BG,
    BORDER,
    TEXT,
    MUTED,
    PRIMARY,
    PRIMARY_H,
    OUTLINE_BR,
    OUTLINE_H,
    BODY_FONT,
    HEADING_FONT,
    MONO_FONT,
)


class SetupPage(ctk.CTkFrame):
    """
    Setup page: define scope and optionally preprocess inputs.

    Changes:
      • The form card is centered on the screen (both axes).
      • Progress UI (bar, phase, ETA) is hidden until Start is clicked.
      • Console is hidden by default; an actions button toggles visibility.
    """

    def __init__(self, master, switch_page_callback):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page_callback

        # ===== Root layout ====================================================
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")

        # ... after you've packed everything inside `content`, add:
        bottom_spacer = ctk.CTkFrame(content, height=16, fg_color="transparent")
        bottom_spacer.pack(fill="x", side="bottom")
        bottom_spacer.pack_propagate(False)


        # ===== Header =========================================================
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(16, 6))

        ctk.CTkLabel(header, text="Setup — Inputs & Preprocessing",
                     font=HEADING_FONT, text_color=TEXT).pack(side="left")

        ctk.CTkButton(
            header,
            text="← Back to Landing",
            width=160,
            fg_color="transparent",
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            border_width=1,
            corner_radius=8,
            command=lambda: (self._on_cancel(), self._reset_progress_ui(), self.switch_page("landing")),
        ).pack(side="right")


        # Optional hint under header
        ctk.CTkLabel(
            content,
            text="Pipeline: Enumerate → Preprocess → (optional) AST/Disasm",
            font=BODY_FONT, text_color=MUTED,
            wraplength=FORM_WIDTH - 64   # 👈 optional
        ).pack(fill="x", padx=22, pady=(0, 8))

        # ===== Centering container for the form card ==========================
        center = ctk.CTkFrame(content, fg_color="transparent")
        center.pack(fill="both", expand=True, padx=22, pady=(0, 10))

        # Grid trick: 3x3 with middle cell hosting the form → perfect centering
        for r in (0, 2):
            center.grid_rowconfigure(r, weight=1)
        for c in (0, 2):
            center.grid_columnconfigure(c, weight=1)

        # ===== Form card (upload/scope/workdir) ===============================
        form = ctk.CTkFrame(center, fg_color=CARD_BG, border_width=1,
                            border_color=BORDER, corner_radius=12)
        form.grid(row=1, column=1, sticky="n")         # keep a neat top bias
        form.grid_columnconfigure(1, weight=1)

        form.configure(width=FORM_WIDTH)
        form.grid_propagate(False)

        form.grid_columnconfigure(1, weight=1)

        # --- Scope row
        ctk.CTkLabel(form, text="Scope", text_color=TEXT, font=BODY_FONT)\
            .grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))

        self.scope_entry = ctk.CTkEntry(form, placeholder_text="Folder to scan (use Browse)")
        try:
            default_scope = str((Path.cwd() / "case_demo").resolve())
        except Exception:
            default_scope = str(Path.home())
        self.scope_entry.insert(0, default_scope)
        self.scope_entry.grid(row=0, column=1, sticky="we", padx=(0, 12), pady=(14, 4))

        ctk.CTkButton(
            form, text="Browse", width=100, fg_color=PRIMARY, hover_color=PRIMARY_H,
            command=self._browse_scope
        ).grid(row=0, column=2, padx=(0, 16))

        # --- Workdir row
        ctk.CTkLabel(form, text="Workdir", text_color=TEXT, font=BODY_FONT)\
            .grid(row=1, column=0, sticky="w", padx=16, pady=(6, 4))

        self.workdir_entry = ctk.CTkEntry(form, placeholder_text="Default work directory")
        try:
            default_workdir = str(get_default_workdir())
        except Exception:
            default_workdir = str((Path.cwd() / "case_demo" / "cases").resolve())
        self.workdir_entry.insert(0, default_workdir)
        self.workdir_entry.grid(row=1, column=1, sticky="we", padx=(0, 12), pady=(6, 4))

        wd_btns = ctk.CTkFrame(form, fg_color="transparent")
        wd_btns.grid(row=1, column=2, sticky="e", padx=(0, 16))
        ctk.CTkButton(wd_btns, text="Browse", width=88, fg_color=PRIMARY,
                      hover_color=PRIMARY_H, command=self._browse_workdir).pack(side="left")
        ctk.CTkButton(
            wd_btns, text="Revert", width=88, fg_color="transparent",
            border_color=OUTLINE_BR, hover_color=OUTLINE_H, text_color=TEXT,
            border_width=1, command=self._revert_workdir
        ).pack(side="left", padx=(8, 0))

        # Workdir advisory (theme text only)
        self.workdir_warning = ctk.CTkLabel(form, text="", font=("", 10), text_color=MUTED)
        self.workdir_warning.grid(row=2, column=1, sticky="w", padx=(0, 12), pady=(0, 6))

        # --- Case meta
        ctk.CTkLabel(form, text="Case ID / Client", text_color=TEXT, font=BODY_FONT)\
            .grid(row=3, column=0, sticky="nw", padx=16, pady=(8, 4))

        meta = ctk.CTkFrame(form, fg_color="transparent")
        meta.grid(row=3, column=1, columnspan=2, sticky="we", padx=(0, 16), pady=(6, 10))
        meta.grid_columnconfigure(0, weight=1)

        self.case_entry = ctk.CTkEntry(meta, placeholder_text="e.g. CASE-001")
        self.case_entry.grid(row=0, column=0, sticky="we")
        self.client_entry = ctk.CTkEntry(meta, placeholder_text="Client name (optional)")
        self.client_entry.grid(row=1, column=0, sticky="we", pady=(6, 0))

        # --- Preprocessing options
        ctk.CTkLabel(form, text="Preprocessing Options", text_color=TEXT, font=BODY_FONT)\
            .grid(row=4, column=0, sticky="w", padx=16, pady=(6, 4))

        self.extract_var = tk.BooleanVar(value=True)
        self.fast_scan_var = tk.BooleanVar(value=False)

        opts = ctk.CTkFrame(form, fg_color="transparent")
        opts.grid(row=4, column=1, columnspan=2, sticky="we", padx=(0, 16))
        ctk.CTkCheckBox(opts, text="Extract archives", variable=self.extract_var, text_color=TEXT).grid(row=0, column=0, sticky="w")
        ctk.CTkCheckBox(opts, text="Fast scan (skip hashing)", variable=self.fast_scan_var, text_color=TEXT).grid(row=0, column=1, sticky="w", padx=(12, 0))

        # --- Advanced options launcher
        self.adv_config = {
            "policy": "",
            "extract_archives": True,
            "fast_scan": False,
            "max_extract_depth": 2,
            "build_ast": False,
            "build_disasm": False,
            "case_subdir": "cases",
        }
        ctk.CTkButton(
            form, text="Advanced options…", width=200,
            fg_color="transparent", border_color=OUTLINE_BR,
            hover_color=OUTLINE_H, text_color=TEXT, border_width=1,
            command=self._open_advanced
        ).grid(row=4, column=2, sticky="e", padx=(0, 16))

        # Watch workdir changes
        try:
            self.workdir_entry.bind("<FocusOut>", lambda e: self._check_workdir_canonical())
            self.workdir_entry.bind("<KeyRelease>", lambda e: self._check_workdir_canonical())
        except Exception:
            pass

        # ===== Actions row (with Show Console) ================================
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(fill="x", padx=22, pady=(8, 6))

        self.start_btn = ctk.CTkButton(actions, text="Start Engagement",
                                       fg_color=PRIMARY, hover_color=PRIMARY_H,
                                       command=self._on_start_clicked)
        self.start_btn.pack(side="left")

        self.cancel_btn = ctk.CTkButton(
            actions, text="Cancel", state="disabled",
            fg_color="transparent", border_color=OUTLINE_BR, hover_color=OUTLINE_H,
            text_color=TEXT, border_width=1, command=self._on_cancel
        )
        self.cancel_btn.pack(side="left", padx=(8, 0))

        self.open_workdir_btn = ctk.CTkButton(
            actions, text="Open workdir",
            fg_color="transparent", border_color=OUTLINE_BR, hover_color=OUTLINE_H,
            text_color=TEXT, border_width=1, command=self._open_workdir
        )
        self.open_workdir_btn.pack(side="left", padx=(8, 0))

        self.console_toggle_btn = ctk.CTkButton(
            actions, text="Show console",
            fg_color="transparent", border_color=OUTLINE_BR, hover_color=OUTLINE_H,
            text_color=TEXT, border_width=1, command=self._toggle_console
        )
        self.console_toggle_btn.pack(side="left", padx=(8, 0))

        self.continue_btn = ctk.CTkButton(
            actions, text="Continue → Detectors", state="disabled",
            fg_color=PRIMARY, hover_color=PRIMARY_H, command=self._on_continue
        )
        self.continue_btn.pack(side="right")

        # ===== Progress + status (lazy packed) ===============================
        self.progress_frame = ctk.CTkFrame(content, fg_color="transparent")
        # NOTE: not packed yet — appears on Start

        self.progress = ctk.CTkProgressBar(self.progress_frame, height=10, corner_radius=10)
        self.progress.pack(fill="x")

        self.status_label = ctk.CTkLabel(self.progress_frame, text="", text_color=MUTED, font=BODY_FONT)
        self.status_label.pack(fill="x", pady=(4, 0))

        phase_row = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        phase_row.pack(fill="x", pady=(2, 0))
        self.phase_label = ctk.CTkLabel(phase_row, text="", text_color=TEXT, font=BODY_FONT)
        self.phase_label.pack(side="left")
        self.eta_label = ctk.CTkLabel(phase_row, text="", text_color=MUTED, font=BODY_FONT)
        self.eta_label.pack(side="right")

        # ===== Console (hidden by default) ===================================
        self.console_card = ctk.CTkFrame(content, fg_color=CARD_BG, border_width=1, border_color=BORDER, corner_radius=10)
        # not packed initially

        console_header = ctk.CTkFrame(self.console_card, fg_color="transparent")
        console_header.pack(fill="x", padx=12, pady=(10, 0))
        ctk.CTkLabel(console_header, text="Console", text_color=TEXT, font=BODY_FONT).pack(side="left")

        # Native tk.Text for speed; uses theme colors
        self._console_frame = tk.Frame(self.console_card, bg=BG)
        self._console_frame.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        self.setup_results_box = tk.Text(
            self._console_frame, height=12, wrap="none",
            bg=BG, fg=TEXT, insertbackground=TEXT,
            font=MONO_FONT if MONO_FONT else None, relief=tk.FLAT, padx=8, pady=6
        )
        self.setup_results_box.pack(side="left", fill="both", expand=True)

        self.setup_scrollbar = tk.Scrollbar(self._console_frame, orient="vertical", command=self.setup_results_box.yview)
        self.setup_scrollbar.pack(side="right", fill="y")
        self.setup_results_box.configure(yscrollcommand=self.setup_scrollbar.set)

        # ===== Internal state ================================================
        self._has_progress_reporter = False
        self._cancel_event: Optional[threading.Event] = None
        self._processed_messages = 0
        self._results_max = 5000
        self._console_shown = False  # hidden by default
        try:
            self._last_browse_dir = str(Path.home())
        except Exception:
            self._last_browse_dir = "."


    # ------------------------- UI helpers ------------------------------------
    def _set_status(self, text: str, error: bool = False):
        try:
            self.status_label.configure(text=text)
        except Exception:
            pass

    def _browse_scope(self):
        from tkinter import filedialog
        initial = self._choose_initial_dir(self.scope_entry.get())
        parent = self._parent_win()
        path = filedialog.askdirectory(title="Select folder for scope", initialdir=initial, parent=parent)
        if path:
            self.scope_entry.delete(0, "end"); self.scope_entry.insert(0, path)
            self._last_browse_dir = path

    def _browse_workdir(self):
        from tkinter import filedialog
        initial = self._choose_initial_dir(self.workdir_entry.get())
        parent = self._parent_win()
        path = filedialog.askdirectory(title="Select workdir folder", initialdir=initial, parent=parent)
        if path:
            self.workdir_entry.delete(0, "end"); self.workdir_entry.insert(0, path)
            self._last_browse_dir = path
            self._check_workdir_canonical()

    def _choose_initial_dir(self, entry_val: str) -> str:
        try:
            val = (entry_val or "").strip()
            if val:
                p = Path(val)
                if p.exists() and p.is_dir():
                    return str(p)
                rp = (Path.cwd() / p).resolve()
                if rp.exists():
                    return str(rp if rp.is_dir() else rp.parent)
            return self._last_browse_dir or str(Path.home())
        except Exception:
            return self._last_browse_dir or str(Path.home())

    def _parent_win(self):
        try:
            return self.master.winfo_toplevel()
        except Exception:
            return None

    def _revert_workdir(self):
        try:
            cs = str(self.adv_config.get("case_subdir", "cases"))
            default = str(get_default_workdir(case_subdir=cs))
        except Exception:
            default = str((Path.cwd() / "case_demo" / "cases").resolve())
        self.workdir_entry.delete(0, "end"); self.workdir_entry.insert(0, default)
        self._check_workdir_canonical()

    def _check_workdir_canonical(self):
        try:
            wd = (self.workdir_entry.get() or "").strip()
            if not wd:
                self.workdir_warning.configure(text=""); return
            cs = str(self.adv_config.get("case_subdir", "cases"))
            ok = is_within_default(wd, case_subdir=cs)
            if not ok:
                default = str(get_default_workdir(case_subdir=cs))
                self.workdir_warning.configure(text=f"Recommendation: use the default workdir {default}")
            else:
                self.workdir_warning.configure(text="")
        except Exception:
            pass

    def _open_advanced(self):
        try:
            from .advanced_options import AdvancedOptionsWindow
        except Exception:
            self._set_status("Advanced options unavailable.", True); return

        def _apply(values):
            try:
                values = values or {}
                self.adv_config.update(values)
                cs = str(self.adv_config.get("case_subdir", "cases"))
                new_wd = str(get_default_workdir(case_subdir=cs))
                self.workdir_entry.delete(0, "end"); self.workdir_entry.insert(0, new_wd)
                self._check_workdir_canonical()
            except Exception:
                pass

        AdvancedOptionsWindow(self._parent_win(), initial=self.adv_config, on_apply=_apply)

    def _open_workdir(self):
        import webbrowser
        wd = (self.workdir_entry.get() or "").strip() or str(Path.cwd() / "case_demo")
        case_id = (self.case_entry.get() or "").strip() or "CASE-000"
        try:
            ws = Workspace(Path(wd), case_id)
            ws.ensure()
            webbrowser.open(ws.root.as_uri())
        except Exception:
            self._set_status(f"Could not open folder: {wd}", True)

    def _toggle_console(self):
        try:
            if self._console_shown:
                self.console_card.pack_forget()
                self.console_toggle_btn.configure(text="Show console")
                self._console_shown = False
            else:
                self.console_card.pack(fill="both", expand=True, padx=22, pady=(6, 16))
                self.console_toggle_btn.configure(text="Hide console")
                self._console_shown = True
        except Exception:
            pass

    # ------------------------- Pipeline wiring --------------------------------
    def _on_start_clicked(self):
        # lazily show the progress/status area
        try:
            self.progress.set(0.0)
            self.status_label.configure(text="")
            self.phase_label.configure(text="")
            self.eta_label.configure(text="")
            if not self.progress_frame.winfo_ismapped():
                self.progress_frame.pack(fill="x", padx=22, pady=(2, 6))
        except Exception:
            pass

        # reset console (if it’s open)
        try:
            self.setup_results_box.delete("1.0", "end")
        except Exception:
            pass

        try:
            self.start_btn.configure(state="disabled")
            self.cancel_btn.configure(state="normal")
            self.continue_btn.configure(state="disabled")
        except Exception:
            pass

        t = threading.Thread(target=self._start_pipeline_thread, daemon=True)
        t.start()

    def _on_cancel(self):
        try:
            if self._cancel_event and not self._cancel_event.is_set():
                self._cancel_event.set()
                self._set_status("Cancelling…")
        except Exception:
            pass

    def _start_pipeline_thread(self):
        # Gather inputs
        wd = (self.workdir_entry.get() or "").strip() or str(Path.cwd() / "case_demo")
        case_id = (self.case_entry.get() or "").strip() or "CASE-000"
        client = (self.client_entry.get() or "").strip() or "SetupUI"
        scope = (self.scope_entry.get() or "").strip() or str(Path.cwd())

        ctx = SetupContext(scope=Path(scope), workdir=Path(wd), case_id=case_id, client=client)
        try:
            ctx.case_dir = Path(wd) / case_id
        except Exception:
            ctx.case_dir = Path(wd)

        # Advanced into config
        try:
            adv = getattr(self, "adv_config", {}) or {}
            ctx.config.extract_archives = bool(adv.get("extract_archives", True))
            ctx.config.fast_scan = bool(adv.get("fast_scan", False))
            ctx.config.max_extract_depth = int(adv.get("max_extract_depth", 2) or 2)
            ctx.config.build_ast = bool(adv.get("build_ast", False))
            ctx.config.build_disasm = bool(adv.get("build_disasm", False))
            ctx.policy = adv.get("policy")
        except Exception:
            pass

        # Notifier + progress reporter wiring
        try:
            ctx.case_dir.mkdir(parents=True, exist_ok=True)
            notifier_path = ctx.case_dir / "ui.notifier.ndjson"
        except Exception:
            notifier_path = None

        self._cancel_event = threading.Event()

        def ui_cb(msg: Message):
            try:
                self.after(0, self._handle_notifier_message, msg)
            except Exception:
                pass

        notifier = Notifier(file_path=str(notifier_path) if notifier_path else None, ui_callback=ui_cb)

        progress_reporter = None
        try:
            from auditor.setup_flow.progress import ProgressReporter

            progress_path = ctx.case_dir / "progress.json" if ctx.case_dir else None

            def _ui_progress_cb(pu):
                try:
                    self.after(0, self._update_compact_progress, pu)
                except Exception:
                    pass

            progress_reporter = ProgressReporter(ui_callback=_ui_progress_cb, file_path=progress_path, throttle_s=0.5)
            self._has_progress_reporter = True
        except Exception:
            self._has_progress_reporter = False

        # Run
        try:
            result = run_pipeline(
                ctx,
                notifier=notifier,
                cancel_event=self._cancel_event,
                progress_reporter=progress_reporter,
                pre_count=True,
            )
            cancelled = bool(self._cancel_event and self._cancel_event.is_set())
        except Exception as e:
            result = {"stats": {}, "error": str(e)}
            cancelled = bool(self._cancel_event and self._cancel_event.is_set())
            try:
                notifier.warn(f"Pipeline failed: {e}")
            except Exception:
                pass

        # Finalize on UI thread
        def _finish():
            try:
                if cancelled:
                    self._set_status("Preprocessing cancelled")
                else:
                    self._set_status("Preprocessing completed")
                    try:
                        self.master.current_scan_meta = {"workdir": str(ctx.case_dir), "case_id": case_id}
                    except Exception:
                        pass
                    self.continue_btn.configure(state="normal")
                self.progress.set(1.0)
            except Exception:
                pass
            finally:
                try:
                    self.start_btn.configure(state="normal")
                    self.cancel_btn.configure(state="disabled")
                except Exception:
                    pass

        try:
            self.after(0, _finish)
        except Exception:
            _finish()

    # ------------------------- Notifier / Progress UI ------------------------
    def _handle_notifier_message(self, msg: Message):
        try:
            def _short_path(p: str, max_segs: int = 3) -> str:
                try:
                    pp = Path(p); parts = pp.parts
                    if len(parts) <= max_segs: return pp.as_posix()
                    return f".../{Path(*parts[-max_segs:]).as_posix()}"
                except Exception:
                    return p

            if getattr(msg, "path", None):
                text = f"[{msg.level}] {_short_path(msg.path)} {msg.text}\n"
            else:
                text = f"[{msg.level}] {msg.text}\n"

            # auto-follow if at bottom
            try:
                first, last = self.setup_results_box.yview()
                follow = float(last) >= 0.999
            except Exception:
                follow = True

            self.setup_results_box.insert("end", text)

            try:
                if isinstance(getattr(msg, "details", None), dict):
                    keys = ("sha256", "id", "reason", "ext", "original", "time_s")
                    hints = [f"{k}={msg.details.get(k)}" for k in keys if k in (msg.details or {})]
                    if hints:
                        hint_line = " (" + ", ".join(hints[:3]) + ")\n"
                        try:
                            self.setup_results_box.delete("end-2c", "end-1c")
                        except Exception:
                            pass
                        self.setup_results_box.insert("end", hint_line)
            except Exception:
                pass

            if follow:
                self.setup_results_box.see("end")

            # limit memory
            try:
                lines = int(self.setup_results_box.index("end-1c").split(".")[0])
                if lines > self._results_max:
                    delete_to = lines - self._results_max
                    self.setup_results_box.delete("1.0", f"{delete_to}.0")
            except Exception:
                pass

            # heuristic progress if no reporter
            if not self._has_progress_reporter:
                self._processed_messages += 1
                frac = min(0.95, float(self._processed_messages) / 200.0)
                self.progress.set(frac)
                if self._processed_messages % 20 == 0:
                    self.status_label.configure(text=f"Processing… ({self._processed_messages} msgs)")
        except Exception:
            pass

    def _update_compact_progress(self, pu):
        try:
            self.phase_label.configure(text=f"Phase: {getattr(pu, 'phase', '')}")

            def fmt_time(s):
                try:
                    s = int(s or 0)
                    h = s // 3600; m = (s % 3600) // 60; sec = s % 60
                    return f"{h:02d}:{m:02d}:{sec:02d}"
                except Exception:
                    return str(s)

            elapsed_str = fmt_time(getattr(pu, "elapsed_s", 0))
            total = getattr(pu, "total", None)
            processed = getattr(pu, "processed", 0)
            percent = getattr(pu, "percent", None)
            status = getattr(pu, "status", "")
            eta_s = getattr(pu, "eta_s", None)
            speed = getattr(pu, "speed", None)

            if getattr(pu, "phase", "") == "scanning":
                pct = int(processed or 0) if total else 0
                self.status_label.configure(text=f"Scanning ({pct}%)")
                self.progress.set(min(1.0, (processed or 0) / 100.0))
                self.eta_label.configure(text=f"Elapsed: {elapsed_str}")
            else:
                if total:
                    pct_text = f"{int((percent or 0) * 100)}%" if percent is not None else ""
                    status_text = f" {status}" if status else ""
                    self.status_label.configure(text=f"Processed {processed}/{total} ({pct_text}){status_text}")
                    self.progress.set(percent or 0.0)
                else:
                    self.status_label.configure(text=f"Processed {processed}{(' ' + status) if status else ''}")
                    self.progress.set(min(0.95, float(processed) / 200.0))

                eta_str = fmt_time(eta_s) if eta_s is not None else ""
                spd = f"{speed:.1f} files/s" if speed is not None else ""
                self.eta_label.configure(text=f"Elapsed: {elapsed_str}  {('ETA: ' + eta_str) if eta_str else ''}  {spd}")
        except Exception:
            pass

    # ------------------------- Navigation & hooks ----------------------------
    def _on_continue(self):
        try:
            self.switch_page("detectors")
        except Exception:
            pass

    def on_enter(self):
        # reset UI each time we arrive
        try:
            # Hide progress group until user starts
            if self.progress_frame.winfo_ismapped():
                self.progress_frame.pack_forget()
            self.progress.set(0.0)
            self.status_label.configure(text="")
            self.phase_label.configure(text="")
            self.eta_label.configure(text="")
            self.continue_btn.configure(state="disabled")
            self.setup_results_box.delete("1.0", "end")
            # Keep console hidden unless user opened it
            if self._console_shown:
                self.console_card.pack_forget()
                self.console_toggle_btn.configure(text="Show console")
                self._console_shown = False
        except Exception:
            pass

    def on_resize(self, w, h):
        # Form is centered by the 3x3 grid trick; nothing else needed here.
        pass

    # ------------------------- Clear progress UI -------------------------------

    def _reset_progress_ui(self):
    # hide progress block
        try:
            if self.progress_frame.winfo_ismapped():
                self.progress_frame.pack_forget()
        except Exception:
            pass
        # reset values/text
        try:
            self.progress.set(0.0)
            self.status_label.configure(text="")
            self.phase_label.configure(text="")
            self.eta_label.configure(text="")
        except Exception:
            pass
        # reset console state
        try:
            self.setup_results_box.delete("1.0", "end")
        except Exception:
            pass
        self._processed_messages = 0
        # ensure console is hidden and toggle text is correct
        try:
            if self._console_shown:
                self.console_card.pack_forget()
                self.console_toggle_btn.configure(text="Show console")
                self._console_shown = False
        except Exception:
            pass

