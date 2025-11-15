# src/pages/setup.py
from __future__ import annotations

import threading
import tkinter as tk
from functools import partial
from pathlib import Path
from typing import Optional

from ui.account_bubble import AccountBubble
import customtkinter as ctk

# ---- Theme ---------------------------------------------------------------
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

FORM_WIDTH = 900  # keep comfortable width

class SetupPage(ctk.CTkFrame):
    """
    Safe-by-default Setup page:
      • No heavy top-level imports (auditor.* are imported lazily)
      • No grid/pack mixing in the same parent
      • Progress + console hidden until used
      • All existing functionality preserved
    """

    # ------------------------------ init ----------------------------------
    def __init__(self, master, switch_page_callback):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page_callback

        # Internal state
        self._cancel_event: Optional[threading.Event] = None
        self._console_shown = False
        self._processed_messages = 0
        self._results_max = 5000
        try:
            self._last_browse_dir = str(Path.home())
        except Exception:
            self._last_browse_dir = "."

        # ----- Root layout (pack only in 'content'; grid inside cards) -----
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.pack(fill="both", expand=True)

        header = ctk.CTkFrame(wrapper, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(16, 6))

        ctk.CTkLabel(
            header, text="Setup — Inputs & Preprocessing",
            font=HEADING_FONT, text_color=TEXT
        ).pack(side="left")

        # Account placeholder menu (similar to detectors page)
        self._acct = AccountBubble(self)
        self._acct.mount(top_right_of=self)  # pins to the page’s top-right instead
            # sticks to header’s top-right


        # Sub-header with back button (below title)
        subheader = ctk.CTkFrame(wrapper, fg_color="transparent")
        subheader.pack(fill="x", padx=22, pady=(0, 10))

        ctk.CTkButton(
            subheader, text="← Back to Landing", width=160,
            fg_color="transparent", border_color=OUTLINE_BR, hover_color=OUTLINE_H,
            text_color=TEXT, border_width=1, corner_radius=8,
            command=lambda: (self._on_cancel(), self._reset_progress_ui(), self.switch_page("landing")),
        ).pack(side="left")

        # Centering container (pack this; grid inside it is OK)
        center = ctk.CTkFrame(wrapper, fg_color="transparent")
        center.pack(fill="both", expand=True, padx=22, pady=(0, 10))

        # 3x3 centering grid
        for r in (0, 2): center.grid_rowconfigure(r, weight=1)
        for c in (0, 2): center.grid_columnconfigure(c, weight=1)

        # --------------------------- Form card -----------------------------
        form = ctk.CTkFrame(
            center, fg_color=CARD_BG, border_width=1, border_color=BORDER, corner_radius=12
        )
        form.grid(row=1, column=1, sticky="n")  # top bias for breathing room
        form.configure(width=FORM_WIDTH)
        form.grid_propagate(False)
        form.grid_columnconfigure(1, weight=1)

        # Scope
        ctk.CTkLabel(form, text="Scope", text_color=TEXT, font=BODY_FONT)\
            .grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))

        self.scope_entry = ctk.CTkEntry(form, placeholder_text="Folder to scan (use Browse)")
        self.scope_entry.insert(0, str((Path.cwd() / "case_demo").resolve()))
        self.scope_entry.grid(row=0, column=1, sticky="we", padx=(0, 12), pady=(14, 4))

        ctk.CTkButton(
            form, text="Browse", width=100, fg_color=PRIMARY, hover_color=PRIMARY_H,
            command=self._browse_scope
        ).grid(row=0, column=2, padx=(0, 16))

        # Workdir
        ctk.CTkLabel(form, text="Workdir", text_color=TEXT, font=BODY_FONT)\
            .grid(row=1, column=0, sticky="w", padx=16, pady=(6, 4))

        self.workdir_entry = ctk.CTkEntry(form, placeholder_text="Default work directory")
        self.workdir_entry.insert(0, self._get_default_workdir_safe())
        self.workdir_entry.grid(row=1, column=1, sticky="we", padx=(0, 12), pady=(6, 4))

        wd_btns = ctk.CTkFrame(form, fg_color="transparent")
        wd_btns.grid(row=1, column=2, sticky="e", padx=(0, 16))
        ctk.CTkButton(
            wd_btns, text="Browse", width=88, fg_color=PRIMARY, hover_color=PRIMARY_H,
            command=self._browse_workdir
        ).pack(side="left")
        ctk.CTkButton(
            wd_btns, text="Revert", width=88, fg_color="transparent",
            border_color=OUTLINE_BR, hover_color=OUTLINE_H, text_color=TEXT, border_width=1,
            command=self._revert_workdir
        ).pack(side="left", padx=(8, 0))

        self.workdir_warning = ctk.CTkLabel(form, text="", font=("", 10), text_color=MUTED)
        self.workdir_warning.grid(row=2, column=1, sticky="w", padx=(0, 12), pady=(0, 6))

        # Case meta
        ctk.CTkLabel(form, text="Case ID / Client", text_color=TEXT, font=BODY_FONT)\
            .grid(row=3, column=0, sticky="nw", padx=16, pady=(8, 4))

        meta = ctk.CTkFrame(form, fg_color="transparent")
        meta.grid(row=3, column=1, columnspan=2, sticky="we", padx=(0, 16), pady=(6, 10))
        meta.grid_columnconfigure(0, weight=1)

        self.case_entry = ctk.CTkEntry(meta, placeholder_text="e.g. CASE-001")
        self.case_entry.grid(row=0, column=0, sticky="we")
        self.client_entry = ctk.CTkEntry(meta, placeholder_text="Client name (optional)")
        self.client_entry.grid(row=1, column=0, sticky="we", pady=(6, 0))

        # Preprocessing options (simple checkboxes; advanced dialog optional)
        ctk.CTkLabel(form, text="Preprocessing Options", text_color=TEXT, font=BODY_FONT)\
            .grid(row=4, column=0, sticky="w", padx=16, pady=(6, 4))

        self.extract_archives = tk.BooleanVar(value=True)
        self.fast_scan = tk.BooleanVar(value=False)

        opt_row = ctk.CTkFrame(form, fg_color="transparent")
        opt_row.grid(row=4, column=1, columnspan=1, sticky="we", padx=(0, 16))
        ctk.CTkCheckBox(opt_row, text="Extract archives", variable=self.extract_archives, text_color=TEXT)\
            .grid(row=0, column=0, sticky="w")
        ctk.CTkCheckBox(opt_row, text="Fast scan (skip hashing)", variable=self.fast_scan, text_color=TEXT)\
            .grid(row=0, column=1, sticky="w", padx=(12, 0))

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
            fg_color="transparent", border_color=OUTLINE_BR, hover_color=OUTLINE_H,
            text_color=TEXT, border_width=1, command=self._open_advanced
        ).grid(row=4, column=2, sticky="e", padx=(0, 16))

        # Bottom spacing inside card (grid; no pack in the same parent)
        ctk.CTkFrame(form, height=8, fg_color="transparent")\
            .grid(row=5, column=0, columnspan=3, sticky="ew", padx=16, pady=(0, 12))

        # --------------------------- Actions row ----------------------------
        actions = ctk.CTkFrame(wrapper, fg_color="transparent")
        actions.pack(fill="x", padx=22, pady=(8, 10))

        self.start_btn = ctk.CTkButton(
            actions, text="Start Engagement", fg_color=PRIMARY, hover_color=PRIMARY_H,
            command=self._on_start_clicked
        ); self.start_btn.pack(side="left")

        self.cancel_btn = ctk.CTkButton(
            actions, text="Cancel", state="disabled",
            fg_color="transparent", border_color=OUTLINE_BR, hover_color=OUTLINE_H,
            text_color=TEXT, border_width=1, command=self._on_cancel
        ); self.cancel_btn.pack(side="left", padx=(8, 0))

        self.open_workdir_btn = ctk.CTkButton(
            actions, text="Open workdir",
            fg_color="transparent", border_color=OUTLINE_BR, hover_color=OUTLINE_H,
            text_color=TEXT, border_width=1, command=self._open_workdir
        ); self.open_workdir_btn.pack(side="left", padx=(8, 0))

        self.console_toggle_btn = ctk.CTkButton(
            actions, text="Show console",
            fg_color=PRIMARY, hover_color=PRIMARY_H, text_color="#041007",
            command=self._toggle_console
        ); self.console_toggle_btn.pack(side="left", padx=(8, 0))

        self.continue_btn = ctk.CTkButton(
            actions, text="Continue → Detectors", state="disabled",
            fg_color=PRIMARY, hover_color=PRIMARY_H, command=self._on_continue
        ); self.continue_btn.pack(side="right")

        # --------------------------- Progress group -------------------------
        self.progress_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        # not packed initially (shown on Start)

        self.progress = ctk.CTkProgressBar(self.progress_frame, height=10, corner_radius=10)
        self.progress.pack(fill="x")

        self.status_label = ctk.CTkLabel(self.progress_frame, text="", text_color=MUTED, font=BODY_FONT)
        self.status_label.pack(fill="x", pady=(4, 0))

        phase_row = ctk.CTkFrame(self.progress_frame, fg_color="transparent"); phase_row.pack(fill="x", pady=(2, 0))
        self.phase_label = ctk.CTkLabel(phase_row, text="", text_color=TEXT, font=BODY_FONT); self.phase_label.pack(side="left")
        self.eta_label = ctk.CTkLabel(phase_row, text="", text_color=MUTED, font=BODY_FONT); self.eta_label.pack(side="right")

        # ----------------------------- Console card -------------------------
        self.console_card = ctk.CTkFrame(wrapper, fg_color=CARD_BG, border_width=1, border_color=BORDER, corner_radius=10)
        # not packed initially

        console_header = ctk.CTkFrame(self.console_card, fg_color="transparent")
        console_header.pack(fill="x", padx=12, pady=(10, 0))
        ctk.CTkLabel(console_header, text="Console", text_color=TEXT, font=BODY_FONT).pack(side="left")

        self._console_host = tk.Frame(self.console_card, bg=BG)
        self._console_host.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        self.setup_results_box = tk.Text(
            self._console_host, height=12, wrap="none",
            bg=BG, fg=TEXT, insertbackground=TEXT,
            font=MONO_FONT if MONO_FONT else None, relief=tk.FLAT, padx=8, pady=6
        )
        self.setup_results_box.pack(side="left", fill="both", expand=True)
        self.setup_scrollbar = tk.Scrollbar(self._console_host, orient="vertical", command=self.setup_results_box.yview)
        self.setup_scrollbar.pack(side="right", fill="y")
        self.setup_results_box.configure(yscrollcommand=self.setup_scrollbar.set)

    # ----------------------------- UI helpers ------------------------------
    def _on_profile_change(self, profile: str):
        """Callback for profile/account changes (placeholder)."""
        pass

    def _parent_win(self):
        try: return self.master.winfo_toplevel()
        except Exception: return None

    def _set_status(self, text: str, error: bool = False):
        try: self.status_label.configure(text=text if not error else f"⚠ {text}")
        except Exception: pass

    def _choose_initial_dir(self, entry_val: str) -> str:
        try:
            val = (entry_val or "").strip()
            if val:
                p = Path(val)
                if p.exists() and p.is_dir(): return str(p)
                rp = (Path.cwd() / p).resolve()
                if rp.exists(): return str(rp if rp.is_dir() else rp.parent)
            return self._last_browse_dir or str(Path.home())
        except Exception:
            return self._last_browse_dir or str(Path.home())

    def _browse_scope(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(
            title="Select folder for scope",
            initialdir=self._choose_initial_dir(self.scope_entry.get()),
            parent=self._parent_win(),
        )
        if path:
            self.scope_entry.delete(0, "end"); self.scope_entry.insert(0, path)
            self._last_browse_dir = path

    def _browse_workdir(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(
            title="Select workdir folder",
            initialdir=self._choose_initial_dir(self.workdir_entry.get()),
            parent=self._parent_win(),
        )
        if path:
            self.workdir_entry.delete(0, "end"); self.workdir_entry.insert(0, path)
            self._last_browse_dir = path
            self._check_workdir_canonical()

    def _revert_workdir(self):
        self.workdir_entry.delete(0, "end")
        self.workdir_entry.insert(0, self._get_default_workdir_safe())
        self._check_workdir_canonical()

    def _get_default_workdir_safe(self) -> str:
        """Lazy import default workdir to avoid construction-time crashes."""
        try:
            from auditor.setup_flow.output import get_default_workdir
            # Use getattr with default in case adv_config isn't initialized yet
            adv_cfg = getattr(self, "adv_config", {})
            cs = str(adv_cfg.get("case_subdir", "cases"))
            return str(get_default_workdir(case_subdir=cs))
        except Exception:
            return str((Path.cwd() / "case_demo" / "cases").resolve())

    def _is_within_default_safe(self, wd: str) -> bool:
        try:
            from auditor.setup_flow.output import is_within_default
            cs = str(self.adv_config.get("case_subdir", "cases"))
            return bool(is_within_default(wd, case_subdir=cs))
        except Exception:
            return True  # don't warn if we can't check

    def _check_workdir_canonical(self):
        try:
            wd = (self.workdir_entry.get() or "").strip()
            if not wd: return self.workdir_warning.configure(text="")
            if not self._is_within_default_safe(wd):
                self.workdir_warning.configure(text="Recommendation: use the default workdir (see Advanced → case_subdir).")
            else:
                self.workdir_warning.configure(text="")
        except Exception: pass

    def _open_advanced(self):
        try:
            from .advanced_options import AdvancedOptionsWindow
        except Exception:
            self._set_status("Advanced options unavailable.", True); return

        def _apply(values):
            try:
                values = values or {}
                self.adv_config.update(values)
                self._revert_workdir()
            except Exception:
                pass

        AdvancedOptionsWindow(self._parent_win(), initial=self.adv_config, on_apply=_apply)

    def _open_workdir(self):
        """Open the workdir (case path) in the file explorer."""
        import os
        import sys

        wd = (self.workdir_entry.get() or "").strip() or str(Path.cwd() / "case_demo")
        case_id = (self.case_entry.get() or "").strip() or "CASE-000"

        try:
            # Construct the full case path
            case_path = Path(wd) / case_id

            # Ensure the path exists (create if needed)
            case_path.mkdir(parents=True, exist_ok=True)

            # Convert to absolute path
            case_path = case_path.resolve()

            # Open in file explorer based on platform
            if sys.platform == "win32":
                os.startfile(str(case_path))
            elif sys.platform == "darwin":  # macOS
                os.system(f"open '{case_path}'")
            else:  # Linux and others
                os.system(f"xdg-open '{case_path}'")

            self._set_status(f"✓ Opened: {case_path}")
        except Exception as e:
            self._set_status(f"Could not open folder: {wd} ({str(e)})", True)

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

    # ------------------------------ Actions --------------------------------
    def _on_start_clicked(self):
        # show progress lazily
        try:
            self.progress.set(0.0)
            self.status_label.configure(text="")
            self.phase_label.configure(text="")
            self.eta_label.configure(text="")
            if not self.progress_frame.winfo_ismapped():
                self.progress_frame.pack(fill="x", padx=22, pady=(2, 6))
        except Exception: pass

        # reset console text; keep panel hidden unless toggled
        try: self.setup_results_box.delete("1.0", "end")
        except Exception: pass

        try:
            self.start_btn.configure(state="disabled")
            self.cancel_btn.configure(state="normal")
            self.continue_btn.configure(state="disabled")
        except Exception: pass

        threading.Thread(target=self._start_pipeline_thread, daemon=True).start()

    def _on_cancel(self):
        try:
            if self._cancel_event and not self._cancel_event.is_set():
                self._cancel_event.set()
                self._set_status("Cancelling…")
        except Exception: pass

    # ------------------------- Worker thread -------------------------------
    def _start_pipeline_thread(self):
        # Lazy import all heavy deps here (never at top-level)
        try:
            from auditor.setup_flow.setupcontext import SetupContext
            from auditor.setup_flow.runner import run_pipeline
            from auditor.setup_flow.setupmessages import Notifier, Message
            try:
                from auditor.setup_flow.progress import ProgressReporter
            except Exception:
                ProgressReporter = None  # type: ignore
        except Exception as e:
            self._ui_error(f"Missing auditor modules: {e}")
            return

        # Gather inputs
        wd = (self.workdir_entry.get() or "").strip() or str(Path.cwd() / "case_demo")
        case_id = (self.case_entry.get() or "").strip() or "CASE-000"
        client = (self.client_entry.get() or "").strip() or "SetupUI"
        scope = (self.scope_entry.get() or "").strip() or str(Path.cwd())

        ctx = SetupContext(scope=Path(scope), workdir=Path(wd), case_id=case_id, client=client)
        try: ctx.case_dir = Path(wd) / case_id
        except Exception: ctx.case_dir = Path(wd)

        # Advanced options → config on ctx
        try:
            adv = getattr(self, "adv_config", {}) or {}
            ctx.config.extract_archives = bool(adv.get("extract_archives", True))
            ctx.config.fast_scan = bool(adv.get("fast_scan", False))
            ctx.config.max_extract_depth = int(adv.get("max_extract_depth", 2) or 2)
            ctx.config.build_ast = bool(adv.get("build_ast", False))
            ctx.config.build_disasm = bool(adv.get("build_disasm", False))
            ctx.policy = adv.get("policy")
        except Exception: pass

        # Notifier + optional progress reporter
        try:
            ctx.case_dir.mkdir(parents=True, exist_ok=True)
            notifier_path = ctx.case_dir / "ui.notifier.ndjson"
        except Exception:
            notifier_path = None

        self._cancel_event = threading.Event()

        def ui_cb(msg: Message):
            try: self.after(0, self._handle_notifier_message, msg)
            except Exception: pass

        notifier = Notifier(file_path=str(notifier_path) if notifier_path else None, ui_callback=ui_cb)

        progress_reporter = None
        if 'ProgressReporter' in locals() and ProgressReporter:
            try:
                progress_path = ctx.case_dir / "progress.json" if ctx.case_dir else None

                def _ui_progress_cb(pu):
                    try: self.after(0, self._update_compact_progress, pu)
                    except Exception: pass

                progress_reporter = ProgressReporter(
                    ui_callback=_ui_progress_cb, file_path=progress_path, throttle_s=0.5
                )
            except Exception:
                progress_reporter = None

        # Run pipeline
        try:
            result = run_pipeline(
                ctx, notifier=notifier, cancel_event=self._cancel_event,
                progress_reporter=progress_reporter, pre_count=True,
            )
            cancelled = bool(self._cancel_event and self._cancel_event.is_set())
        except Exception as e:
            result = {"stats": {}, "error": str(e)}
            cancelled = bool(self._cancel_event and self._cancel_event.is_set())
            try: notifier.warn(f"Pipeline failed: {e}")
            except Exception: pass

        # finalize UI on main thread
        try:
            if cancelled:
                self.after(0, self._set_status, "Preprocessing cancelled")
            else:
                self.after(0, self._set_status, "Preprocessing completed")
                # Validate that Setup output files exist
                try:
                    import os

                    case_dir = Path(ctx.case_dir)
                    preproc_dir = case_dir / "preproc"

                    # Validation: check if preproc directory was created
                    files_valid = False
                    validation_msg = ""

                    if preproc_dir.exists() and preproc_dir.is_dir():
                        # Count files in preproc directory
                        preproc_contents = list(preproc_dir.iterdir())
                        if len(preproc_contents) > 0:
                            files_valid = True
                            validation_msg = f"✓ Setup validated: {len(preproc_contents)} file(s) in preproc/"
                        else:
                            validation_msg = "⚠ Warning: preproc/ directory is empty"
                    else:
                        validation_msg = "⚠ Warning: preproc/ directory not found"

                    # Log validation result
                    try:
                        notifier.info(validation_msg)
                    except:
                        pass

                    if files_valid:
                        # enable Continue button and store current scan meta
                        self.master.current_scan_meta = {
                            "workdir": str(ctx.case_dir),
                            "case_id": case_id,
                        }
                        self.after(0, partial(self.continue_btn.configure, state="normal"))
                    else:
                        # Files not valid - don't enable continue button
                        try:
                            notifier.error("Setup validation failed: No files found in preproc/")
                        except:
                            pass
                except Exception as val_err:
                    # Validation error - log but still allow continue (graceful degradation)
                    try:
                        notifier.warn(f"Could not validate setup outputs: {val_err}")
                    except:
                        pass
                    # Allow continue anyway
                    try:
                        self.master.current_scan_meta = {
                            "workdir": str(ctx.case_dir),
                            "case_id": case_id,
                        }
                        self.after(0, partial(self.continue_btn.configure, state="normal"))
                    except Exception:
                        pass
            # mark progress complete
            self.after(0, self.progress.set, 1.0)
        except Exception:
            pass
        finally:
            try:
                self.after(0, partial(self.start_btn.configure, state="normal"))
                self.after(0, partial(self.cancel_btn.configure, state="disabled"))
            except Exception:
                pass

    # ------------------- UI callbacks for pipeline events -------------------
    def _handle_notifier_message(self, msg):
        """Append notifier messages into console; small heuristics for progress."""
        try:
            def _short(p: str, keep: int = 3) -> str:
                try:
                    parts = Path(p).parts
                    return p if len(parts) <= keep else f".../{Path(*parts[-keep:]).as_posix()}"
                except Exception:
                    return p

            level = getattr(msg, "level", "info")
            path = getattr(msg, "path", None)
            text = getattr(msg, "text", "")

            line = f"[{level}] {(_short(path) + ' ') if path else ''}{text}\n"
            # autoscroll detection
            try:
                first, last = self.setup_results_box.yview()
                follow = float(last) >= 0.999
            except Exception:
                follow = True

            self.setup_results_box.insert("end", line)

            det = getattr(msg, "details", None)
            if isinstance(det, dict):
                keys = ("sha256", "id", "reason", "ext", "original", "time_s")
                hints = [f"{k}={det.get(k)}" for k in keys if k in det]
                if hints:
                    try: self.setup_results_box.delete("end-2c", "end-1c")
                    except Exception: pass
                    self.setup_results_box.insert("end", " (" + ", ".join(hints[:3]) + ")\n")

            if follow: self.setup_results_box.see("end")

            # cap memory
            try:
                lines = int(self.setup_results_box.index("end-1c").split(".")[0])
                if lines > self._results_max:
                    self.setup_results_box.delete("1.0", f"{lines - self._results_max}.0")
            except Exception: pass

            # heuristic progress when no reporter
            if getattr(self, "eta_label", None) and getattr(self, "status_label", None):
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

            def tsec(s):
                try:
                    s = int(s or 0); h = s // 3600; m = (s % 3600) // 60; sec = s % 60
                    return f"{h:02d}:{m:02d}:{sec:02d}"
                except Exception:
                    return str(s)

            elapsed = tsec(getattr(pu, "elapsed_s", 0))
            total = getattr(pu, "total", None)
            processed = getattr(pu, "processed", 0)
            percent = getattr(pu, "percent", None)
            status = getattr(pu, "status", "")
            eta_s = getattr(pu, "eta_s", None)
            speed = getattr(pu, "speed", None)
            phase = getattr(pu, "phase", "")

            if phase == "scanning":
                # Scanning phase: processed is 0-100 (simulated animation)
                self.status_label.configure(text=f"Scanning ({int(processed or 0)}%)")
                self.progress.set(min(1.0, (processed or 0) / 100.0))
                self.eta_label.configure(text=f"Elapsed: {elapsed}")
            else:
                # Preprocessing phase: use actual percent if available (total files known)
                if percent is not None:
                    # percent is already 0.0-1.0 from ProgressReporter
                    pct_text = f"{int(percent * 100)}%"
                    self.status_label.configure(text=f"Processed {processed}/{total} {pct_text} {status}".strip())
                    self.progress.set(percent)
                elif total and total > 0:
                    # Fallback: calculate from processed/total if percent not provided
                    calc_percent = min(1.0, float(processed) / float(total))
                    pct_text = f"{int(calc_percent * 100)}%"
                    self.status_label.configure(text=f"Processed {processed}/{total} {pct_text} {status}".strip())
                    self.progress.set(calc_percent)
                else:
                    # No total available: use heuristic progress (0-95%)
                    self.status_label.configure(text=f"Processed {processed} {status}".strip())
                    self.progress.set(min(0.95, float(processed) / 200.0))

                eta = tsec(eta_s) if eta_s is not None else ""
                spd = f"{speed:.1f} files/s" if speed is not None else ""
                self.eta_label.configure(text="  ".join([s for s in (f"Elapsed: {elapsed}", f"ETA: {eta}" if eta else "", spd) if s]))
        except Exception:
            pass

    # ------------------------------ Navigation ------------------------------
    def _on_continue(self):
        try:
            self.switch_page("detectors")
        except Exception:
            pass

    def on_enter(self):
        """Reset ephemeral UI each time the page is shown (prevents stale bars)."""
        try:
            if self.progress_frame.winfo_ismapped():
                self.progress_frame.pack_forget()
            self.progress.set(0.0)
            self.status_label.configure(text="")
            self.phase_label.configure(text="")
            self.eta_label.configure(text="")
            self.continue_btn.configure(state="disabled")
            self.setup_results_box.delete("1.0", "end")
            if self._console_shown:
                self.console_card.pack_forget()
                self.console_toggle_btn.configure(text="Show console")
                self._console_shown = False
        except Exception:
            pass

        # Refresh Account Bubble with the same profile as Detectors / Results
        try:
            app = self.master
            profile = None
            if hasattr(app, "fetch_user_profile"):
                try:
                    profile = app.fetch_user_profile()
                except Exception:
                    profile = None

            if hasattr(self, "_acct") and hasattr(self._acct, "refresh"):
                self._acct.refresh(profile)
        except Exception:
            pass


    def on_resize(self, w, h):
        pass

    # ------------------------------- Utils ----------------------------------
    def _reset_progress_ui(self):
        try:
            if self.progress_frame.winfo_ismapped():
                self.progress_frame.pack_forget()
        except Exception: pass
        try:
            self.progress.set(0.0)
            self.status_label.configure(text="")
            self.phase_label.configure(text="")
            self.eta_label.configure(text="")
        except Exception: pass
        try:
            self.setup_results_box.delete("1.0", "end")
        except Exception: pass
        self._processed_messages = 0
        try:
            if self._console_shown:
                self.console_card.pack_forget()
                self.console_toggle_btn.configure(text="Show console")
                self._console_shown = False
        except Exception: pass

    def _ui_error(self, msg: str):
        # Surface import/runtime errors instead of silently blanking the page
        try:
            self._set_status(msg, True)
            self.console_toggle_btn.configure(text="Hide console")
            if not self._console_shown:
                self.console_card.pack(fill="both", expand=True, padx=22, pady=(6, 16))
                self._console_shown = True
            self.setup_results_box.insert("end", f"[error] {msg}\n")
            self.setup_results_box.see("end")
        except Exception:
            pass
