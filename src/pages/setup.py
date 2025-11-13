from __future__ import annotations

import threading
import tkinter as tk
from functools import partial
from pathlib import Path

# Removed AuditLog/Workspace usage (migrated away from top-level auditor.*)
from auditor.setup_flow.setupcontext import SetupContext
from auditor.setup_flow.runner import run_pipeline
from auditor.setup_flow.setupmessages import Notifier, Message
from auditor.setup_flow.output import get_default_workdir, is_within_default

import customtkinter as ctk  # isort:skip


class SetupPage(ctk.CTkFrame):
    """Setup page: scope selection and preprocessing (Start Engagement).

    This page prepares the case workspace and runs preprocessing. After
    preprocessing completes a Continue button becomes enabled which navigates
    to the Detectors page (which will consume the prepared artifacts).
    """

    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        # Header with a right-aligned accounts/profiles control
        header_fr = ctk.CTkFrame(content, fg_color="transparent")
        header_fr.pack(fill="x", pady=(12, 6))
        header = ctk.CTkLabel(
            header_fr, text="Setup — Inputs & Preprocessing", font=("Roboto", 28)
        )
        header.pack(side="left")
        try:
            from .accounts import AccountsMenu

            acct = AccountsMenu(header_fr, on_profile_change=self._on_profile_change)
            acct.pack(side="right")
        except Exception:
            pass

        # Brief pipeline summary and details link (keeps UI discoverable)
        self.pipeline_label = ctk.CTkLabel(
            content,
            text="Pipeline: Enumerate → Preprocess → (optional) AST/Disasm",
            text_color="#aab",
        )
        self.pipeline_label.pack()

        # Workdir / case / scope
        form = ctk.CTkFrame(content, fg_color="transparent")
        form.pack(padx=12, pady=(6, 6), fill="x")
        form.grid_columnconfigure(1, weight=1)

        # Scope comes first (primary input for scanning)
        ctk.CTkLabel(form, text="Scope:").grid(row=0, column=0, sticky="w")
        self.scope_entry = ctk.CTkEntry(
            form, placeholder_text="Folder to scan (use Browse)"
        )
        try:
            default_scope = str((Path.cwd() / "case_demo").resolve())
        except Exception:
            default_scope = str(Path.home())
        self.scope_entry.insert(0, default_scope)
        self.scope_entry.grid(row=0, column=1, sticky="we", padx=(6, 0))
        self.scope_browse = ctk.CTkButton(
            form, text="Browse", width=90, command=self._browse_scope
        )
        self.scope_browse.grid(row=0, column=2, padx=(8, 0))

        # Workdir is secondary and appears after scope
        ctk.CTkLabel(form, text="Workdir:").grid(row=1, column=0, sticky="w")
        # Use a stacked cell: entry on top, small warning text beneath it
        workdir_cell = ctk.CTkFrame(form, fg_color="transparent")
        workdir_cell.grid(row=1, column=1, sticky="we")
        self.workdir_entry = ctk.CTkEntry(
            workdir_cell, placeholder_text="Select or enter a work directory"
        )
        try:
            # prefer the OS-appropriate default workdir
            default_workdir = str(get_default_workdir())
        except Exception:
            default_workdir = str((Path.cwd() / "case_demo" / "cases").resolve())
        self.workdir_entry.insert(0, default_workdir)
        self.workdir_entry.pack(fill="x")

        # small warning label shown when the selected workdir is outside the canonical path
        self.workdir_warning = ctk.CTkLabel(
            workdir_cell, text="", text_color="#d1b000", font=("Roboto", 10)
        )
        self.workdir_warning.pack(anchor="w", pady=(4, 0))

        # Browse and revert buttons to the right (keep alignment with other rows)
        self.workdir_browse = ctk.CTkButton(
            form, text="Browse", width=90, command=self._browse_workdir
        )
        self.workdir_browse.grid(row=1, column=2, padx=(8, 0))
        self.workdir_revert = ctk.CTkButton(
            form, text="Revert", width=90, command=self._revert_workdir
        )
        self.workdir_revert.grid(row=1, column=3, padx=(8, 0))
        # bind changes to validate and update the warning inline
        try:
            self.workdir_entry.bind("<FocusOut>", lambda e: self._check_workdir_canonical())
            self.workdir_entry.bind("<KeyRelease>", lambda e: self._check_workdir_canonical())
        except Exception:
            pass

        # Case ID and Client come after workdir — compact vertical layout
        ctk.CTkLabel(form, text="Case ID / Client:").grid(
            row=2, column=0, sticky="nw"
        )
        meta = ctk.CTkFrame(form, fg_color="transparent")
        meta.grid(row=2, column=1, columnspan=3, sticky="w", padx=(6, 0), pady=(8, 12))

        # smaller, stacked fields (closer together vertically)
        self.case_entry = ctk.CTkEntry(meta, width=260, placeholder_text="e.g. CASE-001")
        self.case_entry.grid(row=0, column=0, sticky="w")
        self.client_entry = ctk.CTkEntry(
            meta, width=260, placeholder_text="Client name (optional)"
        )
        self.client_entry.grid(row=1, column=0, sticky="w", pady=(6, 0))

        # Preproc options
        ctk.CTkLabel(form, text="Preproc Options:").grid(row=3, column=0, sticky="w")
        opts = ctk.CTkFrame(form, fg_color="transparent")
        opts.grid(row=3, column=1, sticky="we", padx=(6, 0))
        self.extract_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(opts, text="Extract archives", variable=self.extract_var).grid(
            row=0, column=0, sticky="w"
        )
        self.fast_scan_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opts, text="Fast scan (no hashing)", variable=self.fast_scan_var
        ).grid(row=0, column=3, sticky="w", padx=(8, 0))
        # Keep main page simple: expose only basic preproc options.
        # Advanced options (policy, max depth, AST/disasm generation) are
        # tucked behind a collapsible 'Advanced options' panel to avoid
        # overwhelming non-technical users.
        ctk.CTkLabel(form, text="Preproc Options:").grid(row=3, column=0, sticky="w")
        opts = ctk.CTkFrame(form, fg_color="transparent")
        opts.grid(row=3, column=1, sticky="we", padx=(6, 0))
        self.extract_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(opts, text="Extract archives", variable=self.extract_var).grid(
            row=0, column=0, sticky="w"
        )
        self.fast_scan_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opts, text="Fast scan (no hashing)", variable=self.fast_scan_var
        ).grid(row=0, column=1, sticky="w", padx=(8, 0))

        # Advanced options are shown in a dedicated popup window
        self.adv_config = {
            "policy": "",
            "extract_archives": True,
            "fast_scan": False,
            "max_extract_depth": 2,
            "build_ast": False,
            "build_disasm": False,
        }
        self._advanced_btn = ctk.CTkButton(form, text="Advanced options…", width=200, command=self._open_advanced)
        self._advanced_btn.grid(row=3, column=2, columnspan=2, sticky="w", padx=(8, 0))

        # Actions
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(pady=(8, 8))
        self.start_btn = ctk.CTkButton(
            actions, text="Start Engagement", command=self._on_start_clicked
        )
        self.start_btn.pack(side="left", padx=(0, 8))
        self.cancel_btn = ctk.CTkButton(
            actions, text="Cancel", command=(lambda: None), state="disabled"
        )
        self.cancel_btn.pack(side="left", padx=(0, 8))
        self.continue_btn = ctk.CTkButton(
            actions,
            text="Continue → Detectors",
            command=self._on_continue,
            state="disabled",
        )
        self.continue_btn.pack(side="left", padx=(8, 0))
        self.open_workdir_btn = ctk.CTkButton(
            actions, text="Open workdir", command=self._open_workdir
        )
        self.open_workdir_btn.pack(side="left", padx=(8, 0))

        # Progress
        self.progress_label = ctk.CTkLabel(content, text="")
        self.progress_label.pack(pady=(6, 2))
        self.progress = ctk.CTkProgressBar(content, width=480)
        self.progress.pack(pady=(2, 12))
        self.progress.set(0.0)

        # Phase and ETA
        self.phase_label = ctk.CTkLabel(content, text="")
        self.phase_label.pack()
        self.eta_label = ctk.CTkLabel(content, text="")
        self.eta_label.pack()

        # Small spinner label (improved animation) - kept lightweight so tests don't depend on CTk specifics
        self._spinner_label = ctk.CTkLabel(content, text="")
        self._spinner_label.pack()
        self._spinner_running = False
        # smoother spinner characters
        self._spinner_chars = ("◐", "◓", "◑", "◒")
        self._spinner_index = 0
        # Results buffer for throttled display
        self._results_buffer = []
        # console history cap (maximum number of lines to keep)
        # set a sensible default to avoid unbounded memory growth during long runs
        self._results_max = 5000

        self._enum_start_time = None
        self._preproc_start_time = None

        # Console toggle and Separate results box for Setup page (collapsible)
        self._console_shown = True
        self._console_toggle = ctk.CTkButton(content, text="Hide console messages", width=220, command=self._toggle_console)
        self._console_toggle.pack(pady=(6, 0))

        # Create a console frame that contains a Text widget and a vertical scrollbar
        self._console_frame = tk.Frame(content)
        self._console_frame.pack(fill="both", padx=12, pady=(6, 12), expand=False)
        # Text widget for messages
        self.setup_results_box = tk.Text(self._console_frame, height=10, wrap="none")
        self.setup_results_box.pack(side="left", fill="both", expand=True)
        # Scrollbar linked to the text widget
        self.setup_scrollbar = tk.Scrollbar(self._console_frame, orient="vertical", command=self.setup_results_box.yview)
        self.setup_scrollbar.pack(side="right", fill="y")
        # let the Text widget update the scrollbar; we will check yview at insert time
        self.setup_results_box.configure(yscrollcommand=self.setup_scrollbar.set)

        # internal state
        self._cancel_event = None
        # simple processed-counter for UI progress estimation (increments per notifier message)
        self._processed_messages = 0
        # whether a ProgressReporter was created for this run
        self._has_progress_reporter = False
        # cache last folder used by browse dialogs to avoid slow initialdir
        try:
            self._last_browse_dir = str(Path.home())
        except Exception:
            self._last_browse_dir = "."

    def _browse_scope(self):
        # Use filedialog with a parent and initialdir to reduce platform
        # overhead and avoid long hangs on Windows when opening the dialog.
        from tkinter import filedialog

        # Prefer the directory already present in the entry (if any).
        try:
            entry_val = self.scope_entry.get().strip()
        except Exception:
            entry_val = ""
        initial = None
        try:
            if entry_val:
                p = Path(entry_val)
                # if path exists and is dir, use it
                if p.exists() and p.is_dir():
                    initial = str(p)
                else:
                    # try resolving relative to cwd; if that exists use it or its parent
                    try:
                        rp = (Path.cwd() / p).resolve()
                        if rp.exists():
                            initial = str(rp if rp.is_dir() else rp.parent)
                    except Exception:
                        pass
            # fall back to last browse dir or home
            if not initial:
                initial = self._last_browse_dir or str(Path.home())
        except Exception:
            initial = self._last_browse_dir or str(Path.home())
        # parent helps the native dialog attach to the main window
        try:
            parent = self.master.winfo_toplevel()
        except Exception:
            parent = None
        path = filedialog.askdirectory(title="Select folder for scope", initialdir=initial, parent=parent)

        if path:
            # update entry through .after to ensure the UI remains responsive
            self.after(0, lambda: (self.scope_entry.delete(0, "end"), self.scope_entry.insert(0, path)))
            # update cached last dir to speed up subsequent dialogs
            try:
                self._last_browse_dir = path
            except Exception:
                pass

    def _browse_workdir(self):
        # Browse button for workdir (select a folder)
        from tkinter import filedialog

        # Prefer the directory already present in the workdir entry (if any).
        try:
            entry_val = self.workdir_entry.get().strip()
        except Exception:
            entry_val = ""
        initial = None
        try:
            if entry_val:
                p = Path(entry_val)
                if p.exists() and p.is_dir():
                    initial = str(p)
                else:
                    try:
                        rp = (Path.cwd() / p).resolve()
                        if rp.exists():
                            initial = str(rp if rp.is_dir() else rp.parent)
                    except Exception:
                        pass
            if not initial:
                initial = self._last_browse_dir or str(Path.home())
        except Exception:
            initial = self._last_browse_dir or str(Path.home())
        try:
            parent = self.master.winfo_toplevel()
        except Exception:
            parent = None
        path = filedialog.askdirectory(title="Select workdir folder", initialdir=initial, parent=parent)

        if path:
            self.after(0, lambda: (self.workdir_entry.delete(0, "end"), self.workdir_entry.insert(0, path)))
            try:
                self._last_browse_dir = path
            except Exception:
                pass

    def _check_workdir_canonical(self):
        """Check whether the current workdir is within the OS canonical path and
        update the inline warning label. Logic for canonical path lives in
        `auditor.setup_flow.output.get_default_workdir` / `is_within_default`.
        """
        try:
            wd = self.workdir_entry.get().strip()
            if not wd:
                self.workdir_warning.configure(text="")
                return
            try:
                # use the active case_subdir from advanced options when available
                try:
                    cs = (getattr(self, 'adv_config', {}) or {}).get('case_subdir', 'cases')
                except Exception:
                    cs = 'cases'
                ok = is_within_default(wd, case_subdir=cs)
            except Exception:
                ok = False
            if not ok:
                default = str(get_default_workdir(case_subdir=cs))
                self.workdir_warning.configure(text=f"Recommendation: use the default workdir {default}")
            else:
                self.workdir_warning.configure(text="")
        except Exception:
            pass

    def _revert_workdir(self):
        """Revert the workdir entry to the canonical default path."""
        try:
            default = str(get_default_workdir())
            self.workdir_entry.delete(0, "end")
            self.workdir_entry.insert(0, default)
            # validate and clear the warning
            try:
                self._check_workdir_canonical()
            except Exception:
                pass
        except Exception:
            pass

    def _toggle_advanced(self):
        # legacy toggle removed; advanced options are handled in a popup
        return

    def _open_advanced(self):
        try:
            from .advanced_options import AdvancedOptionsWindow

            def _apply(values):
                try:
                    # simple validation and store
                    self.adv_config.update(values or {})
                    # if the case_subdir changed, update the workdir entry to the canonical default
                    try:
                        cs = str((values or {}).get('case_subdir') or self.adv_config.get('case_subdir') or 'cases')
                        from auditor.setup_flow.output import get_default_workdir

                        new_wd = str(get_default_workdir(case_subdir=cs))
                        # update the entry on the main UI thread
                        self.after(0, lambda: (self.workdir_entry.delete(0, 'end'), self.workdir_entry.insert(0, new_wd), self._check_workdir_canonical()))
                    except Exception:
                        pass
                except Exception:
                    pass

            AdvancedOptionsWindow(self.master.winfo_toplevel(), initial=self.adv_config, on_apply=_apply)
        except Exception:
            pass

    def _on_profile_change(self, profile_name: str):
        # Placeholder: when the AccountsMenu selection changes we could load
        # a global profile in the future. For now we simply record it.
        try:
            self._active_profile = profile_name
            # future: load and apply profile modules.setup into adv_config
        except Exception:
            pass

    def _open_workdir(self):
        # Open the canonical case workspace in the platform file browser
        import webbrowser
        from pathlib import Path

        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        try:
            # Derive the case root from workdir + case_id. If the workdir already
            # points to the case root (its name matches case_id) use it directly.
            p = Path(wd)
            if p.exists() and p.name == case_id:
                case_dir = p
            else:
                case_dir = p / case_id
            # ensure folder exists so explorer can open it
            case_dir.mkdir(parents=True, exist_ok=True)
            webbrowser.open(case_dir.as_uri())
        except Exception:
            try:
                self._set_status(f"Could not open folder: {wd}", error=True)
            except Exception:
                pass

    def _set_status(self, text: str, error: bool = False):
        # reuse same status label area as progress_label
        try:
            self.progress_label.configure(text=text)
        except Exception:
            pass

    def _on_start_clicked(self):
        # Minimal integration: prepare a SetupContext, create a notifier that
        # persists messages under the case_dir, and start the pipeline in a
        # background thread. Nothing should block the UI thread.
        try:
            # reset UI
            self.setup_results_box.delete("1.0", "end")
            self.progress.set(0.0)
            self.phase_label.configure(text="")
            self.eta_label.configure(text="")
            self._processed_messages = 0
        except Exception:
            pass

        # disable start and enable cancel
        try:
            self.start_btn.configure(state="disabled")
            self.cancel_btn.configure(state="normal")
        except Exception:
            pass

        # start background thread that runs the pipeline
        t = threading.Thread(target=self._start_pipeline_thread, daemon=True)
        t.start()

    def _start_pipeline_thread(self):
        # gather UI values and build a SetupContext
        from pathlib import Path

        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        client = self.client_entry.get().strip() or "SetupUI"
        scope = self.scope_entry.get().strip() or str(Path.cwd())

        ctx = SetupContext(scope=Path(scope), workdir=Path(wd), case_id=case_id, client=client)
        # set case_dir to a sensible default (workdir / case_id)
        try:
            ctx.case_dir = Path(wd) / case_id
        except Exception:
            ctx.case_dir = Path(wd)

        # propagate advanced options into ctx.config
        try:
            adv = getattr(self, "adv_config", {}) or {}
            ctx.config.extract_archives = bool(adv.get("extract_archives", True))
            ctx.config.fast_scan = bool(adv.get("fast_scan", False))
            ctx.config.max_extract_depth = int(adv.get("max_extract_depth", 2) or 2)
            ctx.config.build_ast = bool(adv.get("build_ast", False))
            ctx.config.build_disasm = bool(adv.get("build_disasm", False))
            # policy is UI-only for now; if provided we can store it under ctx
            try:
                ctx.policy = adv.get("policy")
            except Exception:
                pass
        except Exception:
            pass

        # prepare notifier persisted under case_dir
        try:
            case_dir = ctx.case_dir
            case_dir.mkdir(parents=True, exist_ok=True)
            notifier_path = case_dir / "ui.notifier.ndjson"
        except Exception:
            notifier_path = None

        # create threading event for cancellation
        self._cancel_event = threading.Event()

        # ui_callback will be called from worker threads; marshal to mainloop
        def ui_cb(msg: Message):
            try:
                # schedule UI update on main thread
                self.after(0, self._handle_notifier_message, msg)
            except Exception:
                pass

        notifier = Notifier(file_path=str(notifier_path) if notifier_path else None, ui_callback=ui_cb)

        # prepare progress reporter persisted under case_dir/progress.json
        try:
            from auditor.setup_flow.progress import ProgressReporter

            progress_path = (case_dir / "progress.json") if case_dir is not None else None

            def _ui_progress_cb(pu):
                try:
                    # schedule compact progress update on main thread
                    self.after(0, self._update_compact_progress, pu)
                except Exception:
                    pass

            # use 0.5s throttle for preprocessing updates as requested
            progress_reporter = ProgressReporter(ui_callback=_ui_progress_cb, file_path=progress_path, throttle_s=0.5)
            # remember that we have a reporter so notifier heuristic doesn't drive the bar
            try:
                self._has_progress_reporter = True
            except Exception:
                pass
        except Exception:
            progress_reporter = None

        # run the pipeline (best-effort). run_pipeline returns result dict
        try:
            result = run_pipeline(ctx, notifier=notifier, cancel_event=self._cancel_event, progress_reporter=progress_reporter, pre_count=True)
            cancelled = bool(self._cancel_event and self._cancel_event.is_set())
        except Exception as e:
            result = {"stats": {}}
            cancelled = bool(self._cancel_event and self._cancel_event.is_set())
            try:
                notifier.warn(f"Pipeline failed: {e}")
            except Exception:
                pass

        # finalize UI on main thread
        try:
            if cancelled:
                self.after(0, self._set_status, "Preprocessing cancelled")
            else:
                self.after(0, self._set_status, "Preprocessing completed")
                # Validate that Setup output files exist
                try:
                    import os
                    from pathlib import Path

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

    def _handle_notifier_message(self, msg: Message):
        # Append a readable line to the results box and update a simple progress
        try:
            # Format message with shortened path and structured indentation
            def _short_path(p: str, max_segs: int = 3) -> str:
                try:
                    from pathlib import Path as _P

                    pp = _P(p)
                    parts = pp.parts
                    if len(parts) <= max_segs:
                        return pp.as_posix()
                    else:
                        tail = _P(*parts[-max_segs:]).as_posix()
                        return f".../{tail}"
                except Exception:
                    return p

            label = f"[{msg.level}]"
            if msg.path:
                short = _short_path(msg.path)
                # Align level to 6 chars for nicer columns; show short path and main message inline
                lvl = f"{msg.level}".ljust(6)
                # Keep output concise: single line per message (no multiline details)
                text = f"[{lvl}] {short} {msg.text}\n"
            else:
                text = f"[{msg.level}] {msg.text}\n"
            try:
                # determine if the view is currently at the bottom (so we should follow)
                try:
                    first, last = self.setup_results_box.yview()
                    follow = float(last) >= 0.999
                except Exception:
                    follow = True

                # insert main line
                self.setup_results_box.insert("end", text)
                # Do not print details as separate lines to keep each file on one line.
                # If details contain a short keyword we can append a compact hint (optional).
                try:
                    if isinstance(getattr(msg, "details", None), dict):
                        # prefer to surface a small hint like 'sha256' or 'id' or 'reason'
                        hint_keys = ("sha256", "id", "reason", "ext", "original", "time_s")
                        hints = []
                        for k in hint_keys:
                            if k in (msg.details or {}):
                                v = msg.details.get(k)
                                hints.append(f"{k}={v}")
                        if hints:
                            hint_line = " (" + ", ".join(hints[:3]) + ")\n"
                            # append hint to the same line: remove trailing newline and add hint
                            try:
                                # get current end index, replace last inserted newline with hint
                                self.setup_results_box.delete("end-2c", "end-1c")
                                self.setup_results_box.insert("end", hint_line)
                            except Exception:
                                # fallback: just append as new small line
                                try:
                                    self.setup_results_box.insert("end", hint_line)
                                except Exception:
                                    pass
                except Exception:
                    pass

                # auto-scroll only when the user is at the bottom
                try:
                    if follow:
                        self.setup_results_box.see("end")
                except Exception:
                    pass

                # enforce history cap: delete oldest lines if we exceed self._results_max
                try:
                    lines = int(self.setup_results_box.index('end-1c').split('.')[0])
                    if lines > self._results_max:
                        # delete top lines to keep only the most recent self._results_max
                        delete_to = lines - self._results_max
                        self.setup_results_box.delete('1.0', f'{delete_to}.0')
                except Exception:
                    pass
            except Exception:
                pass

            # simple progress heuristic: increment processed count and map to 0..0.95
            try:
                # only use notifier-driven heuristic when no ProgressReporter is present
                if not getattr(self, "_has_progress_reporter", False):
                    self._processed_messages += 1
                    frac = min(0.95, float(self._processed_messages) / 200.0)
                    self.progress.set(frac)
            except Exception:
                pass
        except Exception:
            pass

    def _on_cancel_clicked(self):
        try:
            if self._cancel_event:
                self._cancel_event.set()
            self.cancel_btn.configure(state="disabled")
            self._set_status("Cancellation requested — stopping")
        except Exception:
            pass

    def _on_console_user_action(self, event=None):
        # Called when the user interacts with the console (scroll/drag)
        try:
            self._console_follow = False
        except Exception:
            pass

    def _on_text_scroll(self, first, last):
        # yscrollcommand handler: updates scrollbar and track whether view is at bottom
        try:
            try:
                self.setup_scrollbar.set(first, last)
            except Exception:
                pass
            try:
                if float(last) >= 0.999:
                    self._console_follow = True
            except Exception:
                pass
        except Exception:
            pass

    def _toggle_console(self):
        try:
            if self._console_shown:
                try:
                    self._console_frame.pack_forget()
                except Exception:
                    pass
                self._console_toggle.configure(text="Show console messages")
                self._console_shown = False
            else:
                try:
                    self._console_frame.pack(fill="both", padx=12, pady=(6, 12), expand=False)
                except Exception:
                    pass
                self._console_toggle.configure(text="Hide console messages")
                self._console_shown = True
        except Exception:
            pass

    def _update_compact_progress(self, pu):
        try:
            # phase label
            try:
                self.phase_label.configure(text=f"Phase: {pu.phase}")
            except Exception:
                pass
            # status line and progress bar
            try:
                status = pu.status or ""
                # format elapsed and eta into HH:MM:SS
                def fmt_time(s):
                    try:
                        s = int(s or 0)
                        h = s // 3600
                        m = (s % 3600) // 60
                        sec = s % 60
                        return f"{h:02d}:{m:02d}:{sec:02d}"
                    except Exception:
                        return str(s)

                elapsed_str = fmt_time(pu.elapsed_s)

                if pu.phase == "scanning":
                    # scanning phase: display scanning message and have progress go 0..100
                    pct = int((pu.processed or 0)) if pu.total else 0
                    self.progress_label.configure(text=f"Scanning ({pct}%)")
                    # map 0..100 to 0..1.0
                    self.progress.set(min(1.0, (pu.processed or 0) / 100.0))
                    self.eta_label.configure(text=f"Elapsed: {elapsed_str}")
                else:
                    if pu.total:
                        pct = f"{int((pu.percent or 0)*100)}%" if pu.percent is not None else ""
                        # remove dash and status separator; show message after percentage when present
                        status_text = f" {status}" if status else ""
                        self.progress_label.configure(text=f"Processed {pu.processed}/{pu.total} ({pct}){status_text}")
                        # progress bar follows the accurate percent
                        self.progress.set(pu.percent or 0.0)
                    else:
                        self.progress_label.configure(text=f"Processed {pu.processed}{(' ' + status) if status else ''}")
                        self.progress.set(min(0.95, float(pu.processed) / 200.0))

                    # ETA and speed: format time and files/s
                    try:
                        eta_str = fmt_time(pu.eta_s) if pu.eta_s is not None else ""
                        speed = f"{pu.speed:.1f} files/s" if pu.speed is not None else ""
                        self.eta_label.configure(text=f"Elapsed: {elapsed_str}  {('ETA: ' + eta_str) if eta_str else ''}  Speed: {speed}")
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass

    # NOTE: _on_cancel_clicked, _start_spinner and _stop_spinner removed.
    # These functions were intentionally stripped so the start/cancel
    # spinner behaviour can be redesigned and reintroduced later.

    def _on_continue(self):
        # navigate to detectors page; Detectors page will read master.current_scan_meta
        try:
            self.switch_page("detectors")
        except Exception:
            pass

    def on_enter(self):
        # reset UI when entering the page
        try:
            self.progress.set(0.0)
            self.progress_label.configure(text="")
            try:
                self.setup_results_box.delete("1.0", "end")
            except Exception:
                pass
            self.continue_btn.configure(state="disabled")
        except Exception:
            pass
