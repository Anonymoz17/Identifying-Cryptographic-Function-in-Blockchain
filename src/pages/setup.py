from __future__ import annotations

import threading
import tkinter as tk
from functools import partial
from pathlib import Path

from auditor.auditlog import AuditLog
from auditor.workspace import Workspace
from auditor.setup_flow.setupcontext import SetupContext
from auditor.setup_flow.runner import run_pipeline
from auditor.setup_flow.setupmessages import Notifier, Message

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

        header = ctk.CTkLabel(
            content, text="Setup — Inputs & Preprocessing", font=("Roboto", 28)
        )
        header.pack(pady=(12, 6))

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
        self.workdir_entry = ctk.CTkEntry(
            form, placeholder_text="Select or enter a work directory"
        )
        try:
            default_workdir = str((Path.cwd() / "case_demo" / "cases").resolve())
        except Exception:
            default_workdir = str(Path.home() / "CryptoScope" / "cases")
        self.workdir_entry.insert(0, default_workdir)
        self.workdir_entry.grid(row=1, column=1, sticky="we", padx=(6, 0))
        self.workdir_browse = ctk.CTkButton(
            form, text="Browse", width=90, command=self._browse_workdir
        )
        self.workdir_browse.grid(row=1, column=2, padx=(8, 0))

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

        # Advanced options toggle
        self._advanced_shown = False
        self._advanced_btn = ctk.CTkButton(
            form,
            text="Show advanced options ▾",
            width=200,
            command=self._toggle_advanced,
        )
        self._advanced_btn.grid(row=3, column=2, columnspan=2, sticky="w", padx=(8, 0))

        # Advanced options frame (hidden by default)
        self._advanced_frame = ctk.CTkFrame(content, fg_color="#111214")
        # Policy baseline (advanced)
        ctk.CTkLabel(self._advanced_frame, text="Policy (advanced):").grid(
            row=0, column=0, sticky="w"
        )
        self.policy_entry = ctk.CTkEntry(
            self._advanced_frame, placeholder_text="Optional policy baseline (JSON)"
        )
        self.policy_entry.grid(row=0, column=1, sticky="we", padx=(6, 0))
        self.policy_browse = ctk.CTkButton(
            self._advanced_frame, text="Browse", width=90, command=self._browse_policy
        )
        self.policy_browse.grid(row=0, column=2, padx=(8, 0))

        # Max depth and optional caches (advanced)
        ctk.CTkLabel(self._advanced_frame, text="Max extract depth:").grid(
            row=1, column=0, sticky="w"
        )
        self.max_depth_entry = ctk.CTkEntry(self._advanced_frame, width=80)
        self.max_depth_entry.insert(0, "2")
        self.max_depth_entry.grid(row=1, column=1, sticky="w", padx=(6, 0))

        self.ast_var = tk.BooleanVar(value=False)
        self.disasm_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            self._advanced_frame, text="Generate AST cache", variable=self.ast_var
        ).grid(row=2, column=0, sticky="w", pady=(6, 0))
        ctk.CTkCheckBox(
            self._advanced_frame, text="Generate disasm cache", variable=self.disasm_var
        ).grid(row=2, column=1, sticky="w", pady=(6, 0))

        # ensure grid expands nicely
        try:
            self._advanced_frame.grid_columnconfigure(1, weight=1)
        except Exception:
            pass

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
        # keep only the last N lines in the results box to avoid unbounded growth
        self._results_max = 200
        self._enum_start_time = None
        self._preproc_start_time = None

        # Console toggle and Separate results box for Setup page (collapsible)
        self._console_shown = True
        self._console_toggle = ctk.CTkButton(content, text="Hide console messages", width=220, command=self._toggle_console)
        self._console_toggle.pack(pady=(6, 0))
        self.setup_results_box = tk.Text(content, height=10, wrap="none")
        self.setup_results_box.pack(fill="both", padx=12, pady=(6, 12), expand=False)

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

    def _browse_policy(self):
        from tkinter import filedialog

        path = filedialog.askopenfilename(title="Select policy baseline (JSON)")
        if path:
            try:
                self.policy_entry.delete(0, "end")
                self.policy_entry.insert(0, path)
            except Exception:
                pass

    def _toggle_advanced(self):
        try:
            if self._advanced_shown:
                # hide
                try:
                    self._advanced_frame.pack_forget()
                except Exception:
                    pass
                self._advanced_btn.configure(text="Show advanced options ▾")
                self._advanced_shown = False
            else:
                # show
                try:
                    self._advanced_frame.pack(fill="x", padx=12, pady=(6, 6))
                except Exception:
                    pass
                self._advanced_btn.configure(text="Hide advanced options ▴")
                self._advanced_shown = True
        except Exception:
            pass

    def _open_workdir(self):
        # Open the canonical case workspace in the platform file browser
        import webbrowser
        from pathlib import Path

        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        try:
            ws = Workspace(Path(wd), case_id)
            ws.ensure()
            webbrowser.open(ws.root.as_uri())
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

        # propagate extract archives option
        try:
            ctx.config.extract_archives = bool(self.extract_var.get())
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
                # enable Continue button and store current scan meta
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
            text = f"[{msg.level}]"
            if msg.path:
                text = f"{text} {msg.path} - {msg.text}\n"
            else:
                text = f"{text} {msg.text}\n"
            try:
                self.setup_results_box.insert("end", text)
                # keep the buffer size bounded
                lines = int(self.setup_results_box.index('end-1c').split('.')[0])
                if lines > self._results_max:
                    # delete top lines
                    self.setup_results_box.delete('1.0', f'{lines - self._results_max}.0')
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

    def _toggle_console(self):
        try:
            if self._console_shown:
                try:
                    self.setup_results_box.pack_forget()
                except Exception:
                    pass
                self._console_toggle.configure(text="Show console messages")
                self._console_shown = False
            else:
                try:
                    self.setup_results_box.pack(fill="both", padx=12, pady=(6, 12), expand=False)
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
