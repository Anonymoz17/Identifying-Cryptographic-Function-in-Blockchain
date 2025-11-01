from __future__ import annotations

import threading
import tkinter as tk
from functools import partial
from pathlib import Path

from auditor.auditlog import AuditLog
from auditor.case import Engagement
from auditor.intake import count_inputs, enumerate_inputs_iter
from auditor.preproc import preprocess_items
from auditor.workspace import Workspace

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
        self.pipeline_details = ctk.CTkButton(
            content, text="Details…", width=90, command=self._open_pipeline_docs
        )
        self.pipeline_details.pack(pady=(2, 8))

        # Workdir / case / scope
        form = ctk.CTkFrame(content, fg_color="transparent")
        form.pack(padx=12, pady=(6, 6), fill="x")
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Workdir:").grid(row=0, column=0, sticky="w")
        self.workdir_entry = ctk.CTkEntry(
            form, placeholder_text="Select or enter a work directory"
        )
        try:
            default_workdir = str((Path.cwd() / "case_demo" / "cases").resolve())
        except Exception:
            default_workdir = str(Path.home() / "CryptoScope" / "cases")
        self.workdir_entry.insert(0, default_workdir)
        self.workdir_entry.grid(row=0, column=1, sticky="we", padx=(6, 0))

        ctk.CTkLabel(form, text="Case ID:").grid(row=1, column=0, sticky="w")
        self.case_entry = ctk.CTkEntry(form, placeholder_text="e.g. CASE-001")
        self.case_entry.grid(row=1, column=1, sticky="we", padx=(6, 0))

        ctk.CTkLabel(form, text="Client: ").grid(row=1, column=2, sticky="w")
        self.client_entry = ctk.CTkEntry(
            form, placeholder_text="Client name (optional)"
        )
        self.client_entry.grid(row=1, column=3, sticky="we", padx=(6, 0))

        ctk.CTkLabel(form, text="Scope:").grid(row=2, column=0, sticky="w")
        self.scope_entry = ctk.CTkEntry(
            form, placeholder_text="Folder to scan (use Browse)"
        )
        try:
            default_scope = str((Path.cwd() / "case_demo").resolve())
        except Exception:
            default_scope = str(Path.home())
        self.scope_entry.insert(0, default_scope)
        self.scope_entry.grid(row=2, column=1, sticky="we", padx=(6, 0))
        self.scope_browse = ctk.CTkButton(
            form, text="Browse", width=90, command=self._browse_scope
        )
        self.scope_browse.grid(row=2, column=2, padx=(8, 0))

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
            actions, text="Cancel", command=self._on_cancel_clicked, state="disabled"
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

        # Results buffer for summary-only / throttled display
        self.summary_only_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            content, text="Summary-only", variable=self.summary_only_var
        ).pack()
        self._results_buffer = []
        # keep only the last N lines in the results box to avoid unbounded growth
        self._results_max = 200
        self._enum_start_time = None
        self._preproc_start_time = None

        self.results_box = tk.Text(content, height=10, wrap="none")
        self.results_box.pack(fill="both", padx=12, pady=(6, 12), expand=False)

        # internal state
        self._cancel_event = None

    def _browse_scope(self):
        from tkinter import filedialog

        path = filedialog.askdirectory(title="Select folder for scope")
        if path:
            self.scope_entry.delete(0, "end")
            self.scope_entry.insert(0, path)

    def _browse_policy(self):
        from tkinter import filedialog

        path = filedialog.askopenfilename(title="Select policy baseline (JSON)")
        if path:
            try:
                self.policy_entry.delete(0, "end")
                self.policy_entry.insert(0, path)
            except Exception:
                pass

    def _open_pipeline_docs(self):
        # Open the pipeline documentation file if present
        try:
            import webbrowser
            from pathlib import Path

            doc = Path(__file__).parent.parent / "docs" / "pipeline.md"
            if doc.exists():
                webbrowser.open(doc.resolve().as_uri())
            else:
                # fallback: open repository README
                webbrowser.open(
                    (Path(__file__).parent.parent / "README.md").resolve().as_uri()
                )
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
        # Start background engagement without doing a blocking pre-count.
        # For very large scopes counting can itself be expensive, so we stream
        # enumeration updates into the UI instead of calling count_inputs()
        scope = self.scope_entry.get().strip() or "."
        self.results_box.delete("1.0", "end")
        self.results_box.insert("end", f"Starting scan for: {scope}\n")
        self._set_status("Starting engagement (background)...")
        self._cancel_event = threading.Event()
        self.cancel_btn.configure(state="normal")
        self.start_btn.configure(state="disabled")
        # start spinner/animation and reset timers
        try:
            self._enum_start_time = None
            self._preproc_start_time = None
            self._start_spinner()
        except Exception:
            pass
        t = threading.Thread(target=self._run_engagement_flow, daemon=True)
        t.start()

    def _run_engagement_flow(self):
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        client = self.client_entry.get().strip() or "SetupUI"
        scope = self.scope_entry.get().strip() or str(Path.cwd())

        try:
            eng = Engagement(workdir=wd, case_id=case_id, client=client, scope=scope)
            eng.write_metadata()
            # import optional policy baseline
            try:
                policy = self.policy_entry.get().strip()
            except Exception:
                policy = ""
            if policy:
                try:
                    eng.import_policy_baseline(policy)
                except Exception:
                    pass
            case_dir = eng.workdir
            auditlog_path = str(case_dir / "auditlog.ndjson")
            al = AuditLog(auditlog_path)
            try:
                al.append(
                    "engagement.created",
                    {"case_id": case_id, "client": client, "scope": scope},
                )
            except Exception:
                # best-effort: don't let logging failures stop the flow
                pass

            # Throttle UI updates slightly to avoid flooding the text widget
            import time

            last_enum_update = 0.0
            last_preproc_update = 0.0

            def preproc_progress(processed, total):
                nonlocal last_preproc_update
                try:
                    now = time.time()
                    # update UI at most 5 times/sec
                    if now - last_preproc_update < 0.2 and (processed % 5) != 0:
                        return
                    last_preproc_update = now
                    # mark phase and start time
                    try:
                        if self._preproc_start_time is None:
                            self._preproc_start_time = now
                        self.after(
                            0, self.phase_label.configure, {"text": "Preprocessing"}
                        )
                    except Exception:
                        pass
                    if total and total > 0:
                        frac = min(1.0, float(processed) / float(total))
                        self.after(0, self.progress.set, frac)
                        self.after(
                            0,
                            self.progress_label.configure,
                            {"text": f"Preproc {processed}/{total}"},
                        )
                        # ETA calculation
                        try:
                            elapsed = max(1e-6, now - (self._preproc_start_time or now))
                            rate = float(processed) / elapsed if elapsed > 0 else 0.0
                            if rate > 0 and total:
                                remain = max(0, int((total - processed) / rate))
                                self.after(
                                    0,
                                    self.eta_label.configure,
                                    {"text": f"ETA: {remain}s"},
                                )
                        except Exception:
                            pass
                        # append a short message to results box
                        if not bool(self.summary_only_var.get()):
                            self.after(
                                0,
                                self.results_box.insert,
                                "end",
                                f"Preproc: {processed}/{total}\n",
                            )
                    else:
                        self.after(
                            0,
                            self.progress_label.configure,
                            {"text": f"Preproc {processed}"},
                        )
                except Exception:
                    pass

            try:
                max_depth = int(self.max_depth_entry.get().strip())
            except Exception:
                max_depth = 2
            do_extract = bool(self.extract_var.get())

            # Stream enumeration and show per-file preview lines. enumerate_inputs
            # will call the progress callback with (count, path, total). We wrap
            # that callback to throttle updates and keep the UI responsive.
            # background estimate of total files (filled by a worker below)
            total_estimate = None

            def enum_progress(count, path, total):
                nonlocal last_enum_update
                # allow background count thread to provide an estimate
                nonlocal total_estimate
                try:
                    now = time.time()
                    # update at most 5 times/sec and always on multiples of 10
                    if now - last_enum_update < 0.2 and (count % 10) != 0:
                        return
                    last_enum_update = now
                    # mark phase and start time
                    try:
                        if self._enum_start_time is None:
                            self._enum_start_time = now
                        self.after(
                            0, self.phase_label.configure, {"text": "Enumerating"}
                        )
                    except Exception:
                        pass
                    # update preview text and a lightweight progress in the label
                    if not bool(self.summary_only_var.get()):
                        # show a shortened path to avoid flooding UI
                        short = path
                        try:
                            if len(path) > 140:
                                short = "..." + path[-137:]
                        except Exception:
                            short = path
                        self.after(
                            0, self.results_box.insert, "end", f"Found: {short}\n"
                        )
                    # prefer explicit total from enumerate_inputs, else use
                    # the background estimate when available
                    effective_total = total if total else total_estimate
                    if effective_total and effective_total > 0:
                        # small progress bump to show activity; preproc will set real progress
                        self.after(
                            0,
                            self.progress.set,
                            min(0.2, float(count) / float(effective_total)),
                        )
                        # ETA estimate for enumeration
                        try:
                            elapsed = max(1e-6, now - (self._enum_start_time or now))
                            rate = float(count) / elapsed if elapsed > 0 else 0.0
                            eta = ""
                            if rate > 0 and effective_total:
                                remain = max(0, int((effective_total - count) / rate))
                                eta = f"ETA: {remain}s"
                            # include rate in the label if available
                            rate_str = f" ({rate:.1f}/s)" if rate > 0 else ""
                            self.after(
                                0,
                                self.progress_label.configure,
                                {
                                    "text": f"Enumerating {count}/{effective_total}{rate_str}"
                                },
                            )
                            self.after(0, self.eta_label.configure, {"text": eta})
                        except Exception:
                            rate_str = f" ({rate:.1f}/s)" if rate > 0 else ""
                            self.after(
                                0,
                                self.progress_label.configure,
                                {
                                    "text": f"Enumerating {count}/{effective_total}{rate_str}"
                                },
                            )
                    else:
                        self.after(
                            0,
                            self.progress_label.configure,
                            {"text": f"Enumerating {count}"},
                        )
                except Exception:
                    pass

            # Start a background count worker to quickly estimate the number
            # of files so we can provide an ETA even if enumerate_inputs does
            # not return a total immediately.
            try:

                def _count_worker():
                    nonlocal total_estimate
                    try:
                        total_estimate = count_inputs([scope])
                    except Exception:
                        total_estimate = None

                tcount = threading.Thread(target=_count_worker, daemon=True)
                tcount.start()
            except Exception:
                pass

            # If the user selected fast scan, skip expensive SHA256 computation
            compute_sha = not bool(self.fast_scan_var.get())

            # Use the iterator variant so we do not block building a full list
            # of items for large scopes. Wrap the iterator with a helper that
            # writes each incoming item to the manifest (NDJSON) and yields it
            # onward to preprocess_items so both see the same stream.
            manifest_path = str(case_dir / "inputs.manifest.ndjson")

            def _iter_and_write_manifest(src_iter, manifest_path_local):
                # local imports to avoid polluting module namespace in tests
                import json
                from pathlib import Path

                p = Path(manifest_path_local)
                p.parent.mkdir(parents=True, exist_ok=True)
                try:
                    f = p.open("w", encoding="utf-8")
                except Exception:
                    f = None
                # batch writes: flush every N lines to avoid heavy syscalls
                batch_flush = 20
                written = 0
                try:
                    for it in src_iter:
                        # write line to manifest (best-effort)
                        if f is not None:
                            try:
                                f.write(
                                    json.dumps(it, sort_keys=True, ensure_ascii=False)
                                    + "\n"
                                )
                                written += 1
                                # flush periodically; avoid os.fsync() which blocks on Windows
                                if (written % batch_flush) == 0:
                                    try:
                                        f.flush()
                                    except Exception:
                                        pass
                            except Exception:
                                # skip serialization errors
                                pass
                        yield it
                finally:
                    try:
                        if f is not None:
                            try:
                                f.flush()
                            except Exception:
                                pass
                            try:
                                f.close()
                            except Exception:
                                pass
                    except Exception:
                        pass

            # create the enumeration iterator (streaming)
            # choose a reasonable number of hashing workers for compute_sha
            try:
                import os

                cpu_cnt = os.cpu_count() or 1
                hw = min(4, max(1, cpu_cnt))
            except Exception:
                hw = 1

            enum_iter = enumerate_inputs_iter(
                [scope],
                compute_sha=compute_sha,
                progress_cb=enum_progress,
                cancel_event=self._cancel_event,
                hash_workers=hw,
            )

            # stream manifest and feed the same items into preprocessing
            items_stream = _iter_and_write_manifest(enum_iter, manifest_path)

            cancelled = False
            try:
                # Run preprocessing in streaming mode so manifests and index
                # lines are written incrementally. By default we do only the
                # basic preprocessing (copy inputs, extract archives) and
                # defer expensive AST/disasm builds unless the user enables
                # them in Advanced options.
                try:
                    build_ast_flag = bool(self.ast_var.get())
                except Exception:
                    build_ast_flag = False
                try:
                    build_disasm_flag = bool(self.disasm_var.get())
                except Exception:
                    build_disasm_flag = False

                preproc_result = preprocess_items(
                    items_stream,
                    str(case_dir),
                    progress_cb=preproc_progress,
                    cancel_event=self._cancel_event,
                    max_extract_depth=max_depth,
                    do_extract=do_extract,
                    build_ast=build_ast_flag,
                    build_disasm=build_disasm_flag,
                    stream=True,
                    compute_sha=compute_sha,
                    copy_inputs=compute_sha,
                )
                # preprocess_items may return early on cancellation without
                # raising; check the cancel event to determine if the run
                # was cancelled by the user.
                cancelled = bool(self._cancel_event and self._cancel_event.is_set())
            except Exception as e:
                preproc_result = {"stats": {}}
                cancelled = bool(self._cancel_event and self._cancel_event.is_set())
                # record cancellation separately from failures
                try:
                    if cancelled:
                        al.append("preproc.cancelled", {"message": "cancelled by user"})
                    else:
                        al.append("preproc.failed", {"error": str(e)})
                except Exception:
                    pass

            # If the run was cancelled, emit a cancellation audit event and
            # update the UI accordingly. Otherwise record completion.
            try:
                if cancelled:
                    try:
                        al.append("preproc.cancelled", {"message": "cancelled by user"})
                    except Exception:
                        pass
                    self.after(0, self._set_status, "Preprocessing cancelled")
                else:
                    stats = preproc_result.get("stats", {})
                    try:
                        al.append(
                            "preproc.completed",
                            {"index_lines": stats.get("index_lines")},
                        )
                    except Exception:
                        pass
                    self.after(0, self._set_status, "Preprocessing completed")
                    # enable Continue button so user can go to detectors page
                    try:
                        self.master.current_scan_meta = {
                            "workdir": str(case_dir),
                            "case_id": case_id,
                        }
                        self.after(
                            0, partial(self.continue_btn.configure, state="normal")
                        )
                    except Exception:
                        pass
            except Exception:
                pass

            # finalize progress bar
            self.after(0, self.progress.set, 1.0)
        except Exception as e:
            try:
                # log to status area; avoid printing to stdout in GUI
                self.after(0, self._set_status, f"Preproc error: {e}")
            except Exception:
                pass
        finally:
            try:
                self.after(0, partial(self.start_btn.configure, state="normal"))
                self.after(0, partial(self.cancel_btn.configure, state="disabled"))
                try:
                    self._stop_spinner()
                except Exception:
                    pass
            except Exception:
                pass

    def _on_cancel_clicked(self):
        if self._cancel_event is not None:
            try:
                self._cancel_event.set()
                self._set_status("Cancellation requested")
                self.cancel_btn.configure(state="disabled")
            except Exception:
                pass

    def _start_spinner(self):
        try:
            if self._spinner_running:
                return
            self._spinner_running = True
            self._spinner_index = 0

            def _tick():
                if not self._spinner_running:
                    return
                try:
                    ch = self._spinner_chars[
                        self._spinner_index % len(self._spinner_chars)
                    ]
                    self._spinner_index += 1
                    self._spinner_label.configure(text=ch)
                except Exception:
                    pass
                try:
                    self.after(200, _tick)
                except Exception:
                    pass

            try:
                self.after(0, _tick)
            except Exception:
                pass
        except Exception:
            pass

    def _stop_spinner(self):
        try:
            self._spinner_running = False
            try:
                self._spinner_label.configure(text="")
            except Exception:
                pass
        except Exception:
            pass

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
            self.results_box.delete("1.0", "end")
            self.continue_btn.configure(state="disabled")
        except Exception:
            pass
