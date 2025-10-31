from __future__ import annotations

import json
import tempfile
import threading
import tkinter as tk
from functools import partial
from pathlib import Path
from tkinter import filedialog, messagebox

from auditor.auditlog import AuditLog
from auditor.case import Engagement
from auditor.intake import count_inputs, enumerate_inputs, write_manifest
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

        # Workdir / case / scope
        form = ctk.CTkFrame(content, fg_color="transparent")
        form.pack(padx=12, pady=(6, 6), fill="x")
        # allow the entry columns to expand (col 1 and col 3)
        form.grid_columnconfigure(1, weight=1)
        form.grid_columnconfigure(3, weight=1)

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
        # Workdir browse button
        self.workdir_browse = ctk.CTkButton(
            form, text="Browse", width=90, command=self._browse_workdir
        )
        self.workdir_browse.grid(row=0, column=2, padx=(8, 0))

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

        # Policy baseline on its own row
        ctk.CTkLabel(form, text="Policy:").grid(row=3, column=0, sticky="w")
        self.policy_entry = ctk.CTkEntry(
            form, placeholder_text="Optional policy baseline (JSON)"
        )
        self.policy_entry.grid(row=3, column=1, sticky="we", padx=(6, 0))
        self.policy_browse = ctk.CTkButton(
            form, text="Browse", width=90, command=self._browse_policy
        )
        self.policy_browse.grid(row=3, column=2, padx=(8, 0))
        # Policy editor button (templates + editor)
        self.policy_edit = ctk.CTkButton(
            form, text="Edit", width=70, command=self._edit_policy_popup
        )
        self.policy_edit.grid(row=3, column=3, padx=(8, 0))

        # Preproc options
        ctk.CTkLabel(form, text="Preproc Options:").grid(row=4, column=0, sticky="w")
        opts = ctk.CTkFrame(form, fg_color="transparent")
        opts.grid(row=4, column=1, sticky="we", padx=(6, 0))
        self.extract_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(opts, text="Extract archives", variable=self.extract_var).grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkLabel(opts, text="Max depth:").grid(row=0, column=1)
        self.max_depth_entry = ctk.CTkEntry(opts, width=60)
        self.max_depth_entry.insert(0, "2")
        self.max_depth_entry.grid(row=0, column=2, padx=(4, 0))

        self.ast_var = tk.BooleanVar(value=False)
        self.disasm_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts, text="Generate AST cache", variable=self.ast_var).grid(
            row=1, column=0, sticky="w", pady=(6, 0)
        )
        ctk.CTkCheckBox(
            opts, text="Generate disasm cache", variable=self.disasm_var
        ).grid(row=1, column=1, sticky="w", pady=(6, 0))

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

    def _browse_workdir(self):
        from tkinter import filedialog

        path = filedialog.askdirectory(title="Select work directory")
        if path:
            try:
                self.workdir_entry.delete(0, "end")
                self.workdir_entry.insert(0, path)
            except Exception:
                pass

    def _browse_policy(self):
        path = filedialog.askopenfilename(title="Select policy baseline (JSON)")
        if path:
            try:
                self.policy_entry.delete(0, "end")
                self.policy_entry.insert(0, path)
            except Exception:
                pass

    def _edit_policy_popup(self):
        """Open a small modal that offers policy JSON templates and an editor.

        The user can pick a template, edit the JSON, then Insert (write to a temp
        file and set the Policy entry), or Save As... to store it elsewhere.
        """
        top = tk.Toplevel(self)
        top.title("Policy baseline editor")
        top.transient(self)
        top.grab_set()

        # Template selector
        frame = ctk.CTkFrame(top, fg_color="transparent")
        frame.pack(padx=12, pady=12, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Template:").grid(row=0, column=0, sticky="w")
        templates = ["Whitelist", "Rule Overrides", "Scoring", "Combined"]
        tmpl_var = tk.StringVar(value=templates[0])
        tmpl_menu = ctk.CTkOptionMenu(frame, values=templates, variable=tmpl_var)
        tmpl_menu.grid(row=0, column=1, sticky="we", padx=(8, 0))

        # Editor (multi-line)
        editor = tk.Text(frame, width=80, height=20, wrap="none")
        editor.grid(row=1, column=0, columnspan=3, pady=(8, 8))

        def _render_template(*_):
            kind = tmpl_var.get()
            editor.delete("1.0", "end")
            editor.insert("1.0", self._policy_template_json(kind))

        tmpl_var.trace_add("write", _render_template)
        # populate initial
        _render_template()

        # Buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=2, column=0, columnspan=3, pady=(6, 0))

        def _insert_to_entry():
            txt = editor.get("1.0", "end").strip()
            # validate JSON
            try:
                json.loads(txt)
            except Exception as e:
                try:
                    messagebox.showerror("Invalid JSON", f"JSON parse error: {e}")
                except Exception:
                    pass
                return
            # write to temp file and set policy_entry
            try:
                fd, path = tempfile.mkstemp(prefix="policy_", suffix=".json")
                with open(fd, "w", encoding="utf-8") as f:
                    f.write(txt)
                self.policy_entry.delete(0, "end")
                self.policy_entry.insert(0, path)
                top.destroy()
            except Exception:
                try:
                    messagebox.showerror("Error", "Could not write temp file")
                except Exception:
                    pass

        def _save_as():
            path = filedialog.asksaveasfilename(
                title="Save policy as...",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*")],
            )
            if not path:
                return
            try:
                txt = editor.get("1.0", "end").strip()
                json.loads(txt)  # validate
                with open(path, "w", encoding="utf-8") as f:
                    f.write(txt)
                self.policy_entry.delete(0, "end")
                self.policy_entry.insert(0, path)
                top.destroy()
            except Exception as e:
                try:
                    messagebox.showerror("Error", f"Could not save file: {e}")
                except Exception:
                    pass

        def _load_file_to_editor():
            p = filedialog.askopenfilename(title="Open policy (JSON)")
            if not p:
                return
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = f.read()
                editor.delete("1.0", "end")
                editor.insert("1.0", data)
            except Exception:
                try:
                    messagebox.showerror("Error", "Could not read file")
                except Exception:
                    pass

        ctk.CTkButton(btn_frame, text="Insert", command=_insert_to_entry).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(btn_frame, text="Save As...", command=_save_as).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(btn_frame, text="Load...", command=_load_file_to_editor).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(btn_frame, text="Cancel", command=top.destroy).pack(
            side="left", padx=(0, 8)
        )

        # keep modal
        top.wait_window()

    def _policy_template_json(self, kind: str) -> str:
        """Return a pretty JSON string for the requested template kind."""
        if kind == "Whitelist":
            obj = {
                "metadata": {"author": "", "version": "1.0"},
                "whitelist": {
                    "file_hashes": [],
                    "function_names": [],
                    "rule_ids": [],
                },
            }
        elif kind == "Rule Overrides":
            obj = {
                "rules": {
                    "YARA-0001": {"action": "allow", "reason": "vendor"},
                    "TS-weak-rand": {"action": "flag", "severity_override": "low"},
                },
                "defaults": {"action": "flag", "severity": "medium"},
            }
        elif kind == "Scoring":
            obj = {
                "scoring": {
                    "engine_weights": {"yara": 1.0, "treesitter": 0.8, "disasm": 0.6},
                    "confidence_thresholds": {"high": 0.9, "medium": 0.6, "low": 0.3},
                }
            }
        else:
            obj = {
                "metadata": {"version": "1.0"},
                "whitelist": {"file_hashes": [], "function_names": [], "rule_ids": []},
                "rules": {},
                "scoring": {
                    "engine_weights": {"yara": 1.0, "treesitter": 0.8, "disasm": 0.6},
                    "confidence_thresholds": {"high": 0.9, "medium": 0.6, "low": 0.3},
                },
            }
        return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2)

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
        scope = self.scope_entry.get().strip() or "."
        try:
            total = count_inputs([scope])
            self.results_box.delete("1.0", "end")
            self.results_box.insert("end", f"Preview: {total} files\n")
        except Exception:
            self.results_box.insert("end", "Preview: (error counting files)\n")
        self._set_status("Starting engagement (background)...")
        self._cancel_event = threading.Event()
        self.cancel_btn.configure(state="normal")
        self.start_btn.configure(state="disabled")
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
            al.append(
                "engagement.created",
                {"case_id": case_id, "client": client, "scope": scope},
            )

            def preproc_progress(processed, total):
                try:
                    if total and total > 0:
                        frac = min(1.0, float(processed) / float(total))
                        self.after(0, self.progress.set, frac)
                        self.after(
                            0,
                            self.progress_label.configure,
                            {"text": f"Preproc {processed}/{total}"},
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

            # Enumerate inputs and write manifest into the case workspace (same as Auditor)
            items = enumerate_inputs(
                [scope], progress_cb=None, cancel_event=self._cancel_event
            )
            # write canonical NDJSON manifest (tests and other code expect .ndjson)
            manifest_path = str(case_dir / "inputs.manifest.ndjson")
            try:
                write_manifest(manifest_path, items)
            except Exception:
                pass

            try:
                preproc_result = preprocess_items(
                    items,
                    str(case_dir),
                    progress_cb=preproc_progress,
                    cancel_event=self._cancel_event,
                    max_extract_depth=max_depth,
                    do_extract=do_extract,
                    build_ast=bool(self.ast_var.get()),
                    build_disasm=bool(self.disasm_var.get()),
                )
            except Exception as e:
                preproc_result = {"stats": {}}
                al.append("preproc.failed", {"error": str(e)})

            stats = preproc_result.get("stats", {})
            al.append("preproc.completed", {"index_lines": stats.get("index_lines")})
            self.after(0, self._set_status, "Preprocessing completed")
            # enable Continue button so user can go to detectors page
            try:
                self.master.current_scan_meta = {
                    "workdir": str(case_dir),
                    "case_id": case_id,
                }
                self.after(0, partial(self.continue_btn.configure, state="normal"))
            except Exception:
                pass

            self.after(0, self.progress.set, 1.0)
        except Exception as e:
            try:
                self.after(0, self._set_status, f"Preproc error: {e}")
            except Exception:
                pass
        finally:
            try:
                self.after(0, partial(self.start_btn.configure, state="normal"))
                self.after(0, partial(self.cancel_btn.configure, state="disabled"))
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
