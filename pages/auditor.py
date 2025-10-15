# pages/auditor.py
"""Simple Auditor UI page to create engagements and run intake.

This is a minimal CTkFrame that integrates the `auditor` package scaffolding.
It provides controls to set Case ID, Client, Scope (path), select a policy file,
and run a simple intake that produces `inputs.manifest.json` and appends to
`auditlog.ndjson` inside the selected workdir.
"""
from __future__ import annotations

import threading
import tkinter as tk
import webbrowser
from functools import partial
from pathlib import Path

import customtkinter as ctk

from auditor.auditlog import AuditLog
from auditor.case import Engagement
from auditor.evidence import build_evidence_pack
from auditor.intake import count_inputs, enumerate_inputs, write_manifest
from auditor.preproc import preprocess_items
from auditor.workspace import Workspace


class AuditorPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(content, text="Auditor (beta)", font=("Roboto", 28, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 8)
        )

        # Inputs: workdir, case id, client, scope
        ctk.CTkLabel(content, text="Workdir:").grid(
            row=1, column=0, sticky="e", padx=8, pady=6
        )
        self.workdir_entry = ctk.CTkEntry(content, width=420)
        self.workdir_entry.grid(row=1, column=1, sticky="we", padx=8, pady=6)
        self.workdir_entry.insert(0, str(Path.cwd() / "case_demo"))

        ctk.CTkLabel(content, text="Case ID:").grid(
            row=2, column=0, sticky="e", padx=8, pady=6
        )
        self.case_entry = ctk.CTkEntry(content, width=240)
        self.case_entry.grid(row=2, column=1, sticky="w", padx=8, pady=6)
        self.case_entry.insert(0, "CASE-001")

        ctk.CTkLabel(content, text="Client:").grid(
            row=3, column=0, sticky="e", padx=8, pady=6
        )
        self.client_entry = ctk.CTkEntry(content, width=240)
        self.client_entry.grid(row=3, column=1, sticky="w", padx=8, pady=6)
        self.client_entry.insert(0, "ACME Corp")

        ctk.CTkLabel(content, text="Scope (path):").grid(
            row=4, column=0, sticky="e", padx=8, pady=6
        )
        self.scope_entry = ctk.CTkEntry(content, width=420)
        self.scope_entry.grid(row=4, column=1, sticky="we", padx=8, pady=6)
        self.scope_entry.insert(0, str(Path.cwd()))

        # Policy baseline selector
        ctk.CTkLabel(content, text="Policy baseline (optional):").grid(
            row=5, column=0, sticky="e", padx=8, pady=6
        )
        self.policy_entry = ctk.CTkEntry(content, width=420)
        self.policy_entry.grid(row=5, column=1, sticky="we", padx=8, pady=6)

        select_btn = ctk.CTkButton(
            content, text="Browse...", command=self._browse_policy
        )
        select_btn.grid(row=5, column=2, sticky="w", padx=8, pady=6)

        # Air-gapped toggle
        self.airgapped_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            content, text="Air-gapped mode (no network)", variable=self.airgapped_var
        ).grid(row=6, column=1, sticky="w", padx=8, pady=6)

        # Actions
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.grid(row=7, column=0, columnspan=3, sticky="we", padx=8, pady=(12, 8))
        actions.grid_columnconfigure(0, weight=1)

        # Start / Cancel buttons
        self.start_btn = ctk.CTkButton(
            actions, text="Start Engagement & Intake", command=self._on_start_clicked
        )
        self.start_btn.grid(row=0, column=0, sticky="w")

        self.cancel_btn = ctk.CTkButton(
            actions,
            text="Cancel",
            fg_color="#ff6b6b",
            hover_color="#ff4c4c",
            command=self._on_cancel_clicked,
        )
        self.cancel_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.cancel_btn.configure(state="disabled")

        self.status = ctk.CTkLabel(content, text="")
        self.status.grid(
            row=8, column=0, columnspan=3, sticky="we", padx=8, pady=(8, 6)
        )

        # Preview & progress labels
        self.preview_label = ctk.CTkLabel(content, text="Preview: 0 files")
        self.preview_label.grid(
            row=9, column=0, columnspan=3, sticky="w", padx=8, pady=(2, 2)
        )

        self.progress_label = ctk.CTkLabel(content, text="")
        self.progress_label.grid(
            row=10, column=0, columnspan=3, sticky="we", padx=8, pady=(2, 12)
        )

        # Progress bar
        self.progress = ctk.CTkProgressBar(content, width=480)
        self.progress.grid(
            row=11, column=0, columnspan=2, sticky="w", padx=8, pady=(2, 12)
        )
        self.progress.set(0.0)

        # Quick actions: Open workdir, View audit log
        quick = ctk.CTkFrame(content, fg_color="transparent")
        quick.grid(row=12, column=0, columnspan=3, sticky="we", padx=8, pady=(4, 12))
        quick.grid_columnconfigure((0, 1, 2), weight=1)
        self.open_workdir_btn = ctk.CTkButton(
            quick, text="Open workdir", command=self._open_workdir
        )
        self.open_workdir_btn.grid(row=0, column=0, sticky="w")
        self.view_auditlog_btn = ctk.CTkButton(
            quick, text="View audit log", command=self._view_auditlog
        )
        self.view_auditlog_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.export_evidence_btn = ctk.CTkButton(
            quick, text="Export Evidence Pack", command=self._on_export_evidence
        )
        self.export_evidence_btn.grid(row=0, column=2, sticky="w", padx=(8, 0))

        # cancellation event holder
        self._cancel_event = None

    def _browse_policy(self):
        from tkinter import filedialog

        path = filedialog.askopenfilename(title="Select policy baseline (JSON)")
        if path:
            self.policy_entry.delete(0, "end")
            self.policy_entry.insert(0, path)

    def _set_status(self, text: str, error: bool = False):
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    def _on_start_clicked(self):
        # Show preview count then start background job
        scope = self.scope_entry.get().strip() or "."
        try:
            total = count_inputs([scope])
            self.preview_label.configure(text=f"Preview: {total} files")
        except Exception:
            self.preview_label.configure(text="Preview: (error counting files)")
        # start background processing
        self._set_status("Starting engagement (background)...")
        # prepare cancel event and toggle buttons
        self._cancel_event = threading.Event()
        self.cancel_btn.configure(state="normal")
        self.start_btn.configure(state="disabled")
        t = threading.Thread(target=self._run_engagement_flow, daemon=True)
        t.start()

    def _run_engagement_flow(self):
        # noqa: C901 - contains UI orchestration; refactor later if needed
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        client = self.client_entry.get().strip() or "Unknown"
        scope = self.scope_entry.get().strip() or str(Path.cwd())

        try:
            eng = Engagement(workdir=wd, case_id=case_id, client=client, scope=scope)
            eng.write_metadata()
            policy = self.policy_entry.get().strip()
            if policy:
                eng.import_policy_baseline(policy)

            # Use the case-specific workdir created by Engagement so exporter/Workspace sees canonical files
            case_dir = eng.workdir
            auditlog_path = str(case_dir / "auditlog.ndjson")
            al = AuditLog(auditlog_path)
            al.append(
                "engagement.created",
                {
                    "case_id": case_id,
                    "client": client,
                    "scope": scope,
                    "airgapped": bool(self.airgapped_var.get()),
                },
            )

            # Enumerate + hash with progress updates
            def progress_cb(count, path, total=None):
                # update textual progress every 5 files, update progress bar when total is known
                try:
                    if total:
                        frac = (
                            min(1.0, float(count) / float(total))
                            if total and total > 0
                            else 0.0
                        )
                        self.after(0, self.progress.set, frac)
                        self.after(
                            0,
                            partial(
                                self.progress_label.configure,
                                text=f"Processed {count}/{total} files...",
                            ),
                        )
                    else:
                        if count % 5 == 0:
                            self.after(
                                0,
                                partial(
                                    self.progress_label.configure,
                                    text=f"Processed {count} files...",
                                ),
                            )
                except Exception:
                    pass

            # enumerate inputs from the scope but write the manifest into the case directory
            items = enumerate_inputs(
                [scope], progress_cb=progress_cb, cancel_event=self._cancel_event
            )
            manifest_path = str(case_dir / "inputs.manifest.json")
            write_manifest(manifest_path, items)
            al.append(
                "inputs.ingested",
                {"manifest": Path(manifest_path).name, "count": len(items)},
            )

            # Run preprocessing scaffold (cancellable, with progress)
            try:
                self.after(0, self._set_status, "Running preprocessing scaffold...")

                def preproc_progress(processed, total):
                    try:
                        if total and total > 0:
                            frac = min(1.0, float(processed) / float(total))
                            self.after(0, self.progress.set, frac)
                            self.after(
                                0,
                                partial(
                                    self.progress_label.configure,
                                    text=f"Preproc {processed}/{total}",
                                ),
                            )
                        else:
                            self.after(
                                0,
                                partial(
                                    self.progress_label.configure,
                                    text=f"Preproc {processed}",
                                ),
                            )
                    except Exception:
                        pass

                preproc_index = preprocess_items(
                    items,
                    str(case_dir),
                    progress_cb=preproc_progress,
                    cancel_event=self._cancel_event,
                )
                al.append("preproc.completed", {"index_lines": len(preproc_index)})
                self.after(0, self._set_status, "Preprocessing completed")
            except Exception as e:
                al.append("preproc.failed", {"error": str(e)})
                self.after(0, partial(self._set_status, f"Preproc error: {e}", True))

            # final UI update
            try:
                self.after(
                    0,
                    partial(
                        self.progress_label.configure,
                        text=f"Engagement started in {wd} — {len(items)} files recorded",
                    ),
                )
                self.after(0, self.progress.set, 1.0)
                # reset buttons
                self.after(0, partial(self.cancel_btn.configure, state="disabled"))
                self.after(0, partial(self.start_btn.configure, state="normal"))
            except Exception:
                pass
        except Exception as e:
            try:
                self.after(
                    0, partial(self.progress_label.configure, text=f"Error: {e}")
                )
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

    def _open_workdir(self):
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        wd = str(Path(wd).resolve())
        try:
            # Use webbrowser to open the folder via file:// URL which is portable
            webbrowser.open(Path(wd).as_uri())
        except Exception:
            self._set_status(f"Could not open folder: {wd}", error=True)

    def _view_auditlog(self):
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        path = str(Path(wd).resolve() / "auditlog.ndjson")
        try:
            if Path(path).exists():
                # show an in-app viewer modal
                try:
                    self._show_auditlog_viewer(path)
                except Exception:
                    # fallback to external opener
                    webbrowser.open(Path(path).as_uri())
            else:
                self._set_status("No auditlog found in workdir", error=True)
        except Exception:
            self._set_status("Could not open audit log", error=True)

    def _show_auditlog_viewer(self, path: str):
        # modal window with scrollable text and a Verify button
        top = tk.Toplevel(self)
        top.title("Audit Log Viewer")
        top.geometry("800x500")
        txt = tk.Text(top, wrap="none")
        txt.pack(fill="both", expand=True, side="top")

        # read file and populate
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = [line for line in f.readlines() if line.strip()]
            for line in lines:
                txt.insert("end", line)
        except Exception as e:
            txt.insert("end", f"Error reading audit log: {e}\n")

        def on_verify():
            try:
                al = AuditLog(path)
                ok = al.verify()
                self._set_status(
                    (
                        "Audit log verification: OK"
                        if ok
                        else "Audit log verification: FAILED"
                    ),
                    error=not ok,
                )
            except Exception as e:
                self._set_status(f"Verify error: {e}", error=True)

        btn = ctk.CTkButton(top, text="Verify Chain", command=on_verify)
        btn.pack(side="bottom", pady=8)

    def _on_export_evidence(self):
        # spawn background worker to build evidence pack
        self.export_evidence_btn.configure(state="disabled")
        t = threading.Thread(target=self._export_evidence, daemon=True)
        t.start()

    def _export_evidence(self):
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        ws = Workspace(Path(wd), case_id)
        ws.ensure()
        paths = ws.paths()

        try:
            # collect files to include
            files = []
            for key in (
                "engagement",
                "auditlog",
                "inputs_manifest",
                "preproc_index",
                "policy_baseline",
            ):
                p = paths.get(key)
                if p and p.exists():
                    files.append(p)

            # include all preproc artifacts
            preproc_dir = paths.get("preproc_dir")
            if preproc_dir and preproc_dir.exists():
                for p in preproc_dir.rglob("*"):
                    if p.is_file():
                        files.append(p)

            # ensure unique
            unique_files = list(dict.fromkeys([Path(f) for f in files]))

            # build pack
            self.after(0, partial(self._set_status, "Building evidence pack..."))
            zip_path, zip_sha = build_evidence_pack(
                ws.root, case_id, unique_files, out_dir=paths.get("evidence_dir")
            )

            # append auditlog event
            al = AuditLog(str(paths.get("auditlog")))
            al.append("evidence.packaged", {"zip": zip_path.name, "sha256": zip_sha})

            # UI update: show pack location
            self.after(
                0, partial(self._set_status, f"Evidence pack created: {zip_path.name}")
            )
            # open evidence folder (portable)
            try:
                webbrowser.open(paths.get("evidence_dir").as_uri())
            except Exception:
                pass
        except Exception as e:
            self.after(0, partial(self._set_status, f"Export failed: {e}", True))
        finally:
            self.after(0, partial(self.export_evidence_btn.configure, state="normal"))

    def on_resize(self, w, h):
        # no-op: keep layout flexible via grid/pack
        pass
