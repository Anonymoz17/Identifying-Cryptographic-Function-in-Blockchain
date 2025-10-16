"""moved from pages/auditor.py"""

from __future__ import annotations

import threading
import tkinter as tk
import webbrowser
from functools import partial
from pathlib import Path

from auditor.auditlog import AuditLog
from auditor.case import Engagement
from auditor.intake import count_inputs, enumerate_inputs, write_manifest
from auditor.preproc import preprocess_items
from auditor.workspace import Workspace

import customtkinter as ctk  # isort:skip


class AuditorPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        # Layout
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        # Title + status
        self.title = ctk.CTkLabel(content, text="Auditor", font=("Roboto", 48))
        self.title.pack(pady=(12, 4))
        self.status = ctk.CTkLabel(content, text="")
        self.status.pack(pady=(0, 6))

        # Form: workdir + case id
        form = ctk.CTkFrame(content, fg_color="transparent")
        form.pack(padx=12, pady=(6, 6), fill="x")
        ctk.CTkLabel(form, text="Workdir:").grid(row=0, column=0, sticky="w")
        self.workdir_entry = ctk.CTkEntry(form)
        self.workdir_entry.grid(row=0, column=1, sticky="we", padx=(6, 0))
        ctk.CTkLabel(form, text="Case ID:").grid(row=1, column=0, sticky="w")
        self.case_entry = ctk.CTkEntry(form)
        self.case_entry.grid(row=1, column=1, sticky="we", padx=(6, 0))
        form.grid_columnconfigure(1, weight=1)

        # Client, scope, policy placeholders (used by other methods)
        self.client_entry = ctk.CTkEntry(form)
        self.scope_entry = ctk.CTkEntry(form)
        self.policy_entry = ctk.CTkEntry(form)
        self.airgapped_var = tk.BooleanVar(value=False)

        # Actions (start/cancel)
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(pady=(6, 6))
        self.start_btn = ctk.CTkButton(
            actions,
            text="Start Engagement",
            command=self._on_start_clicked,
        )
        self.start_btn.pack(side="left", padx=(0, 6))
        self.cancel_btn = ctk.CTkButton(
            actions,
            text="Cancel",
            command=self._on_cancel_clicked,
            state="disabled",
        )
        self.cancel_btn.pack(side="left")

        # Progress and preview
        self.preview_label = ctk.CTkLabel(content, text="Preview: 0 files")
        self.preview_label.pack()
        self.progress_label = ctk.CTkLabel(content, text="")
        self.progress_label.pack(pady=(6, 2))
        self.progress = ctk.CTkProgressBar(content, width=480)
        self.progress.pack(pady=(2, 12))
        self.progress.set(0.0)

        # Quick actions row
        quick = ctk.CTkFrame(content, fg_color="transparent")
        quick.pack(fill="x", padx=8, pady=(4, 12))
        quick.grid_columnconfigure((0, 1, 2), weight=1)
        self.open_workdir_btn = ctk.CTkButton(
            quick,
            text="Open workdir",
            command=self._open_workdir,
        )
        self.open_workdir_btn.grid(row=0, column=0, sticky="w")
        self.view_auditlog_btn = ctk.CTkButton(
            quick,
            text="View audit log",
            command=self._view_auditlog,
        )
        self.view_auditlog_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.export_evidence_btn = ctk.CTkButton(
            quick,
            text="Export Evidence Pack",
            command=self._on_export_evidence,
        )
        self.export_evidence_btn.grid(row=0, column=2, sticky="w", padx=(8, 0))

        # Cancellation event holder
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
        scope = self.scope_entry.get().strip() or "."
        try:
            total = count_inputs([scope])
            self.preview_label.configure(text=f"Preview: {total} files")
        except Exception:
            self.preview_label.configure(text="Preview: (error counting files)")
        self._set_status("Starting engagement (background)...")
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
        case_id = self.case_entry.get().strip() or "CASE-000"
        try:
            ws = Workspace(Path(wd), case_id)
            # ensure canonical case workspace exists then open it
            ws.ensure()
            webbrowser.open(ws.root.as_uri())
        except Exception:
            self._set_status(f"Could not open folder: {wd}", error=True)

    def _view_auditlog(self):
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        try:
            ws = Workspace(Path(wd), case_id)
            auditlog_path = ws.paths().get("auditlog")
            if auditlog_path and auditlog_path.exists():
                try:
                    self._show_auditlog_viewer(str(auditlog_path))
                except Exception:
                    webbrowser.open(auditlog_path.as_uri())
            else:
                self._set_status("No auditlog found in case workspace", error=True)
        except Exception:
            self._set_status("Could not open audit log", error=True)

    def _on_export_evidence(self):
        """Build an evidence pack in background and show progress modal.

        The packer writes a zip into the case `evidence` directory. We run the
        packaging in a worker thread so the UI stays responsive and provide a
        Cancel button to request cooperative cancellation.
        """

        # prepare workspace
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        ws = Workspace(Path(wd), case_id)
        ws.ensure()

        # ensure evidence dir exists
        evidence_dir = ws.evidence_dir
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # build a small progress modal
        top = tk.Toplevel(self)
        top.title("Exporting evidence")
        top.geometry("420x120")
        lbl = ctk.CTkLabel(top, text="Preparing evidence pack...")
        lbl.pack(fill="x", padx=12, pady=(12, 6))
        pb = ctk.CTkProgressBar(top, width=360)
        pb.pack(padx=12, pady=(6, 6))
        pb.set(0.0)

        cancel_btn = ctk.CTkButton(top, text="Cancel", fg_color="#ff6b6b")
        cancel_btn.pack(side="bottom", pady=8)

        # cancellation event
        cancel_event = threading.Event()

        def on_cancel():
            cancel_event.set()
            try:
                cancel_btn.configure(state="disabled")
            except Exception:
                pass
            self._set_status("Export cancellation requested")

        cancel_btn.configure(command=on_cancel)

        # disable export button while running
        try:
            self.export_evidence_btn.configure(state="disabled")
        except Exception:
            pass

        # progress callback scheduled to main thread
        def progress_cb(current, total):
            try:
                frac = float(current) / float(total) if total and total > 0 else 0.0
                self.after(0, pb.set, frac)
                self.after(0, lbl.configure, {"text": f"Packaging: {current}/{total}"})
            except Exception:
                pass

        def worker():
            try:
                # call the packer which will write into evidence_dir
                from auditor.evidence import build_evidence_pack

                zip_path, sha = build_evidence_pack(
                    ws.root,
                    case_id,
                    files=None,
                    out_dir=evidence_dir,
                    progress_cb=progress_cb,
                    cancel_event=cancel_event,
                    progress_step=max(1, 1),
                )
                # open the evidence folder after packaging completes
                try:
                    webbrowser.open(evidence_dir.as_uri())
                except Exception:
                    pass
                self.after(
                    0, self._set_status, f"Evidence pack created: {zip_path.name}"
                )
            except Exception as e:
                # if cancelled, show a friendly message
                msg = str(e)
                if "cancel" in msg.lower():
                    self.after(0, self._set_status, "Export cancelled", True)
                else:
                    self.after(0, self._set_status, f"Export error: {e}", True)
            finally:
                try:
                    self.after(0, top.destroy)
                except Exception:
                    pass
                try:
                    self.after(
                        0, partial(self.export_evidence_btn.configure, state="normal")
                    )
                except Exception:
                    pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()

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
            try:
                # try to append a diagnostic record to the auditlog (if writable)
                al = AuditLog(path)
                al.append("auditlog.read_error", {"error": str(e)})
            except Exception:
                pass

        def on_verify():
            try:
                al = AuditLog(path)
                ok = al.verify()
                # append a verification result event to the audit log
                try:
                    al.append(
                        "auditlog.verified" if ok else "auditlog.verify_failed",
                        {"ok": bool(ok)},
                    )
                except Exception:
                    # non-fatal if append fails
                    pass

                # show a confirmation dialog and update status
                import tkinter.messagebox as _mb

                if ok:
                    _mb.showinfo("Verify Chain", "Audit log verification: OK")
                    self._set_status("Audit log verification: OK", error=False)
                else:
                    _mb.showerror("Verify Chain", "Audit log verification: FAILED")
                    self._set_status("Audit log verification: FAILED", error=True)
            except Exception as e:
                self._set_status(f"Verify error: {e}", error=True)

        btn = ctk.CTkButton(top, text="Verify Chain", command=on_verify)
        btn.pack(side="bottom", pady=8)
