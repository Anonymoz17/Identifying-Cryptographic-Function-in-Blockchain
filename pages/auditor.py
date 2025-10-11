# pages/auditor.py
"""Simple Auditor UI page to create engagements and run intake.

This is a minimal CTkFrame that integrates the `auditor` package scaffolding.
It provides controls to set Case ID, Client, Scope (path), select a policy file,
and run a simple intake that produces `inputs.manifest.json` and appends to
`auditlog.ndjson` inside the selected workdir.
"""
from __future__ import annotations

import os
import tkinter as tk
import customtkinter as ctk
from typing import Optional

from auditor.case import Engagement
from auditor.auditlog import AuditLog
from auditor.intake import enumerate_inputs, write_manifest


class AuditorPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(content, text="Auditor (beta)", font=("Roboto", 28, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12,8))

        # Inputs: workdir, case id, client, scope
        ctk.CTkLabel(content, text="Workdir:").grid(row=1, column=0, sticky="e", padx=8, pady=6)
        self.workdir_entry = ctk.CTkEntry(content, width=420)
        self.workdir_entry.grid(row=1, column=1, sticky="we", padx=8, pady=6)
        self.workdir_entry.insert(0, os.path.abspath("./case_demo"))

        ctk.CTkLabel(content, text="Case ID:").grid(row=2, column=0, sticky="e", padx=8, pady=6)
        self.case_entry = ctk.CTkEntry(content, width=240)
        self.case_entry.grid(row=2, column=1, sticky="w", padx=8, pady=6)
        self.case_entry.insert(0, "CASE-001")

        ctk.CTkLabel(content, text="Client:").grid(row=3, column=0, sticky="e", padx=8, pady=6)
        self.client_entry = ctk.CTkEntry(content, width=240)
        self.client_entry.grid(row=3, column=1, sticky="w", padx=8, pady=6)
        self.client_entry.insert(0, "ACME Corp")

        ctk.CTkLabel(content, text="Scope (path):").grid(row=4, column=0, sticky="e", padx=8, pady=6)
        self.scope_entry = ctk.CTkEntry(content, width=420)
        self.scope_entry.grid(row=4, column=1, sticky="we", padx=8, pady=6)
        self.scope_entry.insert(0, os.path.abspath("."))

        # Policy baseline selector
        ctk.CTkLabel(content, text="Policy baseline (optional):").grid(row=5, column=0, sticky="e", padx=8, pady=6)
        self.policy_entry = ctk.CTkEntry(content, width=420)
        self.policy_entry.grid(row=5, column=1, sticky="we", padx=8, pady=6)

        select_btn = ctk.CTkButton(content, text="Browse...", command=self._browse_policy)
        select_btn.grid(row=5, column=2, sticky="w", padx=8, pady=6)

        # Air-gapped toggle
        self.airgapped_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(content, text="Air-gapped mode (no network)", variable=self.airgapped_var).grid(row=6, column=1, sticky="w", padx=8, pady=6)

        # Actions
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.grid(row=7, column=0, columnspan=3, sticky="we", padx=8, pady=(12,8))
        actions.grid_columnconfigure(0, weight=1)

        self.start_btn = ctk.CTkButton(actions, text="Start Engagement & Intake", command=self._start_engagement)
        self.start_btn.grid(row=0, column=0, sticky="w")

        self.status = ctk.CTkLabel(content, text="")
        self.status.grid(row=8, column=0, columnspan=3, sticky="we", padx=8, pady=(8,12))

    def _browse_policy(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="Select policy baseline (JSON)")
        if path:
            self.policy_entry.delete(0, 'end')
            self.policy_entry.insert(0, path)

    def _set_status(self, text: str, error: bool = False):
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    def _start_engagement(self):
        wd = self.workdir_entry.get().strip() or './case_demo'
        case_id = self.case_entry.get().strip() or 'CASE-000'
        client = self.client_entry.get().strip() or 'Unknown'
        scope = self.scope_entry.get().strip() or '.'

        try:
            eng = Engagement(workdir=wd, case_id=case_id, client=client, scope=scope)
            eng.write_metadata()
            policy = self.policy_entry.get().strip()
            if policy:
                eng.import_policy_baseline(policy)

            # init audit log and append an event
            al = AuditLog(os.path.join(wd, 'auditlog.ndjson'))
            al.append('engagement.created', {'case_id': case_id, 'client': client, 'scope': scope, 'airgapped': bool(self.airgapped_var.get())})

            # Run intake: enumerate inputs and write manifest
            items = enumerate_inputs([scope])
            manifest_path = os.path.join(wd, 'inputs.manifest.json')
            write_manifest(manifest_path, items)

            al.append('inputs.ingested', {'manifest': os.path.basename(manifest_path), 'count': len(items)})

            self._set_status(f'Engagement started in {wd} — {len(items)} files recorded')
        except Exception as e:
            self._set_status(f'Error: {e}', error=True)

    def on_resize(self, w, h):
        # no-op: keep layout flexible via grid/pack
        pass
