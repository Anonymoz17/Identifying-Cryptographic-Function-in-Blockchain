from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path

import customtkinter as ctk


class EvidencePage(ctk.CTkFrame):
    """Small page exposing an 'Export Evidence Pack' helper.

    This encapsulates the modal UI and background worker that calls
    `auditor.evidence.build_evidence_pack` so it can be reused from the
    Dashboard or Setup page.
    """

    def __init__(self, master, switch_page_callback=None):
        super().__init__(master)
        self.switch_page = switch_page_callback
        self.grid_rowconfigure(0, weight=1)
        lbl = ctk.CTkLabel(self, text="Evidence Export", font=("Roboto", 20))
        lbl.pack(pady=(12, 6))
        desc = ctk.CTkLabel(self, text="Create an evidence pack for the current case.")
        desc.pack(pady=(6, 12))
        self.export_btn = ctk.CTkButton(
            self, text="Export Evidence Pack", command=self._on_export
        )
        self.export_btn.pack(pady=(6, 12))

    def _on_export(self):
        # open a small modal and start the worker; UI expects the current
        # case/workdir to be set on master.current_scan_meta if available.
        wd = getattr(self.master, "current_scan_meta", {}).get("workdir") or str(
            Path.cwd() / "case_demo"
        )
        case_id = (
            getattr(self.master, "current_scan_meta", {}).get("case_id") or "CASE-000"
        )
        ws_root = Path(wd)
        from auditor.workspace import Workspace

        ws = Workspace(ws_root, case_id)
        ws.ensure()

        evidence_dir = ws.evidence_dir
        evidence_dir.mkdir(parents=True, exist_ok=True)

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

        cancel_event = threading.Event()

        def on_cancel():
            cancel_event.set()
            try:
                cancel_btn.configure(state="disabled")
            except Exception:
                pass

        cancel_btn.configure(command=on_cancel)

        def progress_cb(current, total):
            try:
                frac = float(current) / float(total) if total and total > 0 else 0.0
                self.after(0, pb.set, frac)
                self.after(0, lbl.configure, {"text": f"Packaging: {current}/{total}"})
            except Exception:
                pass

        def worker():
            try:
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
                try:
                    webbrowser_open = __import__("webbrowser").open
                    webbrowser_open(evidence_dir.as_uri())
                except Exception:
                    pass
                self.after(
                    0, self._show_status, f"Evidence pack created: {zip_path.name}"
                )
            except Exception as e:
                msg = str(e)
                if "cancel" in msg.lower():
                    self.after(0, self._show_status, "Export cancelled")
                else:
                    self.after(0, self._show_status, f"Export error: {e}")
            finally:
                try:
                    self.after(0, top.destroy)
                except Exception:
                    pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _show_status(self, text: str):
        try:
            # write into the master status label if present else print
            if hasattr(self.master, "status_label"):
                try:
                    self.master.status_label.configure(text=text)
                except Exception:
                    pass
            else:
                print(text)
        except Exception:
            pass
