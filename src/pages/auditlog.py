from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from auditor.auditlog import AuditLog


def show_auditlog_viewer(master, path: str):
    """Open a modal auditlog viewer and provide a Verify Chain button.

    This mirrors the old AuditorPage modal but is provided as a reusable
    helper so other pages (Setup, Overview) can show audit logs.
    """
    top = tk.Toplevel(master)
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
            al = AuditLog(path)
            al.append("auditlog.read_error", {"error": str(e)})
        except Exception:
            pass

    def on_verify():
        try:
            al = AuditLog(path)
            ok = al.verify()
            try:
                al.append(
                    "auditlog.verified" if ok else "auditlog.verify_failed",
                    {"ok": bool(ok)},
                )
            except Exception:
                pass
            import tkinter.messagebox as _mb

            if ok:
                _mb.showinfo("Verify Chain", "Audit log verification: OK")
            else:
                _mb.showerror("Verify Chain", "Audit log verification: FAILED")
        except Exception as e:
            try:
                import tkinter.messagebox as _mb

                _mb.showerror("Verify Chain", f"Verify error: {e}")
            except Exception:
                pass

    btn = ctk.CTkButton(top, text="Verify Chain", command=on_verify)
    btn.pack(side="bottom", pady=8)
