from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Callable, Dict, Any
import customtkinter as ctk
from tkinter import filedialog


class AdvancedOptionsWindow(ctk.CTkToplevel):
    """Popup window for advanced preprocessing options.

    Usage:
      adv = AdvancedOptionsWindow(parent, initial_values, on_apply)
      where on_apply is called with a dict of values when user clicks OK.
    """

    def __init__(self, parent, initial: Dict[str, Any], on_apply: Callable[[Dict[str, Any]], None]):
        super().__init__(parent)
        self.title("Advanced options")
        self.transient(parent)
        self.resizable(False, False)
        self.grab_set()
        self.on_apply = on_apply

        # initial values fallback
        iv = initial or {}
        self.policy_var = tk.StringVar(value=iv.get("policy", ""))
        self.max_depth_var = tk.StringVar(value=str(iv.get("max_extract_depth", 2)))
        self.ast_var = tk.BooleanVar(value=bool(iv.get("build_ast", False)))
        self.disasm_var = tk.BooleanVar(value=bool(iv.get("build_disasm", False)))
        self.extract_var = tk.BooleanVar(value=bool(iv.get("extract_archives", True)))
        self.fast_scan_var = tk.BooleanVar(value=bool(iv.get("fast_scan", False)))

        frm = ctk.CTkFrame(self, fg_color="transparent")
        frm.pack(padx=12, pady=12, fill="both", expand=True)

        # Policy
        ctk.CTkLabel(frm, text="Policy baseline (JSON):").grid(row=0, column=0, sticky="w")
        self.policy_entry = ctk.CTkEntry(frm, textvariable=self.policy_var, width=380)
        self.policy_entry.grid(row=0, column=1, sticky="we", padx=(8, 0))
        self.policy_browse = ctk.CTkButton(frm, text="Browse", width=90, command=self._browse_policy)
        self.policy_browse.grid(row=0, column=2, padx=(8, 0))

        # Preproc options
        ctk.CTkLabel(frm, text="Preprocessing options:").grid(row=1, column=0, sticky="nw", pady=(8, 0))
        opts = ctk.CTkFrame(frm, fg_color="transparent")
        opts.grid(row=1, column=1, columnspan=2, sticky="we", pady=(8, 0))
        ctk.CTkCheckBox(opts, text="Extract archives", variable=self.extract_var).grid(row=0, column=0, sticky="w")
        ctk.CTkCheckBox(opts, text="Fast scan (no hashing)", variable=self.fast_scan_var).grid(row=0, column=1, sticky="w", padx=(8, 0))

        # Max depth and caches
        ctk.CTkLabel(frm, text="Max extract depth:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.max_depth_entry = ctk.CTkEntry(frm, textvariable=self.max_depth_var, width=80)
        self.max_depth_entry.grid(row=2, column=1, sticky="w", padx=(8, 0), pady=(8, 0))

        ctk.CTkCheckBox(frm, text="Generate AST cache", variable=self.ast_var).grid(row=3, column=0, sticky="w", pady=(8, 0))
        ctk.CTkCheckBox(frm, text="Generate disasm cache", variable=self.disasm_var).grid(row=3, column=1, sticky="w", pady=(8, 0))

        # Buttons
        btn_frm = ctk.CTkFrame(frm, fg_color="transparent")
        btn_frm.grid(row=4, column=0, columnspan=3, pady=(12, 0))
        self.ok_btn = ctk.CTkButton(btn_frm, text="OK", width=120, command=self._on_ok)
        self.ok_btn.pack(side="right", padx=(8, 0))
        self.cancel_btn = ctk.CTkButton(btn_frm, text="Cancel", width=120, command=self._on_cancel)
        self.cancel_btn.pack(side="right")

        # keyboard bindings
        self.bind('<Return>', lambda e: self._on_ok())
        self.bind('<Escape>', lambda e: self._on_cancel())

    def _browse_policy(self):
        p = filedialog.askopenfilename(title="Select policy baseline (JSON)")
        if p:
            try:
                self.policy_var.set(p)
            except Exception:
                pass

    def _on_ok(self):
        # sanitize values and call callback
        try:
            md = 2
            try:
                md = int(self.max_depth_var.get())
            except Exception:
                md = 2
            out = {
                "policy": self.policy_var.get() or "",
                "max_extract_depth": max(0, md),
                "build_ast": bool(self.ast_var.get()),
                "build_disasm": bool(self.disasm_var.get()),
                "extract_archives": bool(self.extract_var.get()),
                "fast_scan": bool(self.fast_scan_var.get()),
            }
            try:
                self.on_apply(out)
            except Exception:
                pass
        finally:
            try:
                self.grab_release()
            except Exception:
                pass
            try:
                self.destroy()
            except Exception:
                pass

    def _on_cancel(self):
        try:
            self.grab_release()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
