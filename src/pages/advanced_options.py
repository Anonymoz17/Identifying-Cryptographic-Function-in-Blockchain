from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Callable, Dict, Any
import customtkinter as ctk
from tkinter import filedialog


class AdvancedOptionsWindow(ctk.CTkToplevel):
    """Tabbed popup window for advanced/preproc settings (placeholders).

    This initial version creates a tabbed modal with placeholder controls for
    each settings category. Controls are created but not fully wired; the
    Apply/OK button returns a minimal dict of values to the caller. We'll
    implement each control incrementally in follow-up commits.
    """

    def __init__(self, parent, initial: Dict[str, Any], on_apply: Callable[[Dict[str, Any]], None]):
        super().__init__(parent)
        self.title("Advanced options")
        self.transient(parent)
        self.resizable(True, True)
        self.grab_set()
        self.on_apply = on_apply

        iv = initial or {}
        # store simple backing vars; actual controls per-tab will map to these
        self.values = dict(iv)

        # main frame
        frm = ctk.CTkFrame(self, fg_color="transparent")
        frm.pack(padx=12, pady=12, fill="both", expand=True)

        # Tabview: General | Extraction | Hashing | Preproc | Persistence | Performance | Diagnostics
        try:
            tab = ctk.CTkTabview(frm, width=760)
        except Exception:
            # fallback to a frame with stacked sections if CTkTabview not available
            tab = None

        if tab is not None:
            tab.pack(fill="both", expand=True)
            tab.add("Extraction")
            tab.add("Hashing")
            tab.add("Preproc")
            tab.add("Persistence")
            tab.add("Performance")
            tab.add("Diagnostics")

            # (General tab removed) — profiles and policy editing moved to
            # the global Accounts area (top-right). Advanced options now
            # contains only module-specific placeholders.

            # Extraction tab
            e = tab.tab("Extraction")
            ctk.CTkLabel(e, text="Extraction settings (placeholders)").pack(anchor="w", pady=(6, 2))
            ctk.CTkCheckBox(e, text="Extract archives (placeholder)").pack(anchor="w", pady=(6, 2))
            ctk.CTkLabel(e, text="Max extract depth (placeholder):").pack(anchor="w")
            self._max_depth = ctk.CTkEntry(e, width=120)
            self._max_depth.insert(0, str(iv.get("max_extract_depth", 2)))
            self._max_depth.pack(anchor="w", pady=(2, 8))

            # Hashing tab
            h = tab.tab("Hashing")
            ctk.CTkLabel(h, text="Hashing & dedupe (placeholders)").pack(anchor="w", pady=(6, 2))
            ctk.CTkCheckBox(h, text="Fast scan (no hashing) (placeholder)").pack(anchor="w", pady=(6, 2))

            # Preproc tab
            p = tab.tab("Preproc")
            ctk.CTkLabel(p, text="Preprocessing & caches (placeholders)").pack(anchor="w", pady=(6, 2))
            ctk.CTkCheckBox(p, text="Generate AST cache (placeholder)").pack(anchor="w", pady=(6, 2))
            ctk.CTkCheckBox(p, text="Generate disasm cache (placeholder)").pack(anchor="w", pady=(6, 2))

            # Persistence tab
            per = tab.tab("Persistence")
            ctk.CTkLabel(per, text="Output & persistence (placeholders)").pack(anchor="w", pady=(6, 2))
            ctk.CTkLabel(per, text="NDJSON flush size (placeholder):").pack(anchor="w")
            ctk.CTkEntry(per, width=120).pack(anchor="w", pady=(2, 8))

            # Performance tab
            perf = tab.tab("Performance")
            ctk.CTkLabel(perf, text="Performance & limits (placeholders)").pack(anchor="w", pady=(6, 2))
            ctk.CTkLabel(perf, text="Parallel workers (placeholder):").pack(anchor="w")
            ctk.CTkEntry(perf, width=120).pack(anchor="w", pady=(2, 8))

            # Diagnostics tab
            d = tab.tab("Diagnostics")
            ctk.CTkLabel(d, text="Diagnostics & logging (placeholders)").pack(anchor="w", pady=(6, 2))
            ctk.CTkButton(d, text="Export debug bundle (placeholder)", width=220).pack(anchor="w", pady=(8, 0))

        else:
            # Fallback: stacked placeholder sections
            ctk.CTkLabel(frm, text="Advanced settings (tabview unavailable) — placeholders").pack(anchor="w")

        # Bottom action buttons
        btn_frm = ctk.CTkFrame(frm, fg_color="transparent")
        btn_frm.pack(fill="x", pady=(12, 0))
        left_fr = ctk.CTkFrame(btn_frm, fg_color="transparent")
        left_fr.pack(side="left")
        right_fr = ctk.CTkFrame(btn_frm, fg_color="transparent")
        right_fr.pack(side="right")

        self.revert_btn = ctk.CTkButton(left_fr, text="Revert to defaults", width=160, command=self._on_revert)
        self.revert_btn.pack(side="left")
        self.import_btn = ctk.CTkButton(left_fr, text="Import…", width=100, command=self._on_import)
        self.import_btn.pack(side="left", padx=(8, 0))
        self.export_btn = ctk.CTkButton(left_fr, text="Export…", width=100, command=self._on_export)
        self.export_btn.pack(side="left", padx=(8, 0))

        self.ok_btn = ctk.CTkButton(right_fr, text="OK", width=120, command=self._on_ok)
        self.ok_btn.pack(side="right", padx=(8, 0))
        self.cancel_btn = ctk.CTkButton(right_fr, text="Cancel", width=120, command=self._on_cancel)
        self.cancel_btn.pack(side="right")

        # keyboard bindings
        self.bind('<Return>', lambda e: self._on_ok())
        self.bind('<Escape>', lambda e: self._on_cancel())

    def _on_revert(self):
        # placeholder: reset advanced options to defaults
        try:
            self.values.clear()
        except Exception:
            pass

    def _on_import(self):
        # placeholder: import a JSON settings file into advanced values
        try:
            p = filedialog.askopenfilename(title="Import advanced settings (JSON)", filetypes=[("JSON files", "*.json"), ("All files", "*")])
            if p:
                try:
                    import json

                    with open(p, 'r', encoding='utf-8') as fh:
                        data = json.load(fh)
                    if isinstance(data, dict):
                        self.values.update(data)
                except Exception:
                    pass
        except Exception:
            pass

    def _on_export(self):
        # placeholder: export current values to JSON file
        try:
            p = filedialog.asksaveasfilename(title="Export profile (JSON)", defaultextension='.json')
            if p:
                try:
                    import json

                    with open(p, 'w', encoding='utf-8') as fh:
                        json.dump(self.values or {}, fh, indent=2)
                except Exception:
                    pass
        except Exception:
            pass

    def _on_ok(self):
        try:
            # collect a minimal set of values and call back
            out = dict(self.values or {})
            try:
                # apply values (placeholder). Persistence is handled in Accounts.
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
