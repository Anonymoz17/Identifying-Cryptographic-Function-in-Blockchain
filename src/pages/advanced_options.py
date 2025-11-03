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
            tab.add("General")
            tab.add("Extraction")
            tab.add("Hashing")
            tab.add("Preproc")
            tab.add("Persistence")
            tab.add("Performance")
            tab.add("Diagnostics")

            # General tab (placeholders -> now interactive)
            g = tab.tab("General")
            ctk.CTkLabel(g, text="General settings").pack(anchor="w", pady=(6, 2))
            ctk.CTkLabel(g, text="Profile name:").pack(anchor="w")
            self._profile_name = ctk.CTkEntry(g, width=420)
            # prefill profile name if provided
            try:
                self._profile_name.insert(0, str(self.values.get('profile_name', '')))
            except Exception:
                pass
            self._profile_name.pack(anchor="w", pady=(2, 8))

            # Policy baseline path (file)
            ctk.CTkLabel(g, text="Policy baseline (JSON, optional):").pack(anchor="w")
            pol_fr = ctk.CTkFrame(g, fg_color="transparent")
            pol_fr.pack(anchor="w", fill="x")
            self._policy_entry = ctk.CTkEntry(pol_fr, width=320)
            try:
                # prefill policy if present in initial values
                self._policy_entry.insert(0, str(self.values.get('policy', '')))
            except Exception:
                pass
            self._policy_entry.pack(side="left", pady=(2, 8))
            def _browse_policy_local():
                try:
                    from tkinter import filedialog
                    # prefer JSON files but allow all files as fallback
                    p = filedialog.askopenfilename(title="Select policy baseline (JSON)", filetypes=[("JSON files", "*.json"), ("All files", "*")])
                    if p:
                        try:
                            self._policy_entry.delete(0, 'end')
                            self._policy_entry.insert(0, p)
                        except Exception:
                            pass
                        # run validation immediately after selecting a file
                        try:
                            from auditor.setup_flow.advanced_settings import validate_policy_path
                            ok, msg = validate_policy_path(p)
                            try:
                                self._policy_warn.configure(text=msg if not ok else '')
                            except Exception:
                                pass
                        except Exception:
                            pass
                except Exception:
                    pass
            self._policy_browse = ctk.CTkButton(pol_fr, text="Browse", width=90, command=_browse_policy_local)
            self._policy_browse.pack(side="left", padx=(8, 0))
            self._policy_warn = ctk.CTkLabel(g, text="", text_color="#d1b000", font=("Roboto", 10))
            self._policy_warn.pack(anchor="w", pady=(0, 8))
            # Live validation of the policy entry using the shared helper
            try:
                def _on_policy_change(event=None):
                    try:
                        from auditor.setup_flow.advanced_settings import validate_policy_path

                        ok, msg = validate_policy_path(self._policy_entry.get().strip())
                        try:
                            self._policy_warn.configure(text=msg if not ok else '')
                        except Exception:
                            pass
                    except Exception:
                        pass

                self._policy_entry.bind('<KeyRelease>', _on_policy_change)
            except Exception:
                pass
            # Case subdir
            ctk.CTkLabel(g, text="Case subdir (used in default workdir):").pack(anchor="w")
            self._case_subdir = ctk.CTkEntry(g, width=200)
            self._case_subdir.insert(0, str(self.values.get("case_subdir", "cases")))
            self._case_subdir.pack(anchor="w", pady=(2, 6))

            # Live preview of the canonical default workdir
            from auditor.setup_flow import advanced_settings as ui_settings

            preview_text = ui_settings.default_workdir_preview(self._case_subdir.get())
            self._workdir_preview = ctk.CTkLabel(g, text=f"Default workdir: {preview_text}", text_color="#aab", font=("Roboto", 10))
            self._workdir_preview.pack(anchor="w", pady=(0, 8))

            # Save-as-default
            self._save_default_var = tk.BooleanVar(value=bool(self.values.get("save_as_default", False)))
            ctk.CTkCheckBox(g, text="Save this profile as default", variable=self._save_default_var).pack(anchor="w", pady=(6, 2))

            # Bind updates to case_subdir to update preview
            try:
                def _on_case_subdir_change(event=None):
                    try:
                        cs = self._case_subdir.get().strip() or "cases"
                        prev = ui_settings.default_workdir_preview(cs)
                        try:
                            self._workdir_preview.configure(text=f"Default workdir: {prev}")
                        except Exception:
                            pass
                    except Exception:
                        pass
                self._case_subdir.bind("<KeyRelease>", _on_case_subdir_change)
            except Exception:
                pass

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
        # placeholder: reset UI values to defaults
        try:
            # attempt to load the named profile, or the 'default' profile
            try:
                from auditor.setup_flow.advanced_settings import load_profile

                name = self._profile_name.get().strip() if hasattr(self, '_profile_name') else ''
                profile = None
                if name:
                    profile = load_profile(name=name)
                if profile is None:
                    profile = load_profile(name='default')
                if profile:
                    # merge into values and update UI fields
                    self.values.update(profile or {})
                    try:
                        self._profile_name.delete(0, 'end')
                        self._profile_name.insert(0, profile.get('profile_name', name or ''))
                    except Exception:
                        pass
                    try:
                        self._policy_entry.delete(0, 'end')
                        self._policy_entry.insert(0, profile.get('policy', ''))
                    except Exception:
                        pass
                    try:
                        self._case_subdir.delete(0, 'end')
                        self._case_subdir.insert(0, profile.get('case_subdir', 'cases'))
                    except Exception:
                        pass
                else:
                    # no profile found; clear to sensible defaults
                    self.values.clear()
                    try:
                        self._profile_name.delete(0, 'end')
                    except Exception:
                        pass
                    try:
                        self._policy_entry.delete(0, 'end')
                    except Exception:
                        pass
                    try:
                        self._case_subdir.delete(0, 'end')
                        self._case_subdir.insert(0, 'cases')
                    except Exception:
                        pass
            except Exception:
                # fallback: clear
                self.values.clear()
        except Exception:
            pass

    def _on_import(self):
        # placeholder: import JSON profile
        try:
            # default to profiles dir for convenience
            try:
                from auditor.setup_flow import advanced_settings as ui_settings

                initdir = str(ui_settings.profiles_dir())
            except Exception:
                initdir = None
            p = filedialog.askopenfilename(title="Import profile (JSON)", initialdir=initdir)
            if p:
                try:
                    import json

                    with open(p, 'r', encoding='utf-8') as fh:
                        data = json.load(fh)
                    if isinstance(data, dict):
                        self.values.update(data or {})
                        # reflect into UI
                        try:
                            self._profile_name.delete(0, 'end')
                            self._profile_name.insert(0, data.get('profile_name', ''))
                        except Exception:
                            pass
                        try:
                            self._policy_entry.delete(0, 'end')
                            self._policy_entry.insert(0, data.get('policy', ''))
                        except Exception:
                            pass
                        try:
                            self._case_subdir.delete(0, 'end')
                            self._case_subdir.insert(0, data.get('case_subdir', 'cases'))
                        except Exception:
                            pass
                        # validate referenced policy path
                        try:
                            from auditor.setup_flow.advanced_settings import validate_policy_path

                            ok, msg = validate_policy_path(data.get('policy', ''))
                            try:
                                self._policy_warn.configure(text=msg if not ok else '')
                            except Exception:
                                pass
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

    def _on_export(self):
        # placeholder: export current values to JSON file
        try:
            # default to profiles dir and suggest filename
            try:
                from auditor.setup_flow import advanced_settings as ui_settings

                initdir = str(ui_settings.profiles_dir())
            except Exception:
                initdir = None
            try:
                suggested = (self._profile_name.get().strip() or 'profile') + '.json'
            except Exception:
                suggested = 'profile.json'
            p = filedialog.asksaveasfilename(title="Export profile (JSON)", defaultextension='.json', initialdir=initdir, initialfile=suggested)
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
                out['profile_name'] = self._profile_name.get() if hasattr(self, '_profile_name') else ''
                out['policy'] = self._policy_entry.get().strip() if hasattr(self, '_policy_entry') else ''
                out['case_subdir'] = self._case_subdir.get() if hasattr(self, '_case_subdir') else 'cases'
                out['save_as_default'] = bool(self._save_default_var.get()) if hasattr(self, '_save_default_var') else False
            except Exception:
                pass
            # Validate policy baseline existence/readability when provided (use helper)
            try:
                from auditor.setup_flow.advanced_settings import validate_policy_path

                pol = out.get('policy')
                ok, msg = validate_policy_path(pol or '')
                if not ok:
                    try:
                        self._policy_warn.configure(text=msg)
                    except Exception:
                        pass
                    try:
                        self._policy_entry.focus_set()
                    except Exception:
                        pass
                    return
                else:
                    try:
                        self._policy_warn.configure(text='')
                    except Exception:
                        pass
            except Exception:
                # non-fatal: proceed if helper import/validation errors
                pass
            try:
                # if user asked to save as default, persist via setup_flow.ui_settings
                if out.get('save_as_default'):
                    try:
                        from auditor.setup_flow.advanced_settings import save_profile

                        prof_name = out.get('profile_name') or 'default'
                        save_profile(out, name=prof_name)
                    except Exception:
                        pass
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
