from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from settings import (
    get_default_workdir,
    get_fast_count_timeout,
    get_setting,
    set_default_workdir,
    set_fast_count_timeout,
    set_setting,
)


class PreferencesDialog:
    """Modal preferences dialog that loads/saves app settings.

    Usage:
        PreferencesDialog.open(parent)
    """

    @staticmethod
    def open(parent: tk.Widget) -> None:
        top = tk.Toplevel(parent)
        top.title("Preferences")
        top.transient(parent)
        top.grab_set()

        frame = ctk.CTkFrame(top, fg_color="transparent")
        frame.pack(padx=12, pady=12, fill="both", expand=True)

        # Default workdir
        ctk.CTkLabel(frame, text="Default workdir:").grid(row=0, column=0, sticky="w")
        wd_entry = ctk.CTkEntry(frame, width=480)
        try:
            wd_entry.insert(0, str(get_default_workdir()))
        except Exception:
            wd_entry.insert(0, "")
        wd_entry.grid(row=0, column=1, columnspan=2, pady=(4, 8), sticky="we")

        # Fast-count timeout
        ctk.CTkLabel(frame, text="Fast-count timeout (s):").grid(
            row=1, column=0, sticky="w"
        )
        fc_entry = ctk.CTkEntry(frame, width=80)
        try:
            fc_entry.insert(0, str(get_fast_count_timeout()))
        except Exception:
            fc_entry.insert(0, "0.8")
        fc_entry.grid(row=1, column=1, sticky="w", pady=(4, 8))

        # Max preview sample
        ctk.CTkLabel(frame, text="Preview sample size:").grid(
            row=2, column=0, sticky="w"
        )
        sample_entry = ctk.CTkEntry(frame, width=80)
        try:
            sample_entry.insert(0, str(get_setting("preview_sample_limit", 200)))
        except Exception:
            sample_entry.insert(0, "200")
        sample_entry.grid(row=2, column=1, sticky="w", pady=(4, 8))

        # Max file size default (KB)
        ctk.CTkLabel(frame, text="Default max file size (KB):").grid(
            row=3, column=0, sticky="w"
        )
        maxsz_entry = ctk.CTkEntry(frame, width=80)
        try:
            maxsz_entry.insert(0, str(get_setting("max_file_size_kb", 0)))
        except Exception:
            maxsz_entry.insert(0, "0")
        maxsz_entry.grid(row=3, column=1, sticky="w", pady=(4, 8))

        # Extract archives default
        try:
            extract_default = bool(get_setting("do_extract", True))
        except Exception:
            extract_default = True
        extract_var = tk.BooleanVar(value=extract_default)
        ctk.CTkCheckBox(
            frame, text="Extract archives by default", variable=extract_var
        ).grid(row=3, column=2, sticky="w")

        # Max extract depth default
        ctk.CTkLabel(frame, text="Default max extract depth:").grid(
            row=4, column=0, sticky="w"
        )
        maxdepth_entry = ctk.CTkEntry(frame, width=80)
        try:
            maxdepth_entry.insert(0, str(get_setting("max_extract_depth", 2)))
        except Exception:
            maxdepth_entry.insert(0, "2")
        maxdepth_entry.grid(row=4, column=1, sticky="w", pady=(4, 8))

        # Follow symlinks default
        try:
            fs_default = bool(get_setting("follow_symlinks", False))
        except Exception:
            fs_default = False
        follow_var = tk.BooleanVar(value=fs_default)
        ctk.CTkCheckBox(
            frame, text="Follow symlinks by default", variable=follow_var
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 8))

        # Confirm thresholds for large scans
        ctk.CTkLabel(frame, text="Confirm threshold (bytes):").grid(
            row=5, column=0, sticky="w"
        )
        thr_bytes_entry = ctk.CTkEntry(frame, width=160)
        try:
            thr_bytes_entry.insert(
                0, str(get_setting("confirm_threshold_bytes", 5 * 1024 * 1024 * 1024))
            )
        except Exception:
            thr_bytes_entry.insert(0, str(5 * 1024 * 1024 * 1024))
        thr_bytes_entry.grid(row=5, column=1, sticky="w", pady=(4, 8))

        ctk.CTkLabel(frame, text="Confirm threshold (files):").grid(
            row=6, column=0, sticky="w"
        )
        thr_files_entry = ctk.CTkEntry(frame, width=160)
        try:
            thr_files_entry.insert(
                0, str(get_setting("confirm_threshold_files", 100000))
            )
        except Exception:
            thr_files_entry.insert(0, "100000")
        thr_files_entry.grid(row=6, column=1, sticky="w", pady=(4, 8))

        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.grid(row=8, column=0, columnspan=3, pady=(12, 0))

        def _save_prefs():
            try:
                wd = wd_entry.get().strip()
                if wd:
                    set_default_workdir(wd)
            except Exception:
                pass
            try:
                fct = float(fc_entry.get().strip() or "0")
                set_fast_count_timeout(fct)
            except Exception:
                pass
            try:
                sample = int(sample_entry.get().strip() or "200")
                set_setting("preview_sample_limit", sample)
            except Exception:
                pass
            try:
                msz = int(maxsz_entry.get().strip() or "0")
                set_setting("max_file_size_kb", msz)
            except Exception:
                pass
            try:
                set_setting("do_extract", bool(extract_var.get()))
            except Exception:
                pass
            try:
                med = int(maxdepth_entry.get().strip() or "2")
                set_setting("max_extract_depth", med)
            except Exception:
                pass
            try:
                set_setting("follow_symlinks", bool(follow_var.get()))
            except Exception:
                pass
            try:
                tb = int(thr_bytes_entry.get().strip() or 0)
                set_setting("confirm_threshold_bytes", tb)
            except Exception:
                pass
            try:
                tf = int(thr_files_entry.get().strip() or 0)
                set_setting("confirm_threshold_files", tf)
            except Exception:
                pass
            top.destroy()

        def _cancel():
            top.destroy()

        ctk.CTkButton(btns, text="Save", command=_save_prefs).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(btns, text="Cancel", command=_cancel).pack(side="left")
        top.wait_window()
