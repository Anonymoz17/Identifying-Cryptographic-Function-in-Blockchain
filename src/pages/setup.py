from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
import tkinter as tk
import urllib.parse
from functools import partial
from pathlib import Path
from tkinter import filedialog, messagebox

from auditor.auditlog import AuditLog
from auditor.case import Engagement
from auditor.intake import (
    count_inputs_fast,
    enumerate_inputs,
    estimate_disk_usage,
    write_manifest,
)
from auditor.preproc import preprocess_items
from auditor.workspace import Workspace
from policy_import import import_and_record_policy
from policy_validator import validate_policy_text
from settings import (
    get_canonical_workdir,
    get_default_workdir,
    get_fast_count_timeout,
    get_setting,
    reset_default_workdir,
    set_default_workdir,
    set_fast_count_timeout,
    set_setting,
)
from ui.tooltip import add_tooltip

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
        # Use the app's canonical per-user default workdir when available.
        try:
            default_workdir = str(get_default_workdir())
        except Exception:
            try:
                default_workdir = str((Path.cwd() / "case_demo" / "cases").resolve())
            except Exception:
                default_workdir = str(Path.home() / "CryptoScope" / "cases")
        self.workdir_entry.insert(0, default_workdir)
        self.workdir_entry.grid(row=0, column=1, sticky="we", padx=(6, 0))
        try:
            add_tooltip(
                self.workdir_entry,
                "Path where case data will be created. Use the canonical default or choose a custom folder.",
            )
        except Exception:
            pass
        # Workdir browse button
        self.workdir_browse = ctk.CTkButton(
            form, text="Browse", width=90, command=self._browse_workdir
        )
        self.workdir_browse.grid(row=0, column=2, padx=(8, 0))

        # row below Workdir: show canonical recommended path and quick actions
        canonical_frame = ctk.CTkFrame(form, fg_color="transparent")
        canonical_frame.grid(row=0, column=3, sticky="we", padx=(8, 0))
        try:
            canonical = str(get_canonical_workdir())
        except Exception:
            canonical = ""
        self._canonical_label = ctk.CTkLabel(
            canonical_frame, text=f"Recommended: {canonical}", wraplength=320
        )
        self._canonical_label.grid(row=0, column=0, sticky="w")
        # small actions: Use canonical (set entry + persist) and Reset to default (clear user setting)
        self.use_canonical_btn = ctk.CTkButton(
            canonical_frame,
            text="Use canonical",
            width=120,
            command=self._use_canonical,
        )
        self.use_canonical_btn.grid(row=1, column=0, pady=(6, 0), sticky="w")
        self.reset_canonical_btn = ctk.CTkButton(
            canonical_frame,
            text="Reset to default",
            width=120,
            command=self._reset_to_canonical,
        )
        self.reset_canonical_btn.grid(row=1, column=1, pady=(6, 0), padx=(6, 0))
        # Migration action: offer to move/copy existing non-canonical workdirs
        self.migrate_btn = ctk.CTkButton(
            canonical_frame,
            text="Migrate workspace",
            width=140,
            command=self._open_migration_dialog,
        )
        self.migrate_btn.grid(row=2, column=0, columnspan=2, pady=(6, 0), sticky="w")

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
        # Right-side area: optional Repo URL input and clone checkbox so the
        # UI clearly separates local folder scope vs a repository URL.
        scope_right = ctk.CTkFrame(form, fg_color="transparent")
        scope_right.grid(row=2, column=3, padx=(8, 0), sticky="we")
        # Repo URL entry (if provided, this will be treated as a repo to clone)
        ctk.CTkLabel(scope_right, text="Repo URL:").grid(row=0, column=0, sticky="w")
        self.repo_entry = ctk.CTkEntry(
            scope_right, placeholder_text="https://... or git@..."
        )
        self.repo_entry.grid(row=1, column=0, sticky="we", pady=(4, 6))
        # Option: treat the scope as a Git repo URL and clone it locally
        self.git_clone_var = tk.BooleanVar(value=False)
        try:
            ctk.CTkCheckBox(
                scope_right,
                text="Clone repo (if URL)",
                variable=self.git_clone_var,
            ).grid(row=2, column=0, sticky="w")
        except Exception:
            # fallback: ignore if customtkinter configuration differs
            pass

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
        try:
            add_tooltip(
                self.policy_edit,
                "Open the policy editor: pick a template or edit JSON. Use Insert to write a temp policy or Save As to persist.",
            )
        except Exception:
            pass

        # Advanced preproc options are now managed in Preferences to keep the
        # Setup page focused. Click Preferences to configure filters, extraction,
        # symlink behavior, and detector defaults.
        adv_note = ctk.CTkLabel(
            form,
            text="Advanced preprocessing options are in Preferences → Configure advanced settings.",
            wraplength=520,
            text_color="#6c757d",
        )
        adv_note.grid(row=4, column=1, sticky="w", padx=(6, 0))

        # Detector selection is handled on the Detectors page; keep Setup focused
        # on preprocessing options (AST/disasm toggles) and filters. Defaults
        # for detectors are persisted/read by the Detectors page itself.

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
        self.prefs_btn = ctk.CTkButton(
            actions, text="Preferences", command=self._open_preferences_modal
        )
        self.prefs_btn.pack(side="left", padx=(8, 0))
        # Quick preview button: sample the scope without hashing to show counts
        self.preview_btn = ctk.CTkButton(
            actions, text="Preview Scope", command=self._on_preview_scope
        )
        self.preview_btn.pack(side="left", padx=(8, 0))

        # Progress
        self.progress_label = ctk.CTkLabel(content, text="")
        self.progress_label.pack(pady=(6, 2))
        self.progress = ctk.CTkProgressBar(content, width=480)
        self.progress.pack(pady=(2, 12))
        self.progress.set(0.0)
        # small transient label shown when waiting for background worker
        # cleanup after a cancellation (hidden by default)
        self.cleaning_label = ctk.CTkLabel(
            content, text="Cleaning up...", text_color="#6c757d"
        )
        self._cleaning_visible = False

        self.results_box = tk.Text(content, height=10, wrap="none")
        self.results_box.pack(fill="both", padx=12, pady=(6, 12), expand=False)

        # internal state
        self._cancel_event = None
        # background worker thread for the current engagement (if any)
        self._worker_thread = None
        # indeterminate ticker state for long-running stages
        self._indeterminate_running = False
        self._indeterminate_val = 0.0
        self._current_stage = None
        self._current_stage_determinate = False
        # per-stage start timestamps (for simple ETA/rate estimation)
        self._stage_timers = {}
        # whether the current flow has been cancelled by the user
        self._cancelled = False
        # whether the numeric progress bar is currently visible
        self._progress_visible = True

    def _append_result(self, text: str):
        """Append a line to the results box (safe to call from main thread).

        Callers from background threads should schedule via self.after(0, ...).
        """
        try:
            self.results_box.insert("end", text)
            self.results_box.see("end")
        except Exception:
            pass

    def _start_spinner(self, message: str = "Working..."):
        # Start a lightweight indeterminate ticker that nudges the numeric
        # bar forward gently and updates the status label. This is simpler
        # and less error-prone than the previous complex spinner logic.
        self._indeterminate_running = True
        self._indeterminate_val = 0.0
        try:
            self.progress_label.configure(text=message)
        except Exception:
            pass
        self.after(150, self._indeterminate_tick)

    def _indeterminate_tick(self):
        # tick function for indeterminate progress: gently advances the bar
        # but never reaches 100% so later stages can visibly replace it.
        if not getattr(self, "_indeterminate_running", False):
            return
        v = (getattr(self, "_indeterminate_val", 0.0) + 0.02) % 1.0
        self._indeterminate_val = v
        # map to a gentle range [0.1, 0.85]
        pulse = 0.1 + 0.75 * v
        try:
            self.progress.set(pulse)
        except Exception:
            pass
        # animate dots in label for visible activity
        try:
            base = self.progress_label.cget("text").split("...")[0]
            dots = int((self._indeterminate_val * 4) % 4)
            self.progress_label.configure(text=f"{base}{'.' * dots}")
        except Exception:
            pass
        self.after(200, self._indeterminate_tick)

    def _stop_spinner(self):
        self._indeterminate_running = False
        try:
            self.progress.set(0.0)
        except Exception:
            pass

    def _show_progress_bar(self, show: bool):
        """Show or hide the numeric progress bar widget."""
        try:
            if show and not getattr(self, "_progress_visible", False):
                # re-pack the progress widget in the same place it was
                # originally packed. We assume the layout from __init__.
                self.progress.pack(pady=(2, 12))
                self._progress_visible = True
            elif not show and getattr(self, "_progress_visible", False):
                try:
                    self.progress.pack_forget()
                except Exception:
                    pass
                self._progress_visible = False
        except Exception:
            pass

    def _show_cleaning_label(self, show: bool):
        """Show or hide the small "Cleaning up..." label while worker finishes."""
        try:
            if show and not getattr(self, "_cleaning_visible", False):
                # insert the cleaning label immediately before the numeric
                # progress bar so it appears beneath the main status label.
                try:
                    self.cleaning_label.pack(pady=(0, 4), before=self.progress)
                except Exception:
                    try:
                        self.cleaning_label.pack(pady=(0, 4))
                    except Exception:
                        pass
                self._cleaning_visible = True
            elif not show and getattr(self, "_cleaning_visible", False):
                try:
                    self.cleaning_label.pack_forget()
                except Exception:
                    pass
                self._cleaning_visible = False
        except Exception:
            pass

    def _begin_stage(self, name: str, determinate: bool = False):
        """Begin a named stage. Resets the progress bar and updates label.

        If determinate=True the caller is expected to update the bar with
        fractional values (0.0-1.0). If determinate=False an indeterminate
        spinner will be shown.
        """
        try:
            # if we've been cancelled, don't start new stages
            if getattr(self, "_cancelled", False):
                try:
                    self.after(
                        0, self._append_result, f"==> {name} skipped (cancelled)\n"
                    )
                except Exception:
                    pass
                return
            # reset numeric bar and record whether this stage will be
            # determinate (i.e. we expect a known total) or not.
            self._current_stage = name
            self._current_stage_determinate = bool(determinate)
            self.after(0, self.progress.set, 0.0)
            self.after(0, self.progress_label.configure, {"text": f"{name} — 0"})
            # record stage start time for ETA/rate estimation
            try:
                self._stage_timers[name] = time.time()
            except Exception:
                pass
            # if determinate, stop the spinner animation and show numeric
            # bar; otherwise hide the numeric bar and show indeterminate
            # spinner label animation.
            if determinate:
                # ensure indeterminate ticker is stopped and numeric bar shown
                self._indeterminate_running = False
                self._show_progress_bar(True)
            else:
                # start indeterminate ticker with a clear message
                self._show_progress_bar(True)
                self._start_spinner(f"{name}...")
            # append a short message to the results box so the user sees a
            # persistent trace of stage transitions
            try:
                self.after(0, self._append_result, f">>> {name} started\n")
            except Exception:
                pass
        except Exception:
            pass

    def _end_stage(self, name: str, keep_message: bool = True):
        """Mark a named stage as completed. Sets progress to 100% briefly and
        stops the spinner. If keep_message is False the status label is cleared.
        After a short delay the bar will be reset to 0 to prepare for the next
        stage.
        """
        try:
            # stop indeterminate ticker and show completion briefly
            self._indeterminate_running = False
            self.after(0, self.progress.set, 1.0)
            if keep_message:
                try:
                    self.after(
                        0,
                        self.progress_label.configure,
                        {"text": f"{name} — completed"},
                    )
                except Exception:
                    pass
            else:
                try:
                    self.after(0, self.progress_label.configure, {"text": ""})
                except Exception:
                    pass

            # reset progress after a short pause so the next stage is visually
            # distinct and the bar does not immediately appear full again.
            def _reset_after_delay():
                self.progress.set(0.0)
                # clear the label if requested
                if not keep_message:
                    try:
                        self.progress_label.configure(text="")
                    except Exception:
                        pass
                # clear current stage marker and determinate flag
                self._current_stage = None
                self._current_stage_determinate = False

            try:
                self.after(700, _reset_after_delay)
            except Exception:
                _reset_after_delay()

            # append completion to the results box
            def _log_end():
                try:
                    self.results_box.insert("end", f"<<< {name} completed\n")
                    self.results_box.see("end")
                except Exception:
                    pass

            # clear any recorded timer for this stage
            try:
                if name in self._stage_timers:
                    try:
                        del self._stage_timers[name]
                    except Exception:
                        pass
            except Exception:
                pass
            self.after(0, _log_end)
        except Exception:
            pass

    def _browse_scope(self):
        path = self._open_dialog(
            filedialog.askdirectory,
            parent=self.winfo_toplevel(),
            title="Select folder for scope",
        )
        if path:
            self.scope_entry.delete(0, "end")
            self.scope_entry.insert(0, path)

    def _update_progress(
        self,
        stage: str,
        processed: int,
        total: int | None = None,
        path: str | None = None,
    ):
        """Unified progress updater used by background callbacks.

        - stage: human name (e.g. 'Scanning' or 'Preprocessing')
        - processed: number processed so far
        - total: optional total; when present we operate in determinate mode
        - path: optional current item path for short label
        """
        # if this stage is different, start it with appropriate mode
        if self._current_stage != stage:
            self._begin_stage(stage, determinate=bool(total))

        # cancellation quick-check
        if (
            getattr(self, "_cancel_event", None) is not None
            and self._cancel_event.is_set()
        ) or getattr(self, "_cancelled", False):
            self._cancelled = True
            self._set_status("Cancelling...")
            self._stop_spinner()
            self.progress.set(0.0)
            self._append_result(f"{stage.lower()}: cancelled by user\n")
            return

        short = Path(path).name if path else ""
        # determinate path
        if total and total > 0:
            # ensure determinate mode
            if not self._current_stage_determinate:
                self._begin_stage(stage, determinate=True)
            frac = min(1.0, float(processed) / float(total))
            self.progress.set(frac)
            # compute ETA using recorded stage start time when available
            eta_text = ""
            try:
                start = self._stage_timers.get(stage)
                if start:
                    elapsed = max(0.001, time.time() - float(start))
                    # require a minimum sample size to avoid noisy ETA
                    if elapsed >= 0.5 and processed >= 5:
                        rate = float(processed) / float(elapsed)
                        if rate > 0:
                            remaining = float(total - processed)
                            eta = int(remaining / rate)
                            # format ETA as M:SS or S s
                            if eta >= 60:
                                eta_text = f" — ETA: {eta//60}:{eta%60:02d}"
                            else:
                                eta_text = f" — ETA: {eta}s"
            except Exception:
                eta_text = ""
            self.progress_label.configure(
                text=f"{stage} {processed}/{total} — {short}{eta_text}"
            )
            # log occasionally to the results box
            if processed % max(1, total // 10 if total >= 10 else 1) == 0:
                self._append_result(f"{stage.lower()}: {processed}/{total}\n")
        else:
            # indeterminate: keep ticker running and show counts
            if self._current_stage_determinate:
                # switch to indeterminate if no total available
                self._begin_stage(stage, determinate=False)
            # start ticker if not already
            if not getattr(self, "_indeterminate_running", False):
                self._start_spinner(f"{stage}... ({processed})")
            # indeterminate: show processed count and optionally an
            # estimated rate if we have a timer.
            rate_text = ""
            try:
                start = self._stage_timers.get(stage)
                if start:
                    elapsed = max(0.001, time.time() - float(start))
                    if elapsed >= 0.5 and processed >= 5:
                        rate = float(processed) / float(elapsed)
                        rate_text = f" — {rate:.1f}/s"
            except Exception:
                rate_text = ""
            self.progress_label.configure(
                text=f"{stage} {processed} (estimating total...){rate_text} — {short}"
            )
            if processed % 50 == 0:
                self._append_result(f"{stage.lower()}: {processed} items...\n")

    def _browse_workdir(self):
        path = self._open_dialog(
            filedialog.askdirectory,
            parent=self.winfo_toplevel(),
            title="Select work directory",
        )
        if path:
            try:
                # If the chosen path differs from the recommended canonical
                # path, ask the user if they'd prefer to use the canonical
                # location. This is a non-destructive suggestion only.
                try:
                    canonical = str(get_canonical_workdir())
                except Exception:
                    canonical = None

                if canonical and str(Path(path).resolve()) != str(
                    Path(canonical).resolve()
                ):
                    try:
                        msg = (
                            f"You selected a non-standard workdir:\n{path}\n\n"
                            f"Recommended canonical path:\n{canonical}\n\n"
                            "Would you like to use the recommended location instead?"
                        )
                        r = messagebox.askyesno("Use canonical workdir?", msg)
                        if r:
                            # user chose canonical
                            chosen = canonical
                        else:
                            chosen = path
                    except Exception:
                        chosen = path
                else:
                    chosen = path

                # set the entry and persist the chosen preference
                self.workdir_entry.delete(0, "end")
                self.workdir_entry.insert(0, chosen)
                try:
                    set_default_workdir(chosen)
                except Exception:
                    pass
                # update canonical label in case system defaults changed
                try:
                    can = str(get_canonical_workdir())
                    self._canonical_label.configure(text=f"Recommended: {can}")
                except Exception:
                    pass
            except Exception:
                pass

    def _browse_policy(self):
        path = self._open_dialog(
            filedialog.askopenfilename,
            parent=self.winfo_toplevel(),
            title="Select policy baseline (JSON)",
        )
        if path:
            try:
                self.policy_entry.delete(0, "end")
                self.policy_entry.insert(0, path)
            except Exception:
                pass

    def _open_dialog(self, fn, /, **kwargs):
        """Wrapper to open file dialogs with a small UI pre/post handling.

        - calls update_idletasks() before opening the dialog to flush pending
          UI updates
        - calls the provided dialog function `fn(**kwargs)` synchronously
        - schedules a short post-dialog cleanup via after() so the main loop
          can handle redraws and avoid perceived hangs
        Returns the dialog result (or None).
        """
        try:
            # flush pending UI work
            self.update_idletasks()
        except Exception:
            pass
        try:
            res = fn(**kwargs)
        except Exception:
            res = None

        # schedule a tiny cleanup so focus is restored and UI can redraw
        try:
            self.after(50, self._dialog_post_cleanup)
        except Exception:
            try:
                self._dialog_post_cleanup()
            except Exception:
                pass
        return res

    def _dialog_post_cleanup(self):
        try:
            # restore focus to top-level window and process pending events
            top = self.winfo_toplevel()
            try:
                top.focus_force()
            except Exception:
                pass
            try:
                top.update()
            except Exception:
                pass
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

        # Template selector + two-pane editor: structured form (left) + raw JSON (right)
        frame = ctk.CTkFrame(top, fg_color="transparent")
        frame.pack(padx=12, pady=12, fill="both", expand=True)

        # Row 0: template selector
        ctk.CTkLabel(frame, text="Template:").grid(row=0, column=0, sticky="w")
        templates = ["Whitelist", "Rule Overrides", "Scoring", "Combined"]
        tmpl_var = tk.StringVar(value=templates[0])
        tmpl_menu = ctk.CTkOptionMenu(frame, values=templates, variable=tmpl_var)
        tmpl_menu.grid(row=0, column=1, sticky="we", padx=(8, 0), columnspan=2)

        # Split area: structured form (left) and raw JSON editor (right)
        split = ctk.CTkFrame(frame, fg_color="transparent")
        split.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=(8, 8))
        split.grid_columnconfigure(0, weight=1)
        split.grid_columnconfigure(1, weight=2)

        # Left: structured fields for common policy elements
        form_frame = ctk.CTkFrame(split, fg_color="transparent")
        form_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        form_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form_frame, text="Version:").grid(row=0, column=0, sticky="w")
        version_entry = ctk.CTkEntry(form_frame)
        version_entry.grid(row=0, column=1, sticky="we", pady=(2, 6))

        ctk.CTkLabel(form_frame, text="Author:").grid(row=1, column=0, sticky="w")
        author_entry = ctk.CTkEntry(form_frame)
        author_entry.grid(row=1, column=1, sticky="we", pady=(2, 6))

        ctk.CTkLabel(form_frame, text="Metadata version:").grid(
            row=2, column=0, sticky="w"
        )
        meta_ver_entry = ctk.CTkEntry(form_frame)
        meta_ver_entry.grid(row=2, column=1, sticky="we", pady=(2, 6))

        # Scoring engine weights (common tuning knobs)
        ctk.CTkLabel(form_frame, text="Engine weights (yara/treesitter/disasm):").grid(
            row=3, column=0, sticky="w", columnspan=2
        )
        ew_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        ew_frame.grid(row=4, column=0, columnspan=2, sticky="we", pady=(2, 6))
        yara_w = ctk.CTkEntry(ew_frame, width=60)
        yara_w.grid(row=0, column=0, padx=(0, 6))
        ts_w = ctk.CTkEntry(ew_frame, width=60)
        ts_w.grid(row=0, column=1, padx=(0, 6))
        disasm_w = ctk.CTkEntry(ew_frame, width=60)
        disasm_w.grid(row=0, column=2)

        # Whitelist file hashes (comma-separated simple UI)
        ctk.CTkLabel(form_frame, text="Whitelist file hashes:").grid(
            row=5, column=0, sticky="w"
        )
        whitelist_entry = tk.Text(form_frame, height=6, wrap="none")
        whitelist_entry.grid(row=5, column=1, sticky="we", pady=(2, 6))

        # Right: raw JSON editor (kept for advanced edits)
        editor_frame = ctk.CTkFrame(split, fg_color="transparent")
        editor_frame.grid(row=0, column=1, sticky="nsew")
        editor_frame.grid_rowconfigure(0, weight=1)
        editor_frame.grid_columnconfigure(0, weight=1)

        editor = tk.Text(editor_frame, width=80, height=20, wrap="none")
        editor.grid(row=0, column=0, sticky="nsew")

        def _render_template(*_):
            kind = tmpl_var.get()
            editor.delete("1.0", "end")
            editor.insert("1.0", self._policy_template_json(kind))
            # update the structured form to reflect the template
            try:
                obj = json.loads(self._policy_template_json(kind))
                try:
                    json_to_form(obj)
                except Exception:
                    pass
            except Exception:
                pass

        tmpl_var.trace_add("write", _render_template)
        # populate initial
        _render_template()

        # Helper: map JSON object -> form fields
        def json_to_form(obj: dict):
            try:
                version = obj.get("version", "")
                version_entry.delete(0, "end")
                version_entry.insert(0, str(version))
            except Exception:
                pass
            try:
                meta = obj.get("metadata", {}) or {}
                author_entry.delete(0, "end")
                author_entry.insert(0, str(meta.get("author", "")))
                meta_ver_entry.delete(0, "end")
                meta_ver_entry.insert(0, str(meta.get("version", "")))
            except Exception:
                pass
            try:
                scoring = obj.get("scoring", {}) or {}
                ew = scoring.get("engine_weights", {}) or {}
                yara_w.delete(0, "end")
                yara_w.insert(0, str(ew.get("yara", "")))
                ts_w.delete(0, "end")
                ts_w.insert(0, str(ew.get("treesitter", "")))
                disasm_w.delete(0, "end")
                disasm_w.insert(0, str(ew.get("disasm", "")))
            except Exception:
                pass
            try:
                wl = obj.get("whitelist", {}) or {}
                fh = wl.get("file_hashes", []) or []
                whitelist_entry.delete("1.0", "end")
                whitelist_entry.insert("1.0", ",".join(str(x) for x in fh))
            except Exception:
                pass

        # Helper: map form fields -> JSON in editor (doesn't validate schema)
        def form_to_json():
            out = {}
            try:
                v = version_entry.get().strip()
                if v:
                    out["version"] = v
            except Exception:
                pass
            try:
                meta = {}
                a = author_entry.get().strip()
                if a:
                    meta["author"] = a
                mv = meta_ver_entry.get().strip()
                if mv:
                    meta["version"] = mv
                if meta:
                    out["metadata"] = meta
            except Exception:
                pass
            try:
                ew = {}
                y = yara_w.get().strip()
                t = ts_w.get().strip()
                d = disasm_w.get().strip()
                if y:
                    try:
                        ew["yara"] = float(y)
                    except Exception:
                        ew["yara"] = y
                if t:
                    try:
                        ew["treesitter"] = float(t)
                    except Exception:
                        ew["treesitter"] = t
                if d:
                    try:
                        ew["disasm"] = float(d)
                    except Exception:
                        ew["disasm"] = d
                if ew:
                    out.setdefault("scoring", {})["engine_weights"] = ew
            except Exception:
                pass
            try:
                fh_txt = whitelist_entry.get("1.0", "end").strip()
                if fh_txt:
                    fh = [s.strip() for s in fh_txt.split(",") if s.strip()]
                    out.setdefault("whitelist", {})["file_hashes"] = fh
            except Exception:
                pass
            try:
                editor.delete("1.0", "end")
                editor.insert(
                    "1.0", json.dumps(out, sort_keys=True, ensure_ascii=False, indent=2)
                )
                schedule_validate()
            except Exception:
                pass

        # Debounced form->json sync
        top.form_sync_timer = None

        def schedule_form_sync():
            try:
                if getattr(top, "form_sync_timer", None):
                    top.after_cancel(top.form_sync_timer)
            except Exception:
                pass
            try:
                top.form_sync_timer = top.after(300, form_to_json)
            except Exception:
                form_to_json()

        # Bind form changes to update raw JSON editor
        try:
            version_entry.bind("<KeyRelease>", lambda e: schedule_form_sync())
            author_entry.bind("<KeyRelease>", lambda e: schedule_form_sync())
            meta_ver_entry.bind("<KeyRelease>", lambda e: schedule_form_sync())
            yara_w.bind("<KeyRelease>", lambda e: schedule_form_sync())
            ts_w.bind("<KeyRelease>", lambda e: schedule_form_sync())
            disasm_w.bind("<KeyRelease>", lambda e: schedule_form_sync())
            whitelist_entry.bind("<KeyRelease>", lambda e: schedule_form_sync())
        except Exception:
            pass

        # Inline validation area (debounced): shows parse/schema errors and
        # disables Insert/Save while errors exist.
        error_var = tk.StringVar(value="")
        error_label = ctk.CTkLabel(frame, textvariable=error_var, text_color="#d9534f")
        error_label.grid(row=3, column=0, columnspan=3, sticky="we", pady=(0, 6))

        # attach simple debounce state to the modal window object
        top.policy_validate_timer = None
        top.last_policy_text = None
        # option to attach policy on Insert (will set an attribute on the page)
        attach_var = tk.BooleanVar(value=False)
        try:
            ctk.CTkCheckBox(frame, text="Attach on Insert", variable=attach_var).grid(
                row=4, column=0, sticky="w", pady=(4, 0)
            )
        except Exception:
            pass

        def schedule_validate():
            try:
                if getattr(top, "policy_validate_timer", None):
                    top.after_cancel(top.policy_validate_timer)
            except Exception:
                pass
            try:
                top.policy_validate_timer = top.after(400, run_validate)
            except Exception:
                run_validate()

        def run_validate():
            try:
                top.policy_validate_timer = None
                txt = editor.get("1.0", "end").strip()
                if txt == getattr(top, "last_policy_text", None):
                    return
                top.last_policy_text = txt
                valid, errors = validate_policy_text(txt)
                if not valid:
                    try:
                        error_var.set("\n".join(errors))
                    except Exception:
                        pass
                    try:
                        insert_btn.configure(state="disabled")
                    except Exception:
                        pass
                    try:
                        save_btn.configure(state="disabled")
                    except Exception:
                        pass
                else:
                    try:
                        error_var.set("")
                    except Exception:
                        pass
                    # when valid, update structured form to reflect current JSON
                    try:
                        obj = json.loads(txt)
                        try:
                            json_to_form(obj)
                        except Exception:
                            pass
                    except Exception:
                        pass
                    try:
                        insert_btn.configure(state="normal")
                    except Exception:
                        pass
                    try:
                        save_btn.configure(state="normal")
                    except Exception:
                        pass
            except Exception:
                try:
                    error_var.set("Validation error")
                except Exception:
                    pass

        # validate on keystrokes and when template/file is loaded
        editor.bind("<KeyRelease>", lambda e: schedule_validate())

        # run an initial validation pass now that schedule_validate is defined
        try:
            schedule_validate()
        except Exception:
            pass

        # Buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=2, column=0, columnspan=3, pady=(6, 0))

        def _insert_to_entry():
            txt = editor.get("1.0", "end").strip()
            # validate JSON
            # validate JSON + schema
            valid, errors = validate_policy_text(txt)
            if not valid:
                try:
                    error_var.set("\n".join(errors))
                except Exception:
                    pass
                try:
                    messagebox.showerror("Invalid policy", "\n".join(errors))
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
                # record attach preference on the page instance so callers
                # can inspect whether the user wanted the policy attached
                try:
                    self._policy_attached = bool(attach_var.get())
                except Exception:
                    self._policy_attached = False
                top.destroy()
            except Exception:
                try:
                    messagebox.showerror("Error", "Could not write temp file")
                except Exception:
                    pass

        def _save_as():
            path = filedialog.asksaveasfilename(
                parent=top,
                title="Save policy as...",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*")],
            )
            if not path:
                return
            try:
                txt = editor.get("1.0", "end").strip()
                valid, errors = validate_policy_text(txt)
                if not valid:
                    try:
                        error_var.set("\n".join(errors))
                    except Exception:
                        pass
                    try:
                        messagebox.showerror("Invalid policy", "\n".join(errors))
                    except Exception:
                        pass
                    return
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
            p = filedialog.askopenfilename(parent=top, title="Open policy (JSON)")
            if not p:
                return
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = f.read()
                editor.delete("1.0", "end")
                editor.insert("1.0", data)
                # re-validate newly loaded file
                try:
                    schedule_validate()
                except Exception:
                    pass
            except Exception:
                try:
                    messagebox.showerror("Error", "Could not read file", parent=top)
                except Exception:
                    pass

        insert_btn = ctk.CTkButton(btn_frame, text="Insert", command=_insert_to_entry)
        insert_btn.pack(side="left", padx=(0, 8))
        save_btn = ctk.CTkButton(btn_frame, text="Save As...", command=_save_as)
        save_btn.pack(side="left", padx=(0, 8))
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
                # include top-level version (schema requires it) and optional metadata
                "version": "1.0",
                "metadata": {"author": "", "version": "1.0"},
                "whitelist": {
                    "file_hashes": [],
                    "function_names": [],
                    "rule_ids": [],
                },
            }
        elif kind == "Rule Overrides":
            obj = {
                "version": "1.0",
                "rules": {
                    "YARA-0001": {"action": "allow", "reason": "vendor"},
                    "TS-weak-rand": {"action": "flag", "severity_override": "low"},
                },
                "defaults": {"action": "flag", "severity": "medium"},
            }
        elif kind == "Scoring":
            obj = {
                "version": "1.0",
                "scoring": {
                    "engine_weights": {"yara": 1.0, "treesitter": 0.8, "disasm": 0.6},
                    "confidence_thresholds": {"high": 0.9, "medium": 0.6, "low": 0.3},
                },
            }
        else:
            obj = {
                "version": "1.0",
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

    def _use_canonical(self):
        try:
            can = str(get_canonical_workdir())
        except Exception:
            return
        try:
            self.workdir_entry.delete(0, "end")
            self.workdir_entry.insert(0, can)
            try:
                set_default_workdir(can)
            except Exception:
                pass
            try:
                self._canonical_label.configure(text=f"Recommended: {can}")
            except Exception:
                pass
        except Exception:
            pass

    def _open_preferences_modal(self):
        """Open a Preferences modal allowing users to set common defaults.

        Fields: default workdir, fast-count timeout, max-preview-sample,
        max-file-size default (KB), follow-symlinks default, and simple
        detector defaults (yara/treesitter/disasm).
        """
        top = tk.Toplevel(self)
        top.title("Preferences")
        top.transient(self)
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

        # Max preview sample (how many files preview samples)
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
        ).grid(row=3, column=2, sticky="w", padx=(8, 0))

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

        # Detector defaults are configured on the Detectors page to avoid
        # duplicated UI. The Detectors page persists its own defaults so
        # the Preferences modal does not expose detector toggles.

        # Buttons
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
                # confirm thresholds for large-scan prompt
                tb = int(thr_bytes_entry.get().strip() or 0)
                set_setting("confirm_threshold_bytes", tb)
            except Exception:
                pass
            try:
                tf = int(thr_files_entry.get().strip() or 0)
                set_setting("confirm_threshold_files", tf)
            except Exception:
                pass
            # Detector defaults are managed on the Detectors page; do not
            # persist detector toggles from Preferences to avoid UI overlap.
            top.destroy()

        def _cancel():
            top.destroy()

        ctk.CTkButton(btns, text="Save", command=_save_prefs).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(btns, text="Cancel", command=_cancel).pack(side="left")
        top.wait_window()

    def _open_migration_dialog(self):
        """Open a migration dialog to move or copy a non-canonical workdir

        The dialog samples the selected source (workdir_entry) for a small
        estimate of file count and size then offers Move / Copy / Cancel.
        The actual operation runs in a background thread and logs progress
        into the results box. This is opt-in; no automatic moves happen.
        """
        src = self.workdir_entry.get().strip()
        if not src:
            messagebox.showinfo("Migrate workspace", "No workdir selected")
            return

        try:
            canonical = str(get_canonical_workdir())
        except Exception:
            canonical = None
        if not canonical:
            messagebox.showerror(
                "Migrate workspace", "Could not determine canonical workdir"
            )
            return

        top = tk.Toplevel(self)
        top.title("Migrate workspace to canonical location")
        top.transient(self)
        top.grab_set()

        frame = ctk.CTkFrame(top, fg_color="transparent")
        frame.pack(padx=12, pady=12, fill="both", expand=True)

        ctk.CTkLabel(frame, text=f"Source: {src}").pack(anchor="w")
        ctk.CTkLabel(frame, text=f"Destination parent: {canonical}").pack(
            anchor="w", pady=(4, 8)
        )

        # sample counts
        sample_lbl = ctk.CTkLabel(frame, text="Estimating...")
        sample_lbl.pack(anchor="w", pady=(4, 8))

        # choice buttons
        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.pack(pady=(8, 0))

        def _do_estimate():
            try:
                SAMPLE = int(get_setting("preview_sample_limit", 200))
            except Exception:
                SAMPLE = 200
            try:
                res = estimate_disk_usage(
                    [src],
                    sample_limit=SAMPLE,
                    follow_symlinks=bool(get_setting("follow_symlinks", False)),
                )
                seen = res.get("sampled_files", 0)
                total_size = res.get("sampled_bytes", 0)
                top_dirs = res.get("top_dirs", {})
                human = (
                    f"{total_size/1024:.1f} KB"
                    if total_size < 1024 * 1024
                    else f"{total_size/1024/1024:.1f} MB"
                )
                lines = [f"Sampled files: {seen}; approx size (sample): {human}"]
                if top_dirs:
                    lines.append("Top folders (sample):")
                    for name, sz in list(top_dirs.items())[:8]:
                        hs = (
                            f"{sz/1024:.1f} KB"
                            if sz < 1024 * 1024
                            else f"{sz/1024/1024:.1f} MB"
                        )
                        lines.append(f"  {name}: {hs}")
                sample_lbl.configure(text="\n".join(lines))
            except Exception as e:
                try:
                    sample_lbl.configure(text=f"Estimate error: {e}")
                except Exception:
                    pass

        _do_estimate()

        def _do_migrate(move: bool):
            # run migration in background
            def _worker():
                try:
                    self.after(
                        0,
                        self._append_result,
                        f"Migration started: {'move' if move else 'copy'} {src} -> {canonical}\n",
                    )
                    target_parent = Path(canonical)
                    target_parent.mkdir(parents=True, exist_ok=True)
                    dest = target_parent / Path(src).name
                    if dest.exists():
                        # avoid overwriting existing dest
                        self.after(
                            0,
                            self._append_result,
                            f"Destination exists: {dest} — aborting\n",
                        )
                        return
                    if move:
                        shutil.move(src, str(dest))
                        self.after(0, self._append_result, f"Moved {src} -> {dest}\n")
                    else:
                        # copytree may raise if dest exists; use copytree
                        shutil.copytree(src, str(dest))
                        self.after(0, self._append_result, f"Copied {src} -> {dest}\n")
                    # update UI to point to new canonical location
                    try:
                        self.workdir_entry.delete(0, "end")
                        self.workdir_entry.insert(0, str(dest))
                        set_default_workdir(str(dest))
                    except Exception:
                        pass
                except Exception as e:
                    self.after(0, self._append_result, f"Migration error: {e}\n")
                finally:
                    try:
                        self.after(
                            0, partial(self.migrate_btn.configure, state="normal")
                        )
                    except Exception:
                        pass

            try:
                # disable button while migrating
                self.migrate_btn.configure(state="disabled")
            except Exception:
                pass
            threading.Thread(target=_worker, daemon=True).start()
            top.destroy()

        ctk.CTkButton(
            btns, text="Move into canonical", command=lambda: _do_migrate(True)
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btns, text="Copy into canonical", command=lambda: _do_migrate(False)
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="Cancel", command=top.destroy).pack(side="left")
        top.wait_window()

    def _reset_to_canonical(self):
        # remove any saved user preference so the app falls back to the
        # canonical path returned by get_canonical_workdir()
        try:
            reset_default_workdir()
        except Exception:
            pass
        try:
            can = str(get_canonical_workdir())
            self.workdir_entry.delete(0, "end")
            self.workdir_entry.insert(0, can)
            try:
                self._canonical_label.configure(text=f"Recommended: {can}")
            except Exception:
                pass
        except Exception:
            pass

    def _set_status(self, text: str, error: bool = False):
        # reuse same status label area as progress_label
        try:
            self.progress_label.configure(text=text)
        except Exception:
            pass

    def _on_start_clicked(self):
        # Start background engagement flow immediately. Counting and
        # enumeration can be slow on large repositories; we'll show a
        # non-blocking spinner and update preview when enumeration finishes.
        self.results_box.delete("1.0", "end")
        self.results_box.insert("end", "Preview: scanning scope...\n")
        self._set_status("Starting engagement (background)...")
        # Prevent starting if a previous worker thread is still running.
        try:
            if getattr(self, "_worker_thread", None) and self._worker_thread.is_alive():
                try:
                    messagebox.showinfo(
                        "Engagement running",
                        "An engagement is already running. Please wait for it to finish or cancel it.",
                    )
                except Exception:
                    pass
                return
        except Exception:
            pass

        self._cancel_event = threading.Event()
        self._cancelled = False
        self.cancel_btn.configure(state="normal")
        self.start_btn.configure(state="disabled")
        # persist workdir selection on start as a user preference
        try:
            wd = self.workdir_entry.get().strip()
            if wd:
                try:
                    set_default_workdir(wd)
                except Exception:
                    pass
        except Exception:
            pass

        # Advanced preferences (filters, extraction, symlink behavior, etc.)
        # are managed in Preferences. Do not persist ephemeral UI fields here.
        # Before starting the main worker, perform a quick sample estimate of
        # the scope size and ask for confirmation if it's large. Skip estimate
        # for repo URLs (we'll clone later in the worker).
        try:
            scope_val = self.repo_entry.get().strip() or self.scope_entry.get().strip()
        except Exception:
            scope_val = ""

        def _is_git_url(s: str) -> bool:
            if not s:
                return False
            s = s.strip()
            if s.startswith("git@"):
                return True
            if s.startswith("http://") or s.startswith("https://"):
                return "github.com" in s or ".git" in s
            return False

        try:
            # Only estimate for local folder scopes
            if scope_val and not _is_git_url(scope_val):
                SAMPLE = int(get_setting("preview_sample_limit", 200))
                try:
                    res = estimate_disk_usage(
                        [scope_val],
                        sample_limit=SAMPLE,
                        follow_symlinks=bool(get_setting("follow_symlinks", False)),
                    )
                    sampled_bytes = int(res.get("sampled_bytes", 0) or 0)
                    sampled_files = int(res.get("sampled_files", 0) or 0)
                    # configurable thresholds (defaults: 5 GiB, 100k files)
                    try:
                        thr_bytes = int(
                            get_setting(
                                "confirm_threshold_bytes", 5 * 1024 * 1024 * 1024
                            )
                        )
                    except Exception:
                        thr_bytes = 5 * 1024 * 1024 * 1024
                    try:
                        thr_files = int(get_setting("confirm_threshold_files", 100000))
                    except Exception:
                        thr_files = 100000

                    if (sampled_bytes and sampled_bytes >= thr_bytes) or (
                        sampled_files and sampled_files >= thr_files
                    ):
                        # present human-friendly size
                        def _human(b: int) -> str:
                            if b >= 1024 * 1024 * 1024:
                                return f"{b/1024/1024/1024:.1f} GB"
                            if b >= 1024 * 1024:
                                return f"{b/1024/1024:.1f} MB"
                            return f"{b/1024:.1f} KB"

                        size_txt = _human(sampled_bytes) if sampled_bytes else "unknown"
                        msg = (
                            f"Estimated sample size: {size_txt}\nEstimated files sampled: {sampled_files}\n\n"
                            "This run may process a very large scope and take significant time or disk.\n"
                            "Do you want to continue?"
                        )
                        try:
                            cont = messagebox.askyesno("Confirm large scan", msg)
                        except Exception:
                            cont = True
                        if not cont:
                            try:
                                self.start_btn.configure(state="normal")
                                self.cancel_btn.configure(state="disabled")
                            except Exception:
                                pass
                            return
                except Exception:
                    # if estimate fails, continue without blocking
                    pass
        except Exception:
            pass

        t = threading.Thread(target=self._run_engagement_flow, daemon=True)
        t.start()
        # remember the worker thread so we can avoid concurrent runs
        try:
            self._worker_thread = t
        except Exception:
            pass
        # Ensure the transient cleaning label is hidden when starting a run
        try:
            self.after(0, self._show_cleaning_label, False)
        except Exception:
            pass

    def _on_preview_scope(self):
        """Run a lightweight non-hashing sample of the scope and show a summary.

        The preview samples up to SAMPLE_LIMIT files using os.scandir (no hashing)
        and reports total files found (sampled), top extensions and approximate
        total size. It runs in a background thread to avoid blocking the UI.
        """
        SAMPLE_LIMIT = 200

        def _worker():
            try:
                self.after(0, partial(self.preview_btn.configure, state="disabled"))
                scope = self.repo_entry.get().strip() or self.scope_entry.get().strip()
                if not scope:
                    self.after(0, self._append_result, "Preview: no scope specified\n")
                    return
                import os
                from collections import Counter, deque

                q = deque([scope])
                seen = 0
                total_size = 0
                ext_counts = Counter()
                file_preview = []

                while q and seen < SAMPLE_LIMIT:
                    cur = q.popleft()
                    try:
                        if os.path.isdir(cur):
                            with os.scandir(cur) as it:
                                for entry in it:
                                    if seen >= SAMPLE_LIMIT:
                                        break
                                    try:
                                        if entry.is_file(follow_symlinks=False):
                                            stat = entry.stat(follow_symlinks=False)
                                            seen += 1
                                            total_size += stat.st_size
                                            name = entry.name
                                            if "." in name:
                                                ext = name.rsplit(".", 1)[-1].lower()
                                            else:
                                                ext = "<noext>"
                                            ext_counts[ext] += 1
                                            if len(file_preview) < 10:
                                                file_preview.append(
                                                    (entry.path, stat.st_size)
                                                )
                                        elif entry.is_dir(follow_symlinks=False):
                                            q.append(entry.path)
                                    except Exception:
                                        continue
                        elif os.path.isfile(cur):
                            try:
                                stat = os.stat(cur)
                                seen += 1
                                total_size += stat.st_size
                                name = os.path.basename(cur)
                                if "." in name:
                                    ext = name.rsplit(".", 1)[-1].lower()
                                else:
                                    ext = "<noext>"
                                ext_counts[ext] += 1
                                if len(file_preview) < 10:
                                    file_preview.append((cur, stat.st_size))
                            except Exception:
                                pass
                    except Exception:
                        continue

                # prepare summary
                most_common = ext_counts.most_common(8)

                def human_size(s):
                    return (
                        f"{s/1024:.1f} KB"
                        if s < 1024 * 1024
                        else f"{s/1024/1024:.1f} MB"
                    )

                lines = [f"Preview results (sampled up to {SAMPLE_LIMIT} files):"]
                lines.append(f"Sampled files: {seen}")
                lines.append(f"Approx total size (sample): {human_size(total_size)}")
                if most_common:
                    lines.append("Top extensions (sample):")
                    for ext, cnt in most_common:
                        lines.append(f"  {ext}: {cnt}")
                if file_preview:
                    lines.append("Example files:")
                    for pth, sz in file_preview:
                        lines.append(f"  {pth} — {human_size(sz)}")

                self.after(0, self._append_result, "\n".join(lines) + "\n")
            except Exception as e:
                try:
                    self.after(0, self._append_result, f"Preview error: {e}\n")
                except Exception:
                    pass
            finally:
                try:
                    self.after(0, partial(self.preview_btn.configure, state="normal"))
                except Exception:
                    pass

        threading.Thread(target=_worker, daemon=True).start()

    def _run_engagement_flow(self):
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        client = self.client_entry.get().strip() or "SetupUI"
        # Support two separate scope inputs: a local folder and an optional
        # repo URL. If the repo field is provided we'll treat the scope as a
        # repository to clone; otherwise we use the local folder path.
        try:
            repo_val = self.repo_entry.get().strip()
        except Exception:
            repo_val = ""
        scope_local = self.scope_entry.get().strip() or str(Path.cwd())
        if repo_val:
            scope = repo_val
            _scope_is_repo = True
        else:
            scope = scope_local
            _scope_is_repo = False

        try:
            eng = Engagement(workdir=wd, case_id=case_id, client=client, scope=scope)
            eng.write_metadata()
            # import optional policy baseline (validate first, record audit event)
            try:
                policy = self.policy_entry.get().strip()
            except Exception:
                policy = ""
            if policy:
                try:
                    audit_path = Path(eng.workdir) / "auditlog.ndjson"
                    ok, info = import_and_record_policy(eng, policy, str(audit_path))
                    if not ok:
                        # record failure in the UI results box
                        try:
                            self.after(
                                0,
                                self._append_result,
                                f"policy import failed: {info}\n",
                            )
                        except Exception:
                            pass
                    else:
                        try:
                            self.after(
                                0, self._append_result, f"policy imported -> {info}\n"
                            )
                        except Exception:
                            pass
                except Exception:
                    pass
            case_dir = eng.workdir
            auditlog_path = str(case_dir / "auditlog.ndjson")
            al = AuditLog(auditlog_path)
            al.append(
                "engagement.created",
                {"case_id": case_id, "client": client, "scope": scope},
            )

            # If the user asked to treat the scope as a Git repo, attempt to
            # clone it into the case workspace and use the cloned folder as
            # the actual scope for scanning. We record audit events for
            # success/failure.
            try:
                # If the user provided a Repo URL we want to clone it. Also
                # keep the legacy checkbox behavior: if the checkbox is set and
                # the provided scope looks like a git URL, attempt a clone.
                if _scope_is_repo or (
                    getattr(self, "git_clone_var", None) and self.git_clone_var.get()
                ):

                    def _is_git_url(s: str) -> bool:
                        if not s:
                            return False
                        s = s.strip()
                        if s.startswith("git@"):
                            return True
                        if s.startswith("http://") or s.startswith("https://"):
                            return "github.com" in s or ".git" in s
                        return False

                    def _repo_name_from_url(s: str) -> str:
                        try:
                            if s.startswith("git@"):
                                s2 = s.split(":", 1)[-1]
                            else:
                                parsed = urllib.parse.urlparse(s)
                                s2 = parsed.path
                            name = s2.rstrip("/\n\r").split("/")[-1]
                            if name.endswith(".git"):
                                name = name[:-4]
                            return name or "repo"
                        except Exception:
                            return "repo"

                    if _is_git_url(scope):
                        repo_name = _repo_name_from_url(scope)
                        dest_parent = Path(eng.workdir) / "cloned_repos"
                        try:
                            dest_parent.mkdir(parents=True, exist_ok=True)
                        except Exception:
                            pass
                        dest = dest_parent / repo_name
                        try:
                            if dest.exists() and (dest / ".git").exists():
                                # try to update existing clone
                                subprocess.run(
                                    [
                                        "git",
                                        "-C",
                                        str(dest),
                                        "pull",
                                    ],
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                    timeout=300,
                                )
                                al.append(
                                    "engagement.clone_repo",
                                    {
                                        "repo": scope,
                                        "dest": str(dest),
                                        "status": "updated",
                                    },
                                )
                                self.after(
                                    0,
                                    self._append_result,
                                    f"Updated existing clone -> {dest}\n",
                                )
                            else:
                                # clone anew
                                subprocess.run(
                                    [
                                        "git",
                                        "clone",
                                        scope,
                                        str(dest),
                                    ],
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                    timeout=600,
                                )
                                al.append(
                                    "engagement.clone_repo",
                                    {
                                        "repo": scope,
                                        "dest": str(dest),
                                        "status": "cloned",
                                    },
                                )
                                self.after(
                                    0, self._append_result, f"Cloned repo -> {dest}\n"
                                )
                            # use cloned path as the scope
                            scope = str(dest)
                        except subprocess.CalledProcessError as e:
                            err = e.stderr or str(e)
                            al.append(
                                "engagement.clone_failed", {"repo": scope, "error": err}
                            )
                            self.after(0, self._append_result, f"Clone failed: {err}\n")
                            try:
                                self.after(
                                    0, self._set_status, "Clone failed — aborting"
                                )
                            except Exception:
                                pass
                            return
                        except Exception as e:
                            al.append(
                                "engagement.clone_failed",
                                {"repo": scope, "error": str(e)},
                            )
                            self.after(0, self._append_result, f"Clone failed: {e}\n")
                            try:
                                self.after(
                                    0, self._set_status, "Clone failed — aborting"
                                )
                            except Exception:
                                pass
                            return
            except Exception:
                pass

            # Attempt a fast pre-count with a short timeout so we can show
            # determinate progress for large repos. If the fast count returns
            # None we fall back to scanning immediately and use a dynamic
            # estimation (items/sec) as files are processed.
            total_count = None
            try:
                fast_timeout = get_fast_count_timeout()
            except Exception:
                fast_timeout = 0.8
            # read advanced filter/preproc preferences from stored settings
            try:
                inc_txt = get_setting("include_globs", "") or ""
            except Exception:
                inc_txt = ""
            try:
                exc_txt = get_setting("exclude_globs", "") or ""
            except Exception:
                exc_txt = ""
            try:
                msz_kb = int(get_setting("max_file_size_kb", 0) or 0)
            except Exception:
                msz_kb = 0
            try:
                follow_links = bool(get_setting("follow_symlinks", False))
            except Exception:
                follow_links = False

            include_globs = (
                [g.strip() for g in inc_txt.split(",") if g.strip()]
                if inc_txt
                else None
            )
            exclude_globs = (
                [g.strip() for g in exc_txt.split(",") if g.strip()]
                if exc_txt
                else None
            )
            max_bytes = (msz_kb * 1024) if (msz_kb and msz_kb > 0) else None

            try:
                total_count = count_inputs_fast(
                    [scope],
                    timeout=fast_timeout,
                    include_globs=include_globs,
                    exclude_globs=exclude_globs,
                    max_file_size_bytes=max_bytes,
                    follow_symlinks=follow_links,
                )
            except Exception:
                total_count = None
            try:
                if total_count and total_count > 0:
                    # start scanning in determinate mode with known total
                    self.after(
                        0, self._append_result, f"Found {total_count} files to scan\n"
                    )
                    self.after(0, self._begin_stage, "Scanning scope", True)
                    # initialize label and tracking
                    self.after(
                        0,
                        self.progress_label.configure,
                        {"text": f"Scanning 0/{total_count}"},
                    )
                    self._scan_total = total_count
                    self._scan_start_time = None
                else:
                    # fall back to indeterminate spinner and dynamic est
                    self.after(
                        0,
                        lambda: self._begin_stage("Scanning scope", determinate=False),
                    )
                    self._scan_total = None
                    self._scan_start_time = None
            except Exception:
                pass

            def enum_progress(processed, path, total):
                # unified, simple progress updater for scanning
                if (
                    getattr(self, "_cancel_event", None) is not None
                    and self._cancel_event.is_set()
                ) or getattr(self, "_cancelled", False):
                    self.after(0, self._set_status, "Cancelling...")
                    self.after(0, self._stop_spinner)
                    self.after(0, self.progress.set, 0.0)
                    self.after(0, self._append_result, "scanning: cancelled by user\n")
                    return

                # prefer pre-count if available
                use_total = getattr(self, "_scan_total", None) or (
                    total if total and total > 0 else None
                )
                self.after(
                    0, self._update_progress, "Scanning", processed, use_total, path
                )

            def preproc_progress(processed, total):
                if (
                    getattr(self, "_cancel_event", None) is not None
                    and self._cancel_event.is_set()
                ) or getattr(self, "_cancelled", False):
                    self.after(0, self._set_status, "Cancelling...")
                    self.after(0, self._stop_spinner)
                    self.after(0, self.progress.set, 0.0)
                    self.after(0, self._append_result, "preproc: cancelled by user\n")
                    return
                self.after(
                    0,
                    self._update_progress,
                    "Preprocessing",
                    processed,
                    (total if total and total > 0 else None),
                    None,
                )

            try:
                max_depth = int(get_setting("max_extract_depth", 2))
            except Exception:
                max_depth = 2
            do_extract = bool(get_setting("do_extract", True))

            # Persist the run-specific preprocessing settings into the case
            # as a separate JSON file so runs are reproducible. This includes
            # include/exclude globs, max file size, and extraction prefs.
            try:
                run_settings = {
                    "include_globs": include_globs,
                    "exclude_globs": exclude_globs,
                    "max_file_size_bytes": max_bytes,
                    "do_extract": do_extract,
                    "max_extract_depth": max_depth,
                    "follow_symlinks": follow_links,
                }
                rs_path = Path(eng.workdir) / "run_settings.json"
                tmp = rs_path.with_suffix(rs_path.suffix + ".tmp")
                tmp.write_text(
                    json.dumps(
                        run_settings, sort_keys=True, ensure_ascii=False, indent=2
                    ),
                    encoding="utf-8",
                )
                tmp.replace(rs_path)
            except Exception:
                pass

            # Enumerate inputs and write manifest into the case workspace (same as Auditor)
            # Provide a progress callback so UI can show scanning progress.
            try:
                items = enumerate_inputs(
                    [scope],
                    progress_cb=enum_progress,
                    cancel_event=self._cancel_event,
                    include_globs=include_globs,
                    exclude_globs=exclude_globs,
                    max_file_size_bytes=max_bytes,
                    follow_symlinks=follow_links,
                )
            finally:
                # mark the scanning stage ended (this will show 100% briefly
                # then reset the bar so the next stage is visually distinct)
                try:
                    self.after(0, self._end_stage, "Scanning scope")
                except Exception:
                    pass
            # write canonical NDJSON manifest (tests and other code expect .ndjson)
            manifest_path = str(case_dir / "inputs.manifest.ndjson")
            # Write the manifest with a determinate "Writing manifest" stage.
            try:
                # prefer an incremental writer to allow determinate progress
                try:
                    self.after(0, self._begin_stage, "Writing manifest", True)
                except Exception:
                    pass

                def _write_with_progress():
                    try:
                        self._write_manifest_with_progress(manifest_path, items)
                    except Exception:
                        try:
                            # fallback to the library writer if streaming fails
                            write_manifest(manifest_path, items)
                        except Exception:
                            pass
                    finally:
                        try:
                            self.after(0, self._end_stage, "Writing manifest")
                        except Exception:
                            pass

                # perform manifest write in the background so UI can update
                wthr = threading.Thread(target=_write_with_progress, daemon=True)
                wthr.start()
                # wait for writer thread to finish before continuing (it is quick)
                wthr.join()
            except Exception:
                pass

            try:
                # begin preprocessing stage
                try:
                    self.after(0, self._begin_stage, "Preprocessing", False)
                except Exception:
                    pass
                # Perform fundamental preprocessing only. Detector-specific
                # artifact generation (AST/disasm) is deferred until detectors
                # are run so Setup stays fast and focused on manifesting/indexing.
                preproc_result = preprocess_items(
                    items,
                    str(case_dir),
                    progress_cb=preproc_progress,
                    cancel_event=self._cancel_event,
                    max_extract_depth=max_depth,
                    do_extract=do_extract,
                    build_ast=False,
                    build_disasm=False,
                )
            except Exception as e:
                preproc_result = {"stats": {}}
                al.append("preproc.failed", {"error": str(e)})

            stats = preproc_result.get("stats", {})
            al.append("preproc.completed", {"index_lines": stats.get("index_lines")})
            try:
                self.after(0, self._end_stage, "Preprocessing")
            except Exception:
                pass
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
                # hide transient cleaning indicator when worker fully cleaned up
                try:
                    self.after(0, self._show_cleaning_label, False)
                except Exception:
                    pass
                # clear worker thread reference
                try:
                    self._worker_thread = None
                except Exception:
                    pass
            except Exception:
                pass

    def _on_cancel_clicked(self):
        if self._cancel_event is not None:
            try:
                # signal background workers to stop
                self._cancel_event.set()
                # stop any visual spinner and reset the bar so the UI doesn't
                # keep animating after cancellation
                try:
                    self._stop_spinner()
                except Exception:
                    pass
                try:
                    self.after(0, self.progress.set, 0.0)
                except Exception:
                    pass
                self._set_status("Cancellation requested")
                # also log into the results box so there's a persistent record
                try:
                    self.results_box.insert("end", ">>> Cancellation requested\n")
                    self.results_box.see("end")
                except Exception:
                    pass
                # Don't re-enable Start here; wait for the worker thread to
                # finish. _run_engagement_flow's finally block will re-enable
                # the Start button when cleanup completes.
                try:
                    self.cancel_btn.configure(state="disabled")
                except Exception:
                    pass
                # show cleaning indicator if the worker thread is still shutting down
                try:
                    if (
                        getattr(self, "_worker_thread", None)
                        and self._worker_thread.is_alive()
                    ):
                        try:
                            self.after(0, self._show_cleaning_label, True)
                        except Exception:
                            pass
                except Exception:
                    pass
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

    def _write_manifest_with_progress(self, manifest_path: str, items: list):
        """Write manifest incrementally so the UI can show determinate progress.

        This writes a regular JSON file compatible with existing consumers by
        streaming the items array and updating the progress bar based on the
        number of items written.
        """
        try:
            total = len(items)
            # ensure determinate stage is active
            try:
                self.after(0, self.progress.set, 0.0)
            except Exception:
                pass
            with open(manifest_path, "w", encoding="utf-8") as f:
                # write header
                gen = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                f.write('{"generated_at": "')
                f.write(gen)
                f.write('", "items": [\n')
                for i, itm in enumerate(items, start=1):
                    try:
                        json.dump(itm, f, ensure_ascii=False)
                        if i < total:
                            f.write(",\n")
                        else:
                            f.write("\n")
                    except Exception:
                        # skip problematic items
                        continue
                    # update progress
                    try:
                        frac = min(1.0, float(i) / float(total)) if total > 0 else 1.0
                        self.after(0, self.progress.set, frac)
                        # update label using unified updater for nice formatting
                        try:
                            self.after(
                                0,
                                self._update_progress,
                                "Writing manifest",
                                i,
                                total,
                                None,
                            )
                        except Exception:
                            pass
                    except Exception:
                        pass
                f.write("]}\n")
        except Exception:
            # bubble up to caller who may call fallback writer
            raise
