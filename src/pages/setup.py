from __future__ import annotations

import json
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
from auditor.intake import count_inputs_fast, enumerate_inputs, write_manifest
from auditor.preproc import preprocess_items
from auditor.workspace import Workspace
from policy_import import import_and_record_policy
from policy_validator import validate_policy_text
from settings import (
    get_canonical_workdir,
    get_default_workdir,
    get_fast_count_timeout,
    reset_default_workdir,
    set_default_workdir,
    set_fast_count_timeout,
)

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
        # Option: treat the scope as a Git repo URL and clone it locally
        self.git_clone_var = tk.BooleanVar(value=False)
        try:
            ctk.CTkCheckBox(
                form,
                text="Clone repo (if URL)",
                variable=self.git_clone_var,
            ).grid(row=2, column=3, padx=(8, 0))
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

        # Preproc options
        ctk.CTkLabel(form, text="Preproc Options:").grid(row=4, column=0, sticky="w")
        opts = ctk.CTkFrame(form, fg_color="transparent")
        opts.grid(row=4, column=1, sticky="we", padx=(6, 0))
        self.extract_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(opts, text="Extract archives", variable=self.extract_var).grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkLabel(opts, text="Max depth:").grid(row=0, column=1)
        self.max_depth_entry = ctk.CTkEntry(opts, width=60)
        self.max_depth_entry.insert(0, "2")
        self.max_depth_entry.grid(row=0, column=2, padx=(4, 0))
        # Fast-count timeout (seconds): small numeric input persisted via settings
        try:
            fast_default = str(get_fast_count_timeout())
        except Exception:
            fast_default = "0.8"
        ctk.CTkLabel(opts, text="Fast-count timeout (s):").grid(
            row=0, column=3, padx=(8, 0)
        )
        self.fastcount_entry = ctk.CTkEntry(opts, width=80)
        self.fastcount_entry.insert(0, fast_default)
        self.fastcount_entry.grid(row=0, column=4, padx=(4, 0))

        self.ast_var = tk.BooleanVar(value=False)
        self.disasm_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts, text="Generate AST cache", variable=self.ast_var).grid(
            row=1, column=0, sticky="w", pady=(6, 0)
        )
        ctk.CTkCheckBox(
            opts, text="Generate disasm cache", variable=self.disasm_var
        ).grid(row=1, column=1, sticky="w", pady=(6, 0))

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

        # Progress
        self.progress_label = ctk.CTkLabel(content, text="")
        self.progress_label.pack(pady=(6, 2))
        self.progress = ctk.CTkProgressBar(content, width=480)
        self.progress.pack(pady=(2, 12))
        self.progress.set(0.0)

        self.results_box = tk.Text(content, height=10, wrap="none")
        self.results_box.pack(fill="both", padx=12, pady=(6, 12), expand=False)

        # internal state
        self._cancel_event = None
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

        # Template selector
        frame = ctk.CTkFrame(top, fg_color="transparent")
        frame.pack(padx=12, pady=12, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Template:").grid(row=0, column=0, sticky="w")
        templates = ["Whitelist", "Rule Overrides", "Scoring", "Combined"]
        tmpl_var = tk.StringVar(value=templates[0])
        tmpl_menu = ctk.CTkOptionMenu(frame, values=templates, variable=tmpl_var)
        tmpl_menu.grid(row=0, column=1, sticky="we", padx=(8, 0))

        # Editor (multi-line)
        editor = tk.Text(frame, width=80, height=20, wrap="none")
        editor.grid(row=1, column=0, columnspan=3, pady=(8, 8))

        def _render_template(*_):
            kind = tmpl_var.get()
            editor.delete("1.0", "end")
            editor.insert("1.0", self._policy_template_json(kind))

        tmpl_var.trace_add("write", _render_template)
        # populate initial
        _render_template()

        # Inline validation area (debounced): shows parse/schema errors and
        # disables Insert/Save while errors exist.
        error_var = tk.StringVar(value="")
        error_label = ctk.CTkLabel(frame, textvariable=error_var, text_color="#d9534f")
        error_label.grid(row=3, column=0, columnspan=3, sticky="we", pady=(0, 6))

        # attach simple debounce state to the modal window object
        top.policy_validate_timer = None
        top.last_policy_text = None

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

        # persist fast-count timeout preference
        try:
            ftxt = self.fastcount_entry.get().strip()
            try:
                fval = float(ftxt)
                set_fast_count_timeout(fval)
            except Exception:
                # ignore invalid entry and keep previous value
                pass
        except Exception:
            pass
        t = threading.Thread(target=self._run_engagement_flow, daemon=True)
        t.start()

    def _run_engagement_flow(self):
        wd = self.workdir_entry.get().strip() or str(Path.cwd() / "case_demo")
        case_id = self.case_entry.get().strip() or "CASE-000"
        client = self.client_entry.get().strip() or "SetupUI"
        scope = self.scope_entry.get().strip() or str(Path.cwd())

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
                if getattr(self, "git_clone_var", None) and self.git_clone_var.get():

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
            try:
                total_count = count_inputs_fast([scope], timeout=fast_timeout)
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
                max_depth = int(self.max_depth_entry.get().strip())
            except Exception:
                max_depth = 2
            do_extract = bool(self.extract_var.get())

            # Enumerate inputs and write manifest into the case workspace (same as Auditor)
            # Provide a progress callback so UI can show scanning progress.
            try:
                items = enumerate_inputs(
                    [scope], progress_cb=enum_progress, cancel_event=self._cancel_event
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
                preproc_result = preprocess_items(
                    items,
                    str(case_dir),
                    progress_cb=preproc_progress,
                    cancel_event=self._cancel_event,
                    max_extract_depth=max_depth,
                    do_extract=do_extract,
                    build_ast=bool(self.ast_var.get()),
                    build_disasm=bool(self.disasm_var.get()),
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
                self.cancel_btn.configure(state="disabled")
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
