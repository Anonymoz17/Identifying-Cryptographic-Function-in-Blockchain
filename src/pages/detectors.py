"""Detectors page: static analysis mode.

This page runs the complete static detection pipeline
including Ghidra exports, heuristics, and findings generation.
"""

from __future__ import annotations

import json
import os
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from typing import Optional, Dict, Any, Callable

# Account bubble widget
from ui.account_bubble import AccountBubble

import customtkinter as ctk

# Theme
from ui.theme import (
    BG, CARD_BG, BORDER, TEXT, MUTED,
    PRIMARY, PRIMARY_H, OUTLINE_BR, OUTLINE_H,
    TITLE_FONT, HEADING_FONT, BODY_FONT, MONO_FONT,
    PLATE_BG, PLATE_BORDER,
)

UPGRADE_URL = "https://anonymoz17.github.io/Identifying-Cryptographic-Function-in-Blockchain/"


class DetectorsPage(ctk.CTkFrame):
    """Detectors page for static analysis."""

    def __init__(self, master, switch_page_callback):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # State
        self._standalone_mode = False
        self._loaded_case_workdir: Optional[str] = None
        self._available_hashes: Dict[str, str] = {}

        # Premium gate overlay (shown when free-tier limit reached)
        self._premium_overlay: Optional[ctk.CTkFrame] = None
        self._premium_message_label: Optional[ctk.CTkLabel] = None


        # ===== Main content container =====
        content = ctk.CTkFrame(self, fg_color=BG)
        content.grid(row=0, column=0, sticky="nsew", padx=22, pady=18)
        content.grid_columnconfigure(0, weight=1)

        # ===== Header =====
        header_frame = ctk.CTkFrame(content, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))

        header = ctk.CTkLabel(
            header_frame,
            text="Cryptographic Detection Analysis",
            font=TITLE_FONT,
            text_color=TEXT,
        )
        header.pack(side="left")

        # Account bubble (top-right, same pattern as SetupPage)
        self._acct = AccountBubble(self)
        self._acct.mount(top_right_of=self)


        # ===== Load Case (Standalone) =====
        self.load_case_frame = ctk.CTkFrame(
            content,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        self._build_load_case_ui(self.load_case_frame)
        self.load_case_frame.pack_forget()

        # ===== Mode Toggle =====
        self.mode_frame = ctk.CTkFrame(
            content,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )

        mode_label = ctk.CTkLabel(
            self.mode_frame,
            text="Analysis Mode",
            font=HEADING_FONT,
            text_color=TEXT,
        )
        mode_label.pack(side="left", padx=(14, 12), pady=10)

        self.mode_var = tk.StringVar(value="static")
        self.mode_toggle = ctk.CTkSegmentedButton(
            self.mode_frame,
            values=["Static Analysis"],
            command=self._on_mode_change,
            variable=self.mode_var,
            font=BODY_FONT,
            width=360,
            height=36,
        )
        self.mode_toggle.set("Static Analysis")
        self.mode_toggle.pack(side="left", padx=(6, 12), pady=10)

        self.mode_description = ctk.CTkLabel(
            self.mode_frame,
            text="Analyzes binaries for crypto patterns using Ghidra",
            font=BODY_FONT,
            text_color=MUTED,
        )
        self.mode_description.pack(side="left", padx=(6, 12))

        # ===== Static Analysis Section =====
        self.static_frame = ctk.CTkFrame(
            content,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        self._build_static_ui(self.static_frame)

        # Hidden by default

        # ===== Status Bar =====
        status_frame = ctk.CTkFrame(
            content,
            corner_radius=8,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
            height=36,
        )
        status_frame.pack(fill="x", pady=(12, 0))
        self.status_label = ctk.CTkLabel(
            status_frame, text="Ready to analyze", font=("Segoe UI", 11), text_color=MUTED
        )
        self.status_label.pack(side="left", padx=12, pady=6)

        # Internal state for analysis
        self._analysis_running = False
        self._cancel_event: Optional[threading.Event] = None
        self._current_mode = "static"
        self._case_workdir: Optional[str] = None

        # Batch state
        self._all_file_hashes = []
        self._batch_results = {}
        self._current_batch_index = 0
        self._total_binaries = 0
        self._cached_binaries = 0
        self._ready_binaries = 0

        # Back to Landing (sticks to the bottom via the status_frame)
        back_btn = ctk.CTkButton(
            status_frame,
            text="← Back to Landing",
            width=160,
            height=32,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: self.switch_page("landing"),
        )
        back_btn.pack(side="right", padx=8, pady=6)

    # ---------- Static Analysis UI ----------
    def _build_static_ui(self, parent: ctk.CTkFrame):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        # Config / summary card
        config_frame = ctk.CTkFrame(
            parent,
            fg_color="transparent",
        )
        config_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=14)
        config_frame.grid_columnconfigure(1, weight=1)

        # Case summary container
        self.summary_container = ctk.CTkFrame(config_frame, fg_color="transparent")
        self.summary_container.grid(
            row=0, column=0, columnspan=3, sticky="ew", padx=8, pady=(6, 12)
        )
        self.summary_container.grid_columnconfigure(0, weight=1)

        summary_title = ctk.CTkLabel(
            self.summary_container,
            text="Case Summary",
            font=HEADING_FONT,
            text_color=TEXT,
        )
        summary_title.pack(anchor="w")

        self.case_summary_label = ctk.CTkLabel(
            self.summary_container,
            text="Scanning for preprocessed binaries...",
            font=BODY_FONT,
            text_color=MUTED,
            justify="left",
        )
        self.case_summary_label.pack(anchor="w", pady=(4, 0))

        # Divider
        divider = ctk.CTkFrame(config_frame, height=1, fg_color=BORDER)
        divider.grid(row=1, column=0, columnspan=3, sticky="ew", padx=8, pady=8)

        # Options row
        options_row = ctk.CTkFrame(config_frame, fg_color="transparent")
        options_row.grid(row=2, column=0, columnspan=3, sticky="w", padx=8, pady=(2, 8))

        # Hidden profile variable (default to "full" for comprehensive analysis)
        self.profile_var = tk.StringVar(value="full")
        
        # Force re-analysis option
        self.force_var = tk.BooleanVar(value=False)
        force_check = ctk.CTkCheckBox(
            options_row,
            text="Force re-analysis (ignore cache)",
            variable=self.force_var,
            font=BODY_FONT,
            text_color=TEXT,
        )
        force_check.pack(side="left", padx=(0, 18))

        # Actions row
        action_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        action_frame.grid(row=3, column=0, sticky="ew", padx=8, pady=(6, 4))

        self.run_static_btn = ctk.CTkButton(
            action_frame,
            text="Analyze All Binaries",
            command=self._run_static_analysis,
            width=220,
            height=40,
            font=("Segoe UI", 14, "bold"),
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
        )
        self.run_static_btn.pack(side="left", padx=(0, 10))

        self.cancel_static_btn = ctk.CTkButton(
            action_frame,
            text="Cancel",
            command=self._cancel_analysis,
            width=120,
            height=40,
            state="disabled",
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
        )
        self.cancel_static_btn.pack(side="left", padx=10)

        self.open_results_btn = ctk.CTkButton(
            action_frame,
            text="📁 Open Results",
            command=self._open_results_folder,
            width=160,
            height=40,
            state="disabled",
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
        )
        self.open_results_btn.pack(side="left", padx=10)

        # View Results in App button (new - navigates to Results page)
        self.view_results_btn = ctk.CTkButton(
            action_frame,
            text="→ View Results",
            command=self._view_results_in_app,
            width=160,
            height=40,
            state="disabled",
            fg_color="#0066CC",
            hover_color="#0052A3"
        )
        self.view_results_btn.pack(side="left", padx=10)

        # Progress section
        progress_plate = ctk.CTkFrame(
            action_frame,
            fg_color=PLATE_BG,
            corner_radius=10,
            border_width=1,
            border_color=PLATE_BORDER,
        )
        progress_plate.pack(side="left", fill="x", expand=True, padx=18)

        self.progress_bar = ctk.CTkProgressBar(
            progress_plate, width=320, progress_color=PRIMARY, fg_color=BORDER
        )
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=(10, 10), pady=10)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            progress_plate,
            text="",
            font=("Segoe UI", 11),
            text_color=MUTED,
        )
        self.progress_label.pack(side="left", padx=(0, 10))

        # Results area
        results_frame = ctk.CTkFrame(
            parent,
            corner_radius=10,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        results_frame.grid(row=2, column=0, sticky="nsew", padx=14, pady=(4, 12))
        results_frame.grid_rowconfigure(1, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        results_header = ctk.CTkLabel(
            results_frame,
            text="Analysis Results",
            font=HEADING_FONT,
            text_color=TEXT,
        )
        results_header.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 8))

        self.results_notebook = ctk.CTkTabview(results_frame)
        self.results_notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Summary tab
        self.results_notebook.add("Summary")
        summary_text = ctk.CTkTextbox(
            self.results_notebook.tab("Summary"),
            wrap="word",
            font=MONO_FONT,
            text_color=TEXT,
        )
        summary_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.summary_text = summary_text

        # Findings tab
        self.results_notebook.add("Findings")
        findings_text = ctk.CTkTextbox(
            self.results_notebook.tab("Findings"),
            wrap="word",
            font=(MONO_FONT[0], 11),
            text_color=TEXT,
        )
        findings_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.findings_text = findings_text

        # Console tab
        self.results_notebook.add("Console")
        console_text = ctk.CTkTextbox(
            self.results_notebook.tab("Console"),
            wrap="word",
            font=(MONO_FONT[0], 10),
            text_color=TEXT,
        )
        console_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.console_text = console_text

    def _build_load_case_ui(self, parent: ctk.CTkFrame):
        parent.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            parent, text="Load Existing Case", font=HEADING_FONT, text_color=TEXT
        )
        title_label.grid(row=0, column=0, sticky="w", padx=14, pady=(14, 4))

        description = ctk.CTkLabel(
            parent,
            text="No active case detected. Load a preprocessed case to run static analysis.",
            font=BODY_FONT,
            text_color=MUTED,
        )
        description.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 12))

        selection_frame = ctk.CTkFrame(
            parent,
            fg_color="transparent",
        )
        selection_frame.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 10))
        selection_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(selection_frame, text="Workdir:", font=BODY_FONT, text_color=TEXT)\
            .grid(row=0, column=0, sticky="w", pady=6)

        workdir_row = ctk.CTkFrame(selection_frame, fg_color="transparent")
        workdir_row.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        workdir_row.grid_columnconfigure(0, weight=1)

        self.case_workdir_entry = ctk.CTkEntry(
            workdir_row, placeholder_text="Enter case workdir path or browse..."
        )
        self.case_workdir_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        browse_btn = ctk.CTkButton(
            workdir_row,
            text="Browse",
            width=100,
            command=self._browse_case_workdir,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
        )
        browse_btn.grid(row=0, column=1)

        ctk.CTkLabel(
            selection_frame, text="Available Cases:", font=BODY_FONT, text_color=TEXT
        ).grid(row=1, column=0, sticky="nw", pady=(12, 6))

        cases_frame = ctk.CTkFrame(
            selection_frame,
            corner_radius=10,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        cases_frame.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(12, 6))
        cases_frame.grid_columnconfigure(0, weight=1)

        self.cases_listbox = ctk.CTkTextbox(
            cases_frame, height=120, font=(MONO_FONT[0], 11), text_color=TEXT
        )
        self.cases_listbox.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
        self.cases_listbox.configure(state="disabled")

        refresh_btn = ctk.CTkButton(
            cases_frame,
            text="Refresh Cases",
            width=150,
            command=self._refresh_case_list,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
        )
        refresh_btn.grid(row=1, column=0, pady=(4, 10))

        # Actions
        action_frame = ctk.CTkFrame(parent, fg_color="transparent")
        action_frame.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 12))

        self.load_case_btn = ctk.CTkButton(
            action_frame,
            text="Load Case",
            width=150,
            height=40,
            font=("Segoe UI", 14, "bold"),
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=self._load_selected_case,
        )
        self.load_case_btn.pack(side="left", padx=6)

        self.load_case_status = ctk.CTkLabel(
            action_frame, text="", font=("Segoe UI", 11), text_color=MUTED
        )
        self.load_case_status.pack(side="left", padx=12)

    def _on_mode_change(self, selected_label: str):
        """Handle mode selection (static-only)."""
        self.static_frame.pack(fill="both", expand=True, pady=(0, 10))
        self.mode_description.configure(
            text="Analyzes binaries for crypto patterns using Ghidra",
            text_color="#88b"
        )

        # Hide case summary in standalone mode if no case is loaded
        if self._standalone_mode and not self._loaded_case_workdir:
            self.summary_container.grid_remove()
        else:
            # Show it if coming from setup page
            self.summary_container.grid()

    def _run_static_analysis(self):
        if self._analysis_running:
            return

        # --- Access control: free vs premium scan quota ---
        app = self.master  # App is the parent window/root

        if hasattr(app, "can_run_scan"):
            allowed, message = app.can_run_scan()

            if not allowed:
                # Hard block: no more scans for this plan
                self._set_status("Scan limit reached for your plan.", error=True)
                if message:
                    self._log_console(message)
                # Show full-page premium gate overlay with quota-aware message
                self._show_premium_gate(message or "Free plan limit reached.")
                return

            # Allowed but show remaining scans, if any
            if message:
                self._log_console(message)

        try:
            if self._loaded_case_workdir:
                self._case_workdir = self._loaded_case_workdir
            else:
                scan_meta = getattr(self.master, "current_scan_meta", None)
                if not scan_meta or not scan_meta.get("workdir"):
                    self._set_status("No case loaded. Load a case or run Setup first.", error=True)
                    return
                self._case_workdir = scan_meta.get("workdir")
        except Exception as e:
            self._set_status(f"Error: {e}", error=True)
            return

        self._analysis_running = True

        self.run_static_btn.configure(state="disabled")
        self.cancel_static_btn.configure(state="normal")
        self.open_results_btn.configure(state="disabled")
        self.view_results_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self._clear_results()
        self._log_console("Starting static analysis…")
        self._set_status("Running static analysis…")

        self._cancel_event = threading.Event()
        t = threading.Thread(target=self._batch_analysis_thread, daemon=True)
        t.start()

    def _batch_analysis_thread(self):
        """Background thread for batch static analysis of all binaries."""
        import time
        import logging
        import sys
        from pathlib import Path

        try:
            from auditor.detectors.static_detection.runner import StaticRunner
            from auditor.detectors.static_detection.context import RunContext, ToolVersions

            self._batch_results = {}
            self._current_batch_index = 0

            profile = self.profile_var.get()
            force = self.force_var.get()
            total_files = len(self._all_file_hashes)

            self.after(0, self._log_console, f"Starting batch analysis of {total_files} binaries...")
            self.after(0, self._log_console, f"Profile: {profile} • Force: {force}")

            runner = StaticRunner()

            # Validate file availability before batch analysis
            try:
                import os
                from pathlib import Path

                preproc_base = Path(self._case_workdir) / "preproc"
                if not preproc_base.exists():
                    self.after(0, self._log_console, "✗ ERROR: preproc/ directory not found. Aborting batch analysis.")
                    self.after(0, self._on_batch_error, "File validation failed: preproc/ directory missing")
                    return

                # Validate that each file hash has a corresponding preproc directory
                missing_files = []
                for file_hash in self._all_file_hashes:
                    file_preproc = preproc_base / file_hash / "input.bin"
                    if not file_preproc.exists():
                        missing_files.append(file_hash)

                if missing_files:
                    self.after(0, self._log_console, f"✗ ERROR: {len(missing_files)} file(s) missing in preproc/")
                    self.after(0, self._on_batch_error, f"File validation failed: {len(missing_files)} file(s) missing")
                    return
                else:
                    self.after(0, self._log_console, f"✓ File validation passed: {len(self._all_file_hashes)} file(s) ready")

            except Exception as val_err:
                self.after(0, self._log_console, f"✗ ERROR: File validation error: {val_err}")
                self.after(0, self._on_batch_error, f"File validation error: {val_err}")
                return

            # Progress update throttling: update UI every N files instead of every file
            # This prevents excessive UI thread calls that can cause freezing
            UI_UPDATE_FREQUENCY = 10  # Update UI every 10 files
            last_ui_update = 0

            for index, file_hash in enumerate(self._all_file_hashes, 1):
                file_start_time = time.time()

                # Check for cancellation
                if self._cancel_event and self._cancel_event.is_set():
                    self.after(0, self._on_batch_cancelled, index - 1, total_files)
                    return

                self._current_batch_index = index
                progress = (index - 0.5) / max(1, total_files)
                self.after(0, self.progress_bar.set, progress)
                self.after(0, self._update_batch_progress, index, total_files, file_hash)

                # Throttle UI updates: only update every N files
                # This dramatically reduces UI thread work and prevents freezing
                should_update_ui = (index % UI_UPDATE_FREQUENCY == 0) or (index == total_files)

                if should_update_ui:
                    progress = (index - 0.5) / total_files
                    self.after(0, self.progress_bar.set, progress)
                    self.after(0, self._update_batch_progress, index, total_files, file_hash)

                try:
                    # Build context for this specific file
                    ctx = RunContext(
                        file_hash=file_hash,
                        preproc_dir=self._case_workdir,
                        analysis_base=self._case_workdir,
                        profile=profile,
                        force=force,
                        tool_versions=ToolVersions(),
                    )
                    result = runner.run(ctx)
                    self._batch_results[file_hash] = result
                    status = "Cached" if getattr(result, "cached", False) else "Analyzed"
                    self.after(0, self._log_console, f"{status} [{index}/{total_files}] {file_hash[:16]}…")

                except TimeoutError as e:
                    elapsed = time.time() - file_start_time
                    self._batch_results[file_hash] = {"error": str(e), "error_type": "timeout"}
                    self.after(0, self._log_console, f"✗ TIMEOUT [{index}/{total_files}] {file_hash[:16]}... after {elapsed:.2f}s")

                except Exception as e:
                    elapsed = time.time() - file_start_time
                    self._batch_results[file_hash] = {"error": str(e), "error_type": type(e).__name__}
                    self.after(0, self._log_console, f"✗ Error [{index}/{total_files}] {file_hash[:16]}...: {type(e).__name__}")

            # All files processed
            self.after(0, self.progress_bar.set, 1.0)
            self.after(0, self._on_batch_complete, total_files)

        except Exception as e:
            self.after(0, self._on_analysis_error, str(e))

    def _update_batch_progress(self, current: int, total: int, file_hash: str):
        try:
            percent = int((current / max(1, total)) * 100)
            self.progress_label.configure(
                text=f"{current}/{total} • {percent}% • {file_hash[:16]}…"
            )
        except Exception:
            pass

    def _cancel_analysis(self):
        if self._cancel_event:
            self._cancel_event.set()
        self._log_console("Cancellation requested…")

    def _on_analysis_complete(self, result):
        self._analysis_running = False
        self.run_static_btn.configure(state="normal")
        self.cancel_static_btn.configure(state="disabled")
        self.open_results_btn.configure(state="normal")
        self.progress_bar.set(1.0)

        if getattr(result, "errors", None):
            self._set_status("Analysis completed with errors", error=True)
            self._log_console(f"Errors: {', '.join(result.errors)}")
        else:
            self._set_status("Analysis completed successfully")

        self._display_results(result)

    def _on_analysis_cancelled(self):
        self._analysis_running = False
        self.run_static_btn.configure(state="normal")
        self.cancel_static_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self._set_status("Analysis cancelled")
        self._log_console("Cancelled by user")

    def _on_analysis_error(self, error_msg: str):
        self._analysis_running = False
        self.run_static_btn.configure(state="normal")
        self.cancel_static_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self._set_status(f"Error: {error_msg}", error=True)
        self._log_console(f"Error: {error_msg}")

    def _on_batch_complete(self, total_files: int):
        """Handle successful batch analysis completion."""
        try:
            self._analysis_running = False
            self.run_static_btn.configure(state="normal")
            self.cancel_static_btn.configure(state="disabled")
            self.open_results_btn.configure(state="normal")
            self.view_results_btn.configure(state="normal")
            self.progress_bar.set(1.0)
            self.progress_label.configure(text=f"Completed {total_files}/{total_files}")

            # Count successes and errors
            successes = sum(1 for r in self._batch_results.values() if not isinstance(r, dict) or "error" not in r)
            errors = total_files - successes
            cached = sum(1 for r in self._batch_results.values() if hasattr(r, 'cached') and r.cached)

            if errors > 0:
                self._set_status(f"⚠️ Batch completed: {successes} successful, {errors} errors", error=True)
                self._log_console(f"Batch analysis completed with {errors} error(s)")
            else:
                self._set_status(f"✅ Batch completed: {successes} binaries analyzed ({cached} cached)", error=False)
                self._log_console("Batch analysis completed successfully!")

            # Record one completed scan for quota purposes
            app = self.master
            if hasattr(app, "record_scan_completed"):
                try:
                    app.record_scan_completed()
                except Exception:
                    # Never let quota bookkeeping crash the UI
                    pass

            # Display aggregated results
            self._display_batch_results()

        except Exception as e:
            self._set_status(f"❌ Error displaying results: {e}", error=True)
            self._log_console(f"Error in batch completion: {e}")

        successes = sum(1 for r in self._batch_results.values() if not (isinstance(r, dict) and "error" in r))
        errors = total_files - successes
        cached = sum(1 for r in self._batch_results.values() if hasattr(r, "cached") and r.cached)

        if errors > 0:
            self._set_status(f"Batch completed: {successes} ok, {errors} errors", error=True)
        else:
            self._set_status(f"Batch completed: {successes} binaries analyzed ({cached} cached)")

        self._display_batch_results()

    # ---------- Premium gate overlay ----------

    def _show_premium_gate(self, message: str):
        """
        Show a full-page overlay that blocks interaction and prompts the
        user to upgrade to premium on the landing website.

        Uses App.user_overview to show how many free scans were used.
        """
        # Build a quota summary line from the App state
        quota_summary = ""
        try:
            app = self.master
            uo = getattr(app, "user_overview", None) or {}
            tier = (uo.get("tier") or getattr(app, "current_user_role", "free")).lower()

            if tier != "premium":
                used = int(uo.get("analysis_count") or 0)
                limit = int(
                    uo.get("analysis_quota_limit")
                    or getattr(app, "FREE_SCAN_LIMIT", 5)
                )
                quota_summary = f"Free plan usage: {used}/{limit} scans."
        except Exception:
            # Best-effort; overlay still works without quota text
            quota_summary = ""

        final_message_lines = [message]
        if quota_summary:
            final_message_lines.append("")
            final_message_lines.append(quota_summary)
        final_message = "\n".join(final_message_lines)

        # If overlay already exists, just update message and re-show it
        if self._premium_overlay is not None:
            try:
                if self._premium_message_label is not None:
                    self._premium_message_label.configure(text=final_message)
            except Exception:
                pass
            self._premium_overlay.lift()
            self._premium_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            return

        # Full overlay over this page
        overlay = ctk.CTkFrame(self, fg_color=BG)
        overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        overlay.grid_rowconfigure(0, weight=1)
        overlay.grid_columnconfigure(0, weight=1)

        # Centered card
        card = ctk.CTkFrame(
            overlay,
            fg_color=CARD_BG,
            corner_radius=16,
            border_width=1,
            border_color=BORDER,
        )
        card.grid(row=0, column=0, padx=40, pady=40, sticky="nsew")
        card.grid_rowconfigure(3, weight=1)
        card.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            card,
            text="Upgrade to CryptoScope Premium",
            font=TITLE_FONT,
            text_color=TEXT,
        )
        title.grid(row=0, column=0, sticky="w", padx=24, pady=(24, 8))

        desc = ctk.CTkLabel(
            card,
            text=(
                "You’ve reached the free-tier scan limit.\n"
                "Upgrade on the CryptoScope landing website to unlock unlimited analyses "
                "and advanced detections."
            ),
            font=BODY_FONT,
            text_color=MUTED,
            justify="left",
        )
        desc.grid(row=1, column=0, sticky="w", padx=24, pady=(0, 8))

        msg_label = ctk.CTkLabel(
            card,
            text=final_message,
            font=BODY_FONT,
            text_color=TEXT,
            justify="left",
        )
        msg_label.grid(row=2, column=0, sticky="w", padx=24, pady=(0, 16))

        # Button row
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=4, column=0, sticky="e", padx=24, pady=(0, 24))

        upgrade_btn = ctk.CTkButton(
            btn_row,
            text="Upgrade on Website",
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=self._open_upgrade_website,
        )
        upgrade_btn.pack(side="right", padx=(8, 0))

        close_btn = ctk.CTkButton(
            btn_row,
            text="Close",
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=self._hide_premium_gate,
        )
        close_btn.pack(side="right")

        self._premium_overlay = overlay
        self._premium_message_label = msg_label
        self._premium_overlay.lift()


    def _hide_premium_gate(self):
        """Hide the premium overlay if it exists."""
        if self._premium_overlay is not None:
            try:
                self._premium_overlay.place_forget()
            except Exception:
                pass

    def _open_upgrade_website(self):
        """Open the external landing website where users can purchase Premium."""
        try:
            webbrowser.open(UPGRADE_URL)
            self._log_console(f"[premium] Opened upgrade page: {UPGRADE_URL}")
        except Exception as e:
            self._log_console(f"[premium] Failed to open upgrade page: {e}")


    def _display_results(self, result):
        try:
            lines = [
                "=" * 60,
                "STATIC ANALYSIS SUMMARY",
                "=" * 60,
                f"File Hash: {getattr(result, 'file_hash', 'N/A')}",
                f"Cached: {'Yes' if getattr(result, 'cached', False) else 'No'}",
            ]

            if getattr(result, "summary", None):
                s = result.summary
                lines.append(f"\nFindings Count: {s.get('findings_count', 0)}")
                lines.append(f"Note: {s.get('note', 'N/A')}")

            if getattr(result, "static_results_path", None):
                lines.append(f"\nResults Path: {result.static_results_path}")
            if getattr(result, "hints_path", None):
                lines.append(f"Hints Path: {result.hints_path}")

            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", "\n".join(lines))

            if getattr(result, "static_results_path", None) and os.path.exists(result.static_results_path):
                self._display_findings_from_file(result.static_results_path)
            else:
                self.findings_text.delete("1.0", "end")
                self.findings_text.insert("1.0", "No findings file generated.")
            self._log_console("Results displayed")
        except Exception as e:
            self._log_console(f"Display error: {e}")

    def _display_findings_from_file(self, filepath: str):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            findings = data.get("findings", [])
            out = []
            out.append("=" * 80)
            out.append(f"FINDINGS ({len(findings)} total)")
            out.append("=" * 80)
            out.append("")

            if not findings:
                out.append("No cryptographic patterns detected.")
            else:
                sorted_findings = sorted(
                    findings,
                    key=lambda x: x.get("score", x.get("confidence", 0)),
                    reverse=True,
                )
                for i, finding in enumerate(sorted_findings[:50], 1):
                    out.append(f"[{i}] {finding.get('type', 'unknown').upper()}")
                    out.append(f"    ID: {finding.get('id', 'N/A')}")
                    out.append(f"    Confidence: {finding.get('confidence', finding.get('score', 0)):.2f}")
                    out.append(f"    Name: {finding.get('name', 'N/A')}")
                    if "reason_tags" in finding:
                        out.append(f"    Tags: {', '.join(finding['reason_tags'])}")
                    if "evidence_snippet" in finding:
                        snip = finding["evidence_snippet"]
                        out.append(f"    Evidence: {snip[:100] + '...' if len(snip) > 100 else snip}")
                    if "address_or_range" in finding:
                        addr = finding["address_or_range"]
                        if isinstance(addr, dict):
                            out.append(f"    Address: {addr.get('start', 'N/A')} - {addr.get('end', 'N/A')}")
                        else:
                            out.append(f"    Address: {addr}")
                    out.append("")

                if len(findings) > 50:
                    out.append(f"... {len(findings) - 50} more findings (see exported results)")

            self.findings_text.delete("1.0", "end")
            self.findings_text.insert("1.0", "\n".join(out))
        except Exception as e:
            self.findings_text.delete("1.0", "end")
            self.findings_text.insert("1.0", f"Error loading findings: {e}")

    def _display_batch_results(self):
        try:
            lines = []
            lines.append("=" * 60)
            lines.append("BATCH ANALYSIS SUMMARY")
            lines.append("=" * 60)
            lines.append(f"Total Binaries: {len(self._batch_results)}")

            successful = sum(1 for r in self._batch_results.values() if not (isinstance(r, dict) and "error" in r))
            errors = len(self._batch_results) - successful
            cached = sum(1 for r in self._batch_results.values() if hasattr(r, "cached") and r.cached)

            lines.append(f"Successful: {successful}")
            lines.append(f"Errors: {errors}")
            lines.append(f"Cached: {cached}")
            lines.append("")
            lines.append("Per-File Summary:")
            lines.append("-" * 60)

            for fh, result in self._batch_results.items():
                sh = fh[:16]
                if isinstance(result, dict) and "error" in result:
                    lines.append(f"✗ {sh}... - ERROR: {result['error']}")
                elif hasattr(result, "cached") and result.cached:
                    lines.append(f"✓ {sh}... - Cached")
                else:
                    fc = result.summary.get("findings_count", 0) if hasattr(result, "summary") else 0
                    lines.append(f"✓ {sh}... - {fc} findings")

            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", "\n".join(lines))

            # Aggregate findings
            all_findings = []
            for fh, result in self._batch_results.items():
                if isinstance(result, dict) and "error" in result:
                    continue
                if hasattr(result, "static_results_path") and result.static_results_path:
                    try:
                        with open(result.static_results_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            findings = data.get("findings", [])
                            for finding in findings:
                                finding["source_file_hash"] = fh
                            all_findings.extend(findings)
                    except Exception:
                        pass

            out = []
            out.append("=" * 80)
            out.append(f"AGGREGATED FINDINGS ({len(all_findings)} total from {successful} binaries)")
            out.append("=" * 80)
            out.append("")
            if not all_findings:
                out.append("No cryptographic patterns detected across all binaries.")
            else:
                sorted_findings = sorted(
                    all_findings,
                    key=lambda x: x.get("score", x.get("confidence", 0)),
                    reverse=True,
                )
                for i, finding in enumerate(sorted_findings[:100], 1):
                    src = finding.get("source_file_hash", "unknown")[:16]
                    out.append(f"[{i}] {finding.get('type', 'unknown').upper()} from {src}...")
                    out.append(f"    Confidence: {finding.get('confidence', finding.get('score', 0)):.2f}")
                    out.append(f"    Name: {finding.get('name', 'N/A')}")
                    if "reason_tags" in finding:
                        out.append(f"    Tags: {', '.join(finding['reason_tags'])}")
                    out.append("")
            self.findings_text.delete("1.0", "end")
            self.findings_text.insert("1.0", "\n".join(out))

            if not (self._cancel_event and self._cancel_event.is_set()):
                self._log_console("Batch results displayed")
        except Exception as e:
            self._log_console(f"Error displaying batch results: {e}")

    def _open_results_folder(self):
        try:
            import subprocess, platform
            workdir = self._case_workdir or self._loaded_case_workdir
            if not workdir:
                self._set_status("No case loaded", error=True)
                return
            analysis_dir = Path(workdir) / "analysis" / "static"
            if not analysis_dir.exists():
                self._set_status("No analysis results found", error=True)
                return
            if platform.system() == "Windows":
                subprocess.run(["explorer", str(analysis_dir)], check=False)
            elif platform.system() == "Darwin":
                subprocess.run(["open", str(analysis_dir)], check=False)
            else:
                subprocess.run(["xdg-open", str(analysis_dir)], check=False)
            self._log_console(f"Opened: {analysis_dir}")
        except Exception as e:
            self._set_status(f"Open failed: {e}", error=True)

    def _view_results_in_app(self):
        """Navigate to Results page to view analysis results."""
        try:
            workdir = self._case_workdir or self._loaded_case_workdir
            if not workdir:
                self._set_status("❌ No case loaded", error=True)
                return

            # Get the first file hash to display results for
            # (In future: could let user select which file)
            if not self._all_file_hashes:
                self._set_status("❌ No binaries analyzed yet", error=True)
                return

            file_hash = self._all_file_hashes[0]

            # Check if results exist
            results_path = Path(workdir) / "analysis" / "static" / file_hash / "static_results.json"
            if not results_path.exists():
                self._set_status(
                    "❌ No results found for this binary. Run analysis first.",
                    error=True
                )
                return

            # Load the Results page and navigate to it
            from pages import ResultsPage

            # Access the results page from parent app
            results_page = None
            if hasattr(self, 'master') and hasattr(self.master, '_pages'):
                results_page = self.master._pages.get("results")
            elif hasattr(self, '_pages'):
                results_page = self._pages.get("results")

            if results_page is None:
                self._set_status("❌ Results page not available in app", error=True)
                return

            # Verify it's the right type
            if type(results_page).__name__ == '_MissingPage':
                self._set_status("❌ Results page failed to load (missing dependency)", error=True)
                return

            if not hasattr(results_page, 'load'):
                self._set_status(f"❌ Results page missing load method ({type(results_page).__name__})", error=True)
                return

            # Load and display results
            try:
                results_page.load(workdir, file_hash)
                self.switch_page("results")
                self._set_status(f"✓ Viewing results for {file_hash[:16]}...", error=False)
                self._log_console(f"Switched to Results page for {file_hash}")
            except Exception as load_err:
                self._set_status(f"❌ Failed to load results: {load_err}", error=True)
                import logging
                logger = logging.getLogger(__name__)
                logger.exception(f"Results load error: {load_err}")

        except Exception as e:
            self._set_status(f"❌ Failed to access results page: {e}", error=True)
            import traceback
            traceback.print_exc()

    def _clear_results(self):
        try:
            self.summary_text.delete("1.0", "end")
            self.findings_text.delete("1.0", "end")
            self.console_text.delete("1.0", "end")
        except Exception:
            pass

    def _scan_all_cases(self):
        try:
            workdir = self._case_workdir or self._loaded_case_workdir
            if not workdir:
                self.case_summary_label.configure(text="No case loaded", text_color=MUTED)
                return
            workdir_path = Path(workdir)
            preproc_dir = workdir_path / "preproc"
            if not preproc_dir.exists():
                self.case_summary_label.configure(text="No preproc directory found", text_color=MUTED)
                return

            all_hashes = []
            cached_count = 0
            for item in preproc_dir.iterdir():
                if item.is_dir():
                    if (item / "input.bin").exists() or (item / "metadata.json").exists():
                        file_hash = item.name
                        all_hashes.append(file_hash)
                        analysis_dir = workdir_path / "analysis" / "static" / file_hash
                        if (analysis_dir / "static_results.json").exists():
                            cached_count += 1

            self._all_file_hashes = all_hashes
            self._total_binaries = len(all_hashes)
            self._cached_binaries = cached_count
            self._ready_binaries = self._total_binaries - cached_count

            if self._total_binaries == 0:
                self.case_summary_label.configure(
                    text="No preprocessed binaries found. Run Setup first.", text_color=MUTED
                )
                self.run_static_btn.configure(state="disabled")
            else:
                summary_text = (
                    f"• Preprocessed binaries: {self._total_binaries}\n"
                    f"• Previously analyzed (cached): {self._cached_binaries}\n"
                    f"• Ready for analysis: {self._ready_binaries if not self.force_var.get() else self._total_binaries}"
                )
                self.case_summary_label.configure(text=summary_text, text_color=TEXT)
                self.run_static_btn.configure(state="normal")

            self._log_console(f"Scanned case: {self._total_binaries} binaries found")
        except Exception as e:
            self._log_console(f"Scan error: {e}")
            self.case_summary_label.configure(text=f"Error scanning cases: {e}", text_color=MUTED)

    def _browse_case_workdir(self):
        try:
            from tkinter import filedialog
            initial_dir = self.case_workdir_entry.get() or str(Path.cwd())
            directory = filedialog.askdirectory(title="Select Case Workdir", initialdir=initial_dir)
            if directory:
                self.case_workdir_entry.delete(0, "end")
                self.case_workdir_entry.insert(0, directory)
                self._refresh_case_list()
        except Exception as e:
            self._set_load_case_status(f"Browse error: {e}", error=True)

    def _refresh_case_list(self):
        try:
            workdir = self.case_workdir_entry.get().strip()
            if not workdir:
                self._set_load_case_status("Enter workdir path", error=True)
                self._update_cases_list([])
                return

            workdir_path = Path(workdir)
            if not workdir_path.exists():
                self._set_load_case_status(f"Not found: {workdir}", error=True)
                self._update_cases_list([])
                return

            preproc_dir = workdir_path / "preproc"
            if not preproc_dir.exists():
                self._set_load_case_status("No preproc directory", error=True)
                self._update_cases_list([])
                return

            cases = []
            for item in preproc_dir.iterdir():
                if item.is_dir():
                    input_bin = item / "input.bin"
                    metadata_json = item / "metadata.json"
                    if input_bin.exists() or metadata_json.exists():
                        cases.append(
                            {
                                "hash": item.name,
                                "path": str(item),
                                "has_binary": input_bin.exists(),
                                "has_metadata": metadata_json.exists(),
                            }
                        )

            if not cases:
                self._set_load_case_status("No preprocessed cases found", error=True)
            else:
                self._set_load_case_status(f"Found {len(cases)} case(s)", error=False)

            self._update_cases_list(cases)
            self._available_cases = cases
        except Exception as e:
            self._set_load_case_status(f"Refresh error: {e}", error=True)
            self._update_cases_list([])

    def _update_cases_list(self, cases: list):
        try:
            self.cases_listbox.configure(state="normal")
            self.cases_listbox.delete("1.0", "end")
            if not cases:
                self.cases_listbox.insert("end", "No cases found. Run Setup to create a case first.\n")
            else:
                self.cases_listbox.insert("end", f"Found {len(cases)} case(s):\n\n")
                for i, case in enumerate(cases, 1):
                    flags = []
                    if case.get("has_binary"):
                        flags.append("bin")
                    if case.get("has_metadata"):
                        flags.append("meta")
                    status = " | ".join(flags) if flags else "incomplete"
                    self.cases_listbox.insert("end", f"{i}. {case['hash'][:16]}... ({status})\n")
            self.cases_listbox.configure(state="disabled")
        except Exception:
            pass

    def _load_selected_case(self):
        try:
            workdir = self.case_workdir_entry.get().strip()
            if not workdir:
                self._set_load_case_status("Enter workdir path", error=True)
                return

            workdir_path = Path(workdir)
            if not workdir_path.exists():
                self._set_load_case_status("Workdir not found", error=True)
                return

            preproc_dir = workdir_path / "preproc"
            if not preproc_dir.exists():
                self._set_load_case_status("No preproc directory", error=True)
                return

            if not hasattr(self, "_available_cases") or not self._available_cases:
                self._set_load_case_status("No cases available. Click Refresh first.", error=True)
                return

            self._loaded_case_workdir = str(workdir_path)
            self._case_workdir = str(workdir_path)
            self._standalone_mode = True

            self.load_case_frame.pack_forget()
            self.mode_frame.pack(fill="x", pady=(0, 12))
            self.summary_container.grid()

            if self._current_mode == "static":
                self.static_frame.pack(fill="both", expand=True, pady=(0, 10))

            self._scan_all_cases()
            self._set_load_case_status(f"Loaded: {workdir}", error=False)
            self._set_status(f"Loaded case: {workdir}")
            self._log_console(f"Standalone mode: {workdir}")
        except Exception as e:
            self._set_load_case_status(f"Load error: {e}", error=True)

    # ---------- Helpers ----------
    def _set_load_case_status(self, message: str, error: bool = False):
        try:
            self.load_case_status.configure(text=message, text_color=(TEXT if not error else TEXT))
        except Exception:
            pass

    def _log_console(self, message: str):
        try:
            from datetime import datetime
            ts = datetime.now().strftime("%H:%M:%S")
            self.console_text.insert("end", f"[{ts}] {message}\n")
            self.console_text.see("end")
        except Exception:
            pass

    def _set_status(self, message: str, error: bool = False):
        try:
            self.status_label.configure(text=message, text_color=(TEXT if not error else TEXT))
        except Exception:
            pass

    def _on_profile_change(self, profile_name: str):
        try:
            self._active_profile = profile_name
        except Exception:
            pass

    def reset_pipeline_state(self):
        """
        Clear any pipeline/Setup-driven state so the next on_enter()
        behaves like a fresh standalone page.
        """
        try:
            # Force standalone mode on next entry
            self._standalone_mode = True
            self._loaded_case_workdir = None
            self._case_workdir = None

            # Drop batch bookkeeping
            self._all_file_hashes = []
            self._batch_results = {}
            self._current_batch_index = 0
            self._total_binaries = 0
            self._cached_binaries = 0
            self._ready_binaries = 0

            # Stop any notion of “running”
            self._analysis_running = False
            self._cancel_event = None

            # Clear UI text safely; layout is handled in on_enter()
            self._clear_results()
            try:
                self.progress_bar.set(0)
                self.progress_label.configure(text="")
            except Exception:
                pass
            self._set_status("Ready to analyze")
        except Exception:
            # Never let a reset crash navigation
            pass


    # Lifecycle
    def on_enter(self):
        """
        Entering Detectors page:
        - If coming from Setup (master.current_scan_meta has workdir), load that workspace.
        - Otherwise, show Standalone mode with 'Load Case'.
        - Always try to refresh the account bubble (if present).
        """
        try:
            scan_meta = getattr(self.master, "current_scan_meta", None)

            if scan_meta and scan_meta.get("workdir"):
                # ----- Case loaded from Setup -----
                workdir = scan_meta.get("workdir")
                self._standalone_mode = False
                self._loaded_case_workdir = workdir
                self._case_workdir = workdir

                # Show analysis UI
                self.load_case_frame.pack_forget()
                self.mode_frame.pack(fill="x", pady=(0, 12))
                self.static_frame.pack(fill="both", expand=True, pady=(8, 0))
                self.summary_container.grid()

                # Refresh case list / status
                self._scan_all_cases()
                self._set_status(f"Ready to analyze: {workdir}")
                self._log_console(f"Loaded workspace: {workdir}")

            else:
                # ----- Standalone mode (no active case) -----
                self._standalone_mode = True
                self._loaded_case_workdir = None
                self._case_workdir = None

                # Hide analysis UI
                self.mode_frame.pack_forget()
                self.static_frame.pack_forget()
                self.summary_container.grid_remove()

                # Show 'Load Case' UI
                self.load_case_frame.pack(fill="x", pady=(0, 12))
                self._set_status("Standalone mode: Load a case to begin analysis")
                self._log_console("Standalone mode: No active case. Please load a case.")

                # Prefill default workdir if helper exists
                try:
                    from auditor.setup_flow.output import get_default_workdir
                    default_wd = str(get_default_workdir())
                    self.case_workdir_entry.delete(0, "end")
                    self.case_workdir_entry.insert(0, default_wd)
                except Exception:
                    # Best-effort only; never fail UI on this
                    pass

            # ----- Refresh Account Bubble (non-fatal if anything fails) -----
            try:
                profile = None
                app = self.master
                if hasattr(app, "fetch_user_profile"):
                    try:
                        profile = app.fetch_user_profile()
                    except Exception:
                        profile = None

                if hasattr(self, "_acct") and hasattr(self._acct, "refresh"):
                    # None → bubble will fall back to its internal fetching logic
                    self._acct.refresh(profile)
                    if getattr(self._acct, "button", None) is not None:
                        self._acct.button.lift()
            except Exception as e:
                print("AccountBubble refresh error:", e)


        except Exception as e:
            # Single catch-all for the whole on_enter path
            self._set_status(f"Initialization error: {e}", error=True)
            self._log_console(f"[error] on_enter failed: {e}")
