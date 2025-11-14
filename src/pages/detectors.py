"""Detectors page: static analysis mode.

This page runs the complete static detection pipeline
including Ghidra exports, heuristics, and findings generation.
"""

from __future__ import annotations

import json
import os
import threading
import tkinter as tk
from pathlib import Path
from typing import Optional, Dict, Any, Callable

import customtkinter as ctk


class DetectorsPage(ctk.CTkFrame):
    """Detectors page for static analysis."""

    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Standalone mode state
        self._standalone_mode = False
        self._loaded_case_workdir = None
        self._available_hashes = {}  # Maps display name to full hash

        # Main content frame
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        content.grid_columnconfigure(0, weight=1)

        # ========== Header ==========
        header_frame = ctk.CTkFrame(content, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        header = ctk.CTkLabel(
            header_frame,
            text="Cryptographic Detection Analysis",
            font=("Roboto", 32, "bold")
        )
        header.pack(side="left")

        # Accounts menu (if available)
        try:
            from .accounts import AccountsMenu
            acct = AccountsMenu(header_frame, on_profile_change=self._on_profile_change)
            acct.pack(side="right")
        except Exception:
            pass

        # ========== Load Case UI (Standalone Mode) ==========
        self.load_case_frame = ctk.CTkFrame(content)
        self._build_load_case_ui(self.load_case_frame)
        # Hidden by default, shown only in standalone mode
        self.load_case_frame.pack_forget()

        # ========== Mode Toggle ==========
        self.mode_frame = ctk.CTkFrame(content)
        # Don't pack yet - will be shown when case is loaded or from setup page
        
        mode_label = ctk.CTkLabel(
            self.mode_frame,
            text="Analysis Mode:",
            font=("Roboto", 16, "bold")
        )
        mode_label.pack(side="left", padx=(10, 15))

        # Segmented button for mode selection
        self.mode_var = tk.StringVar(value="static")
        self.mode_toggle = ctk.CTkSegmentedButton(
            self.mode_frame,
            values=["Static Analysis"],
            command=self._on_mode_change,
            variable=self.mode_var,
            width=400,
            height=40,
            font=("Roboto", 14)
        )
        self.mode_toggle.set("Static Analysis")
        self.mode_toggle.pack(side="left", padx=10)

        # Mode description
        self.mode_description = ctk.CTkLabel(
            self.mode_frame,
            text="🆓 Free • Analyzes binaries for crypto patterns using Ghidra",
            font=("Roboto", 12),
            text_color="#88b"
        )
        self.mode_description.pack(side="left", padx=15)

        # ========== Static Analysis Section ==========
        self.static_frame = ctk.CTkFrame(content)
        # Don't pack yet - will be shown when case is loaded or from setup page
        self._build_static_ui(self.static_frame)

        # Hidden by default

        # ========== Status Bar ==========
        status_frame = ctk.CTkFrame(content, height=30)
        status_frame.pack(fill="x", pady=(10, 0))
        
        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Ready to analyze",
            font=("Roboto", 11),
            text_color="#aaa"
        )
        self.status_label.pack(side="left", padx=10)

        # Internal state
        self._analysis_running = False
        self._cancel_event = None
        self._current_mode = "static"
        self._case_workdir: Optional[str] = None
        
        # Batch processing state
        self._all_file_hashes = []  # List of all hashes to process
        self._batch_results = {}  # Dict mapping file_hash -> result
        self._current_batch_index = 0
        self._total_binaries = 0
        self._cached_binaries = 0
        self._ready_binaries = 0

    def _build_static_ui(self, parent: ctk.CTkFrame):
        """Build the static analysis UI components."""
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        # Configuration section
        config_frame = ctk.CTkFrame(parent)
        config_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        config_frame.grid_columnconfigure(1, weight=1)

        # Case summary section (store reference for visibility control)
        self.summary_container = ctk.CTkFrame(config_frame, fg_color="transparent")
        self.summary_container.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=(10, 15))
        self.summary_container.grid_columnconfigure(0, weight=1)

        summary_title = ctk.CTkLabel(
            self.summary_container,
            text="📊 Case Summary",
            font=("Roboto", 14, "bold")
        )
        summary_title.pack(anchor="w")

        self.case_summary_label = ctk.CTkLabel(
            self.summary_container,
            text="Scanning for preprocessed binaries...",
            font=("Roboto", 11),
            text_color="#999",
            justify="left"
        )
        self.case_summary_label.pack(anchor="w", pady=(5, 0))

        # Separator
        separator = ctk.CTkFrame(config_frame, height=2, fg_color="#333")
        separator.grid(row=1, column=0, columnspan=3, sticky="ew", padx=10, pady=10)

        # Options row
        options_row = ctk.CTkFrame(config_frame, fg_color="transparent")
        options_row.grid(row=2, column=0, columnspan=3, sticky="w", padx=10, pady=10)

        # Hidden profile variable (default to "full" for comprehensive analysis)
        self.profile_var = tk.StringVar(value="full")
        
        # Force re-analysis option
        self.force_var = tk.BooleanVar(value=False)
        force_check = ctk.CTkCheckBox(
            options_row,
            text="Force re-analysis (ignore cache)",
            variable=self.force_var,
            font=("Roboto", 12)
        )
        force_check.pack(side="left", padx=(0, 20))

        # Action buttons
        action_frame = ctk.CTkFrame(parent)
        action_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))

        self.run_static_btn = ctk.CTkButton(
            action_frame,
            text="▶ Analyze All Binaries",
            command=self._run_static_analysis,
            width=220,
            height=40,
            font=("Roboto", 14, "bold"),
            fg_color="#2a7e3f",
            hover_color="#236633"
        )
        self.run_static_btn.pack(side="left", padx=10)

        self.cancel_static_btn = ctk.CTkButton(
            action_frame,
            text="⏹ Cancel",
            command=self._cancel_analysis,
            width=120,
            height=40,
            state="disabled",
            fg_color="#8b3a3a",
            hover_color="#6b2a2a"
        )
        self.cancel_static_btn.pack(side="left", padx=10)

        self.open_results_btn = ctk.CTkButton(
            action_frame,
            text="📁 Open Results",
            command=self._open_results_folder,
            width=160,
            height=40,
            state="disabled"
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
        progress_frame = ctk.CTkFrame(action_frame, fg_color="transparent")
        progress_frame.pack(side="left", fill="x", expand=True, padx=20)

        self.progress_bar = ctk.CTkProgressBar(progress_frame, width=300)
        self.progress_bar.pack(side="left", fill="x", expand=True)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            progress_frame,
            text="",
            font=("Roboto", 11),
            text_color="#aaa"
        )
        self.progress_label.pack(side="left", padx=10)

        # Results display
        results_frame = ctk.CTkFrame(parent)
        results_frame.grid(row=2, column=0, sticky="nsew", padx=15, pady=(0, 15))
        results_frame.grid_rowconfigure(1, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        results_header = ctk.CTkLabel(
            results_frame,
            text="Analysis Results",
            font=("Roboto", 16, "bold")
        )
        results_header.grid(row=0, column=0, sticky="w", padx=10, pady=10)

        # Tabbed results view
        self.results_notebook = ctk.CTkTabview(results_frame)
        self.results_notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Summary tab
        self.results_notebook.add("Summary")
        summary_text = ctk.CTkTextbox(
            self.results_notebook.tab("Summary"),
            wrap="word",
            font=("Consolas", 11)
        )
        summary_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.summary_text = summary_text

        # Findings tab
        self.results_notebook.add("Findings")
        findings_text = ctk.CTkTextbox(
            self.results_notebook.tab("Findings"),
            wrap="word",
            font=("Consolas", 10)
        )
        findings_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.findings_text = findings_text

        # Console/Log tab
        self.results_notebook.add("Console")
        console_text = ctk.CTkTextbox(
            self.results_notebook.tab("Console"),
            wrap="word",
            font=("Consolas", 9)
        )
        console_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.console_text = console_text

    def _build_load_case_ui(self, parent: ctk.CTkFrame):
        """Build the load case UI for standalone mode."""
        parent.grid_columnconfigure(0, weight=1)

        # Title
        title_label = ctk.CTkLabel(
            parent,
            text="Load Existing Case",
            font=("Roboto", 18, "bold")
        )
        title_label.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))

        description = ctk.CTkLabel(
            parent,
            text="No active case detected. Load a previously preprocessed case to run static analysis.",
            font=("Roboto", 12),
            text_color="#aaa"
        )
        description.grid(row=1, column=0, sticky="w", padx=15, pady=(0, 15))

        # Case selection frame
        selection_frame = ctk.CTkFrame(parent, fg_color="transparent")
        selection_frame.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        selection_frame.grid_columnconfigure(1, weight=1)

        # Workdir input
        ctk.CTkLabel(
            selection_frame,
            text="Workdir:",
            font=("Roboto", 12)
        ).grid(row=0, column=0, sticky="w", pady=5)

        workdir_row = ctk.CTkFrame(selection_frame, fg_color="transparent")
        workdir_row.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        workdir_row.grid_columnconfigure(0, weight=1)

        self.case_workdir_entry = ctk.CTkEntry(
            workdir_row,
            placeholder_text="Enter case workdir path or browse..."
        )
        self.case_workdir_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        browse_btn = ctk.CTkButton(
            workdir_row,
            text="Browse",
            width=100,
            command=self._browse_case_workdir
        )
        browse_btn.grid(row=0, column=1)

        # Available cases list
        ctk.CTkLabel(
            selection_frame,
            text="Available Cases:",
            font=("Roboto", 12)
        ).grid(row=1, column=0, sticky="nw", pady=(15, 5))

        cases_frame = ctk.CTkFrame(selection_frame)
        cases_frame.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(15, 5))
        cases_frame.grid_columnconfigure(0, weight=1)

        # Scrollable list of cases
        self.cases_listbox = ctk.CTkTextbox(
            cases_frame,
            height=120,
            font=("Consolas", 10)
        )
        self.cases_listbox.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.cases_listbox.configure(state="disabled")

        refresh_btn = ctk.CTkButton(
            cases_frame,
            text="🔄 Refresh Cases",
            width=150,
            command=self._refresh_case_list
        )
        refresh_btn.grid(row=1, column=0, pady=(5, 10))

        # Action buttons
        action_frame = ctk.CTkFrame(parent, fg_color="transparent")
        action_frame.grid(row=3, column=0, sticky="ew", padx=15, pady=(0, 15))

        self.load_case_btn = ctk.CTkButton(
            action_frame,
            text="Load Case",
            width=150,
            height=40,
            font=("Roboto", 14, "bold"),
            fg_color="#4a9eff",
            hover_color="#357abd",
            command=self._load_selected_case
        )
        self.load_case_btn.pack(side="left", padx=5)

        # Status for load case
        self.load_case_status = ctk.CTkLabel(
            action_frame,
            text="",
            font=("Roboto", 11)
        )
        self.load_case_status.pack(side="left", padx=15)

    def _on_mode_change(self, selected_label: str):
        """Handle mode selection (static-only)."""
        self.static_frame.pack(fill="both", expand=True, pady=(0, 10))
        self.mode_description.configure(
            text="🆓 Free • Analyzes binaries for crypto patterns using Ghidra",
            text_color="#88b"
        )

        # Hide case summary in standalone mode if no case is loaded
        if self._standalone_mode and not self._loaded_case_workdir:
            self.summary_container.grid_remove()
        else:
            # Show it if coming from setup page
            self.summary_container.grid()

    def _run_static_analysis(self):
        """Run static analysis in background thread."""
        if self._analysis_running:
            return

        # Get case workdir (from setup page OR standalone load)
        try:
            # Use loaded case workdir if available (standalone mode)
            if self._loaded_case_workdir:
                self._case_workdir = self._loaded_case_workdir
            else:
                # Try to get from setup page metadata
                scan_meta = getattr(self.master, "current_scan_meta", None)
                if not scan_meta or not scan_meta.get("workdir"):
                    self._set_status("❌ No case loaded. Please load a case or run Setup first.", error=True)
                    return
                
                self._case_workdir = scan_meta.get("workdir")
        except Exception as e:
            self._set_status(f"❌ Error: {e}", error=True)
            return

        # UI feedback
        self._analysis_running = True
        self.run_static_btn.configure(state="disabled")
        self.cancel_static_btn.configure(state="normal")
        self.open_results_btn.configure(state="disabled")
        self.view_results_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self._clear_results()
        self._log_console("Starting static analysis...")
        self._set_status("Running static analysis...")

        # Run in background thread
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

            # Setup comprehensive logging
            log_file = Path(self._case_workdir) / "static_detection_debug.log"
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler(sys.stdout)
                ],
                force=True
            )
            logger = logging.getLogger(__name__)

            logger.info("="*80)
            logger.info("STATIC DETECTION BATCH ANALYSIS START")
            logger.info("="*80)

            # Initialize batch results
            self._batch_results = {}
            self._current_batch_index = 0

            profile = self.profile_var.get()
            force = self.force_var.get()

            total_files = len(self._all_file_hashes)

            logger.info(f"Total files to process: {total_files}")
            logger.info(f"Profile: {profile}, Force: {force}")
            logger.info(f"Case workdir: {self._case_workdir}")

            self.after(0, self._log_console, f"Starting batch analysis of {total_files} binaries...")
            self.after(0, self._log_console, f"Profile: {profile}, Force: {force}")
            self.after(0, self._log_console, f"Debug log: {log_file}")

            # Create runner once (reuse for all files)
            runner = StaticRunner()
            logger.info("StaticRunner created")

            # Validate file availability before batch analysis
            logger.info("="*80)
            logger.info("PRE-BATCH FILE VALIDATION")
            logger.info("="*80)
            try:
                import os
                from pathlib import Path

                preproc_base = Path(self._case_workdir) / "preproc"
                if not preproc_base.exists():
                    logger.error(f"✗ CRITICAL: preproc/ directory not found at {preproc_base}")
                    self.after(0, self._log_console, "✗ ERROR: preproc/ directory not found. Aborting batch analysis.")
                    self.after(0, self._on_batch_error, "File validation failed: preproc/ directory missing")
                    return

                # Validate that each file hash has a corresponding preproc directory
                missing_files = []
                for file_hash in self._all_file_hashes:
                    file_preproc = preproc_base / file_hash / "input.bin"
                    if not file_preproc.exists():
                        missing_files.append(file_hash)
                        logger.warning(f"⚠ Missing: {file_hash}/input.bin")
                    else:
                        try:
                            size = os.path.getsize(file_preproc)
                            logger.debug(f"✓ Found: {file_hash}/input.bin ({size} bytes)")
                        except Exception as e:
                            logger.warning(f"⚠ Could not get size for {file_hash}: {e}")

                if missing_files:
                    logger.error(f"✗ Missing {len(missing_files)} file(s) in preproc/")
                    for mf in missing_files[:10]:  # Show first 10
                        logger.error(f"  - {mf}")
                    self.after(0, self._log_console, f"✗ ERROR: {len(missing_files)} file(s) missing in preproc/")
                    self.after(0, self._on_batch_error, f"File validation failed: {len(missing_files)} file(s) missing")
                    return
                else:
                    logger.info(f"✓ All {len(self._all_file_hashes)} files validated successfully in preproc/")
                    self.after(0, self._log_console, f"✓ File validation passed: {len(self._all_file_hashes)} file(s) ready")

            except Exception as val_err:
                logger.error(f"✗ File validation error: {val_err}", exc_info=True)
                self.after(0, self._log_console, f"✗ ERROR: File validation error: {val_err}")
                self.after(0, self._on_batch_error, f"File validation error: {val_err}")
                return

            logger.info("="*80)

            # Progress update throttling: update UI every N files instead of every file
            # This prevents excessive UI thread calls that can cause freezing
            UI_UPDATE_FREQUENCY = 10  # Update UI every 10 files
            last_ui_update = 0

            # Process each file hash
            for index, file_hash in enumerate(self._all_file_hashes, 1):
                file_start_time = time.time()

                # Check for cancellation
                if self._cancel_event and self._cancel_event.is_set():
                    logger.info(f"Cancellation requested at file {index}/{total_files}")
                    self.after(0, self._on_batch_cancelled, index - 1, total_files)
                    return

                self._current_batch_index = index

                # Throttle UI updates: only update every N files
                # This dramatically reduces UI thread work and prevents freezing
                should_update_ui = (index % UI_UPDATE_FREQUENCY == 0) or (index == total_files)

                if should_update_ui:
                    progress = (index - 0.5) / total_files
                    self.after(0, self.progress_bar.set, progress)
                    self.after(0, self._update_batch_progress, index, total_files, file_hash)
                    logger.debug(f"[UI UPDATE] Progress: {index}/{total_files}")

                logger.info(f"\n{'='*80}")
                logger.info(f"[{index}/{total_files}] Starting analysis of {file_hash}")
                logger.info(f"{'='*80}")

                try:
                    # Build context for this specific file
                    logger.debug(f"[{index}] Creating RunContext...")
                    ctx = RunContext(
                        file_hash=file_hash,
                        preproc_dir=self._case_workdir,
                        analysis_base=self._case_workdir,
                        profile=profile,
                        force=force,
                        tool_versions=ToolVersions()
                    )
                    logger.debug(f"[{index}] RunContext created")

                    # Run analysis for this file
                    logger.debug(f"[{index}] Calling runner.run()...")
                    run_start = time.time()
                    result = runner.run(ctx)
                    run_elapsed = time.time() - run_start
                    logger.info(f"[{index}] runner.run() completed in {run_elapsed:.2f}s")

                    # Store result
                    self._batch_results[file_hash] = result
                    logger.debug(f"[{index}] Result stored")

                    # Log completion
                    status = "✓ Cached" if result.cached else "✓ Analyzed"
                    file_elapsed = time.time() - file_start_time
                    log_msg = f"{status} [{index}/{total_files}] {file_hash[:16]}... ({file_elapsed:.2f}s)"
                    logger.info(log_msg)
                    self.after(0, self._log_console, log_msg)

                except TimeoutError as e:
                    elapsed = time.time() - file_start_time
                    logger.error(f"[{index}] TIMEOUT after {elapsed:.2f}s: {e}", exc_info=True)
                    self._batch_results[file_hash] = {"error": str(e), "error_type": "timeout"}
                    self.after(0, self._log_console, f"✗ TIMEOUT [{index}/{total_files}] {file_hash[:16]}... after {elapsed:.2f}s")

                except Exception as e:
                    elapsed = time.time() - file_start_time
                    logger.error(f"[{index}] ERROR after {elapsed:.2f}s: {type(e).__name__}: {e}", exc_info=True)
                    self._batch_results[file_hash] = {"error": str(e), "error_type": type(e).__name__}
                    self.after(0, self._log_console, f"✗ Error [{index}/{total_files}] {file_hash[:16]}...: {type(e).__name__}")

            # All files processed
            total_elapsed = time.time() - file_start_time
            logger.info(f"\n{'='*80}")
            logger.info(f"BATCH ANALYSIS COMPLETE - Total time: {total_elapsed:.2f}s")
            logger.info(f"{'='*80}")

            self.after(0, self.progress_bar.set, 1.0)
            self.after(0, self._on_batch_complete, total_files)

        except Exception as e:
            logger.error(f"FATAL ERROR in batch thread: {type(e).__name__}: {e}", exc_info=True)
            self.after(0, self._on_analysis_error, str(e))

    def _update_batch_progress(self, current: int, total: int, file_hash: str):
        """Update progress label with batch status."""
        try:
            percent = int((current / total) * 100)
            self.progress_label.configure(
                text=f"Processing {current}/{total} ({percent}%) - {file_hash[:16]}..."
            )
        except Exception:
            pass

    def _cancel_analysis(self):
        """Cancel ongoing analysis."""
        if self._cancel_event:
            self._cancel_event.set()
        self._log_console("Cancellation requested...")

    def _on_analysis_complete(self, result):
        """Handle successful analysis completion."""
        try:
            self._analysis_running = False
            self.run_static_btn.configure(state="normal")
            self.cancel_static_btn.configure(state="disabled")
            self.open_results_btn.configure(state="normal")
            self.view_results_btn.configure(state="normal")
            self.progress_bar.set(1.0)

            if result.errors:
                self._set_status(f"⚠️ Analysis completed with errors", error=True)
                self._log_console(f"Errors: {', '.join(result.errors)}")
            else:
                self._set_status("✅ Analysis completed successfully", error=False)

            # Display results
            self._display_results(result)

        except Exception as e:
            self._log_console(f"Error processing results: {e}")

    def _on_analysis_cancelled(self):
        """Handle analysis cancellation."""
        self._analysis_running = False
        self.run_static_btn.configure(state="normal")
        self.cancel_static_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self._set_status("Analysis cancelled", error=False)
        self._log_console("Analysis cancelled by user")

    def _on_analysis_error(self, error_msg: str):
        """Handle analysis error."""
        self._analysis_running = False
        self.run_static_btn.configure(state="normal")
        self.cancel_static_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self._set_status(f"❌ Error: {error_msg}", error=True)
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
                self._log_console(f"Batch analysis completed successfully!")

            # Display aggregated results
            self._display_batch_results()

        except Exception as e:
            self._set_status(f"❌ Error displaying results: {e}", error=True)
            self._log_console(f"Error in batch completion: {e}")

    def _on_batch_cancelled(self, processed: int, total: int):
        """Handle batch analysis cancellation."""
        try:
            self._analysis_running = False
            self.run_static_btn.configure(state="normal")
            self.cancel_static_btn.configure(state="disabled")
            self.progress_bar.set(0)
            self.progress_label.configure(text="")

            self._set_status(f"⚠️ Cancelled after processing {processed}/{total} binaries", error=True)
            self._log_console(f"Batch analysis cancelled by user")

            # Display partial results if any
            if self._batch_results:
                self._display_batch_results()

        except Exception as e:
            self._log_console(f"Error in cancellation handler: {e}")

    def _display_results(self, result):
        """Display analysis results in the UI."""
        try:
            # Summary
            summary_lines = []
            summary_lines.append("=" * 60)
            summary_lines.append("STATIC ANALYSIS SUMMARY")
            summary_lines.append("=" * 60)
            summary_lines.append(f"File Hash: {result.file_hash}")
            summary_lines.append(f"Cached: {'Yes' if result.cached else 'No'}")
            
            if result.summary:
                summary_lines.append(f"\nFindings Count: {result.summary.get('findings_count', 0)}")
                summary_lines.append(f"Note: {result.summary.get('note', 'N/A')}")
            
            if result.static_results_path:
                summary_lines.append(f"\nResults Path: {result.static_results_path}")
            if result.hints_path:
                summary_lines.append(f"Hints Path: {result.hints_path}")

            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", "\n".join(summary_lines))

            # Load and display findings
            if result.static_results_path and os.path.exists(result.static_results_path):
                self._display_findings_from_file(result.static_results_path)
            else:
                self.findings_text.delete("1.0", "end")
                self.findings_text.insert("1.0", "No findings file generated.")

            self._log_console("Results displayed successfully")

        except Exception as e:
            self._log_console(f"Error displaying results: {e}")

    def _display_findings_from_file(self, filepath: str):
        """Load and display findings from static_results.json."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            findings = data.get('findings', [])
            
            output_lines = []
            output_lines.append("=" * 80)
            output_lines.append(f"FINDINGS ({len(findings)} total)")
            output_lines.append("=" * 80)
            output_lines.append("")

            if not findings:
                output_lines.append("No cryptographic patterns detected.")
            else:
                # Sort by score/confidence
                sorted_findings = sorted(
                    findings,
                    key=lambda x: x.get('score', x.get('confidence', 0)),
                    reverse=True
                )

                for i, finding in enumerate(sorted_findings[:50], 1):  # Limit to top 50
                    output_lines.append(f"[{i}] {finding.get('type', 'unknown').upper()}")
                    output_lines.append(f"    ID: {finding.get('id', 'N/A')}")
                    output_lines.append(f"    Confidence: {finding.get('confidence', finding.get('score', 0)):.2f}")
                    output_lines.append(f"    Name: {finding.get('name', 'N/A')}")
                    
                    if 'reason_tags' in finding:
                        output_lines.append(f"    Tags: {', '.join(finding['reason_tags'])}")
                    
                    if 'evidence_snippet' in finding:
                        snippet = finding['evidence_snippet']
                        if len(snippet) > 100:
                            snippet = snippet[:100] + "..."
                        output_lines.append(f"    Evidence: {snippet}")
                    
                    if 'address_or_range' in finding:
                        addr = finding['address_or_range']
                        if isinstance(addr, dict):
                            output_lines.append(f"    Address: {addr.get('start', 'N/A')} - {addr.get('end', 'N/A')}")
                        else:
                            output_lines.append(f"    Address: {addr}")
                    
                    output_lines.append("")

                if len(findings) > 50:
                    output_lines.append(f"... {len(findings) - 50} more findings (see exported results)")

            self.findings_text.delete("1.0", "end")
            self.findings_text.insert("1.0", "\n".join(output_lines))

        except Exception as e:
            self.findings_text.delete("1.0", "end")
            self.findings_text.insert("1.0", f"Error loading findings: {e}")

    def _display_batch_results(self):
        """Display aggregated results from batch analysis."""
        try:
            # Summary
            summary_lines = []
            summary_lines.append("=" * 60)
            summary_lines.append("BATCH ANALYSIS SUMMARY")
            summary_lines.append("=" * 60)
            summary_lines.append(f"Total Binaries: {len(self._batch_results)}")
            
            successful = sum(1 for r in self._batch_results.values() if not isinstance(r, dict) or "error" not in r)
            errors = len(self._batch_results) - successful
            cached = sum(1 for r in self._batch_results.values() if hasattr(r, 'cached') and r.cached)
            
            summary_lines.append(f"Successful: {successful}")
            summary_lines.append(f"Errors: {errors}")
            summary_lines.append(f"Cached: {cached}")
            summary_lines.append("")
            summary_lines.append("Per-File Summary:")
            summary_lines.append("-" * 60)
            
            for file_hash, result in self._batch_results.items():
                short_hash = file_hash[:16]
                if isinstance(result, dict) and "error" in result:
                    summary_lines.append(f"✗ {short_hash}... - ERROR: {result['error']}")
                elif hasattr(result, 'cached') and result.cached:
                    summary_lines.append(f"✓ {short_hash}... - Cached")
                else:
                    findings_count = result.summary.get('findings_count', 0) if hasattr(result, 'summary') else 0
                    summary_lines.append(f"✓ {short_hash}... - {findings_count} findings")

            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", "\n".join(summary_lines))

            # Aggregate all findings
            all_findings = []
            for file_hash, result in self._batch_results.items():
                if isinstance(result, dict) and "error" in result:
                    continue
                    
                if hasattr(result, 'static_results_path') and result.static_results_path:
                    try:
                        with open(result.static_results_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            findings = data.get('findings', [])
                            # Add file_hash to each finding
                            for finding in findings:
                                finding['source_file_hash'] = file_hash
                            all_findings.extend(findings)
                    except Exception:
                        pass

            # Display aggregated findings
            output_lines = []
            output_lines.append("=" * 80)
            output_lines.append(f"AGGREGATED FINDINGS ({len(all_findings)} total from {successful} binaries)")
            output_lines.append("=" * 80)
            output_lines.append("")

            if not all_findings:
                output_lines.append("No cryptographic patterns detected across all binaries.")
            else:
                # Sort by confidence
                sorted_findings = sorted(
                    all_findings,
                    key=lambda x: x.get('score', x.get('confidence', 0)),
                    reverse=True
                )

                for i, finding in enumerate(sorted_findings[:100], 1):  # Top 100
                    source_hash = finding.get('source_file_hash', 'unknown')[:16]
                    output_lines.append(f"[{i}] {finding.get('type', 'unknown').upper()} from {source_hash}...")
                    output_lines.append(f"    Confidence: {finding.get('confidence', finding.get('score', 0)):.2f}")
                    output_lines.append(f"    Name: {finding.get('name', 'N/A')}")
                    
                    if 'reason_tags' in finding:
                        output_lines.append(f"    Tags: {', '.join(finding['reason_tags'])}")
                    
                    output_lines.append("")

            self.findings_text.delete("1.0", "end")
            self.findings_text.insert("1.0", "\n".join(output_lines))

            # Only log success if analysis wasn't cancelled
            if not self._cancel_event or not self._cancel_event.is_set():
                self._log_console("Batch results displayed successfully")

        except Exception as e:
            self._log_console(f"Error displaying batch results: {e}")

    def _open_results_folder(self):
        """Open the analysis results folder in file explorer."""
        try:
            import subprocess
            import platform
            
            workdir = self._case_workdir or self._loaded_case_workdir
            if not workdir:
                self._set_status("❌ No case loaded", error=True)
                return

            workdir_path = Path(workdir)
            analysis_dir = workdir_path / "analysis" / "static"
            
            if not analysis_dir.exists():
                self._set_status("❌ No analysis results found", error=True)
                return

            # Open folder in file explorer (cross-platform)
            if platform.system() == "Windows":
                subprocess.run(["explorer", str(analysis_dir)], check=False)
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", str(analysis_dir)], check=False)
            else:  # Linux
                subprocess.run(["xdg-open", str(analysis_dir)], check=False)
            
            self._log_console(f"Opened results folder: {analysis_dir}")

        except Exception as e:
            self._set_status(f"❌ Failed to open folder: {e}", error=True)

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
        """Clear all result displays."""
        try:
            self.summary_text.delete("1.0", "end")
            self.findings_text.delete("1.0", "end")
            self.console_text.delete("1.0", "end")
        except Exception:
            pass

    def _scan_all_cases(self):
        """Scan workdir for all preprocessed cases and update summary."""
        try:
            workdir = self._case_workdir or self._loaded_case_workdir
            if not workdir:
                self.case_summary_label.configure(text="No case loaded")
                return

            workdir_path = Path(workdir)
            preproc_dir = workdir_path / "preproc"
            
            if not preproc_dir.exists():
                self.case_summary_label.configure(text="No preproc directory found")
                return

            # Find all valid file hash directories
            all_hashes = []
            cached_count = 0
            
            for item in preproc_dir.iterdir():
                if item.is_dir():
                    # Check if it has expected structure
                    if (item / "input.bin").exists() and (item / "metadata.json").exists():
                        file_hash = item.name
                        all_hashes.append(file_hash)
                        
                        # Check if already analyzed (has static_results.json)
                        analysis_dir = workdir_path / "analysis" / "static" / file_hash
                        if (analysis_dir / "static_results.json").exists():
                            cached_count += 1

            # Update state
            self._all_file_hashes = all_hashes
            self._total_binaries = len(all_hashes)
            self._cached_binaries = cached_count
            self._ready_binaries = self._total_binaries - cached_count

            # Update UI
            if self._total_binaries == 0:
                summary_text = "No preprocessed binaries found. Run Setup first."
                self.case_summary_label.configure(text=summary_text, text_color="#f88")
                self.run_static_btn.configure(state="disabled")
            else:
                summary_text = (
                    f"• Preprocessed binaries: {self._total_binaries}\n"
                    f"• Previously analyzed (cached): {self._cached_binaries}\n"
                    f"• Ready for analysis: {self._ready_binaries if not self.force_var.get() else self._total_binaries}"
                )
                self.case_summary_label.configure(text=summary_text, text_color="#8f8")
                self.run_static_btn.configure(state="normal")
                
            self._log_console(f"Scanned case: found {self._total_binaries} preprocessed binaries")
                
        except Exception as e:
            self._log_console(f"Error scanning cases: {e}")
            self.case_summary_label.configure(
                text=f"Error scanning cases: {e}",
                text_color="#f88"
            )

    def _browse_case_workdir(self):
        """Browse for case workdir."""
        try:
            from tkinter import filedialog
            initial_dir = self.case_workdir_entry.get() or str(Path.cwd())
            
            directory = filedialog.askdirectory(
                title="Select Case Workdir",
                initialdir=initial_dir
            )
            
            if directory:
                self.case_workdir_entry.delete(0, "end")
                self.case_workdir_entry.insert(0, directory)
                self._refresh_case_list()
        except Exception as e:
            self._set_load_case_status(f"❌ Browse error: {e}", error=True)

    def _refresh_case_list(self):
        """Scan workdir for available preprocessed cases."""
        try:
            workdir = self.case_workdir_entry.get().strip()
            if not workdir:
                self._set_load_case_status("⚠️ Enter workdir path", error=True)
                return

            workdir_path = Path(workdir)
            if not workdir_path.exists():
                self._set_load_case_status(f"⚠️ Workdir not found: {workdir}", error=True)
                self._update_cases_list([])
                return

            # Look for preproc directories
            preproc_dir = workdir_path / "preproc"
            if not preproc_dir.exists():
                self._set_load_case_status("⚠️ No preproc directory found", error=True)
                self._update_cases_list([])
                return

            # Find all case directories (file hash directories)
            cases = []
            for item in preproc_dir.iterdir():
                if item.is_dir():
                    # Check if it has the expected structure
                    input_bin = item / "input.bin"
                    metadata_json = item / "metadata.json"
                    
                    if input_bin.exists() or metadata_json.exists():
                        # Valid case
                        case_info = {
                            "hash": item.name,
                            "path": str(item),
                            "has_binary": input_bin.exists(),
                            "has_metadata": metadata_json.exists()
                        }
                        cases.append(case_info)

            if not cases:
                self._set_load_case_status("⚠️ No preprocessed cases found", error=True)
            else:
                self._set_load_case_status(f"✅ Found {len(cases)} case(s)", error=False)

            self._update_cases_list(cases)
            self._available_cases = cases

        except Exception as e:
            self._set_load_case_status(f"❌ Refresh error: {e}", error=True)
            self._update_cases_list([])

    def _update_cases_list(self, cases: list):
        """Update the cases listbox with found cases."""
        try:
            self.cases_listbox.configure(state="normal")
            self.cases_listbox.delete("1.0", "end")

            if not cases:
                self.cases_listbox.insert("end", "No cases found. Run Setup to create a case first.\n")
            else:
                self.cases_listbox.insert("end", f"Found {len(cases)} case(s):\n\n")
                for i, case in enumerate(cases, 1):
                    status_icons = []
                    if case.get("has_binary"):
                        status_icons.append("📦 bin")
                    if case.get("has_metadata"):
                        status_icons.append("📋 meta")
                    
                    status = " | ".join(status_icons) if status_icons else "❓ incomplete"
                    self.cases_listbox.insert("end", f"{i}. {case['hash'][:16]}... ({status})\n")

            self.cases_listbox.configure(state="disabled")
        except Exception:
            pass

    def _load_selected_case(self):
        """Load the case from the entered workdir."""
        try:
            workdir = self.case_workdir_entry.get().strip()
            if not workdir:
                self._set_load_case_status("⚠️ Enter workdir path", error=True)
                return

            workdir_path = Path(workdir)
            if not workdir_path.exists():
                self._set_load_case_status("⚠️ Workdir not found", error=True)
                return

            # Check if preproc exists
            preproc_dir = workdir_path / "preproc"
            if not preproc_dir.exists():
                self._set_load_case_status("⚠️ No preproc directory", error=True)
                return

            # Check if we have any cases
            if not hasattr(self, "_available_cases") or not self._available_cases:
                self._set_load_case_status("⚠️ No cases available. Click Refresh first.", error=True)
                return

            # Load the workdir
            self._loaded_case_workdir = str(workdir_path)
            self._case_workdir = str(workdir_path)
            self._standalone_mode = True

            # Hide load case UI
            self.load_case_frame.pack_forget()
            
            # Show mode toggle and analysis UI
            self.mode_frame.pack(fill="x", pady=(0, 20))

            # Show summary container now that case is loaded
            self.summary_container.grid()

            # Show the appropriate analysis frame
            if self._current_mode == "static":
                self.static_frame.pack(fill="both", expand=True, pady=(0, 10))

            # Scan all cases and update summary
            self._scan_all_cases()

            self._set_status(f"✅ Loaded case: {workdir}")
            self._log_console(f"Standalone mode: Loaded case from {workdir}")
            self._log_console(f"Found {len(self._available_cases)} preprocessed file(s)")

        except Exception as e:
            self._set_load_case_status(f"❌ Load error: {e}", error=True)

    def _set_load_case_status(self, message: str, error: bool = False):
        """Update load case status label."""
        try:
            color = "#f88" if error else "#8f8"
            self.load_case_status.configure(text=message, text_color=color)
        except Exception:
            pass

    def _log_console(self, message: str):
        """Append message to console log."""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.console_text.insert("end", f"[{timestamp}] {message}\n")
            self.console_text.see("end")
        except Exception:
            pass

    def _set_status(self, message: str, error: bool = False):
        """Update status bar."""
        try:
            color = "#f88" if error else "#8f8"
            self.status_label.configure(text=message, text_color=color)
        except Exception:
            pass

    def _on_profile_change(self, profile_name: str):
        """Handle profile change from accounts menu."""
        try:
            self._active_profile = profile_name
            # Future: adjust available features based on profile
        except Exception:
            pass

    def on_enter(self):
        """Called when the page becomes visible."""
        try:
            # Check if we have scan data from setup page
            scan_meta = getattr(self.master, "current_scan_meta", None)
            
            if scan_meta and scan_meta.get("workdir"):
                # Coming from setup page - normal flow
                workdir = scan_meta.get("workdir")
                self._standalone_mode = False
                self._loaded_case_workdir = workdir
                self._case_workdir = workdir
                
                # Hide load case UI
                self.load_case_frame.pack_forget()
                
                # Show mode toggle and analysis UI
                self.mode_frame.pack(fill="x", pady=(0, 20))
                self.static_frame.pack(fill="both", expand=True, pady=(0, 10))
                
                # Make sure summary container is visible
                self.summary_container.grid()
                
                # Scan all cases and update summary
                self._scan_all_cases()
                
                self._set_status(f"Ready to analyze: {workdir}")
                self._log_console(f"Loaded scan workspace: {workdir}")
            else:
                # Standalone mode - show load case UI only
                self._standalone_mode = True
                self._loaded_case_workdir = None
                self._case_workdir = None
                
                # Hide analysis UI completely
                self.mode_frame.pack_forget()
                self.static_frame.pack_forget()
                self.summary_container.grid_remove()
                
                # Show only load case UI
                self.load_case_frame.pack(fill="x", pady=(0, 20))
                
                self._set_status("ℹ️ Standalone mode: Load a case to begin analysis")
                self._log_console("Standalone mode: No active case. Please load a case.")
                
                # Try to auto-populate workdir if possible
                try:
                    from auditor.setup_flow.output import get_default_workdir
                    default_wd = str(get_default_workdir())
                    self.case_workdir_entry.delete(0, "end")
                    self.case_workdir_entry.insert(0, default_wd)
                except Exception:
                    pass
        except Exception as e:
            self._set_status(f"❌ Initialization error: {e}", error=True)
            pass
