"""Detectors page: static and dynamic analysis modes.

This page provides a toggle between Static Analysis (free) and Dynamic Analysis
(premium). The Static Analysis mode runs the complete static detection pipeline
including Ghidra exports, heuristics, and findings generation.
"""

from __future__ import annotations

import json
import os
import threading
import tkinter as tk
from pathlib import Path
from typing import Optional, Dict, Any

import customtkinter as ctk


class DetectorsPage(ctk.CTkFrame):
    """Detectors page with toggleable static/dynamic analysis modes."""

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
        mode_frame = ctk.CTkFrame(content)
        mode_frame.pack(fill="x", pady=(0, 20))

        mode_label = ctk.CTkLabel(
            mode_frame,
            text="Analysis Mode:",
            font=("Roboto", 16, "bold")
        )
        mode_label.pack(side="left", padx=(10, 15))

        # Segmented button for mode selection
        self.mode_var = tk.StringVar(value="static")
        self.mode_toggle = ctk.CTkSegmentedButton(
            mode_frame,
            values=["Static Analysis", "Dynamic Analysis"],
            command=self._on_mode_change,
            variable=self.mode_var,
            width=400,
            height=40,
            font=("Roboto", 14)
        )
        # Map button labels to internal values
        self._mode_map = {
            "Static Analysis": "static",
            "Dynamic Analysis": "dynamic"
        }
        self.mode_toggle.set("Static Analysis")
        self.mode_toggle.pack(side="left", padx=10)

        # Mode description
        self.mode_description = ctk.CTkLabel(
            mode_frame,
            text="🆓 Free • Analyzes binaries for crypto patterns using Ghidra",
            font=("Roboto", 12),
            text_color="#88b"
        )
        self.mode_description.pack(side="left", padx=15)

        # ========== Static Analysis Section ==========
        self.static_frame = ctk.CTkFrame(content)
        self.static_frame.pack(fill="both", expand=True, pady=(0, 10))
        self._build_static_ui(self.static_frame)

        # ========== Dynamic Analysis Section (Stub) ==========
        self.dynamic_frame = ctk.CTkFrame(content)
        self._build_dynamic_ui(self.dynamic_frame)
        self.dynamic_frame.pack_forget()  # Hidden by default

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

    def _build_static_ui(self, parent: ctk.CTkFrame):
        """Build the static analysis UI components."""
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        # Configuration section
        config_frame = ctk.CTkFrame(parent)
        config_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        config_frame.grid_columnconfigure(1, weight=1)

        # File hash selection (for multiple binaries)
        ctk.CTkLabel(config_frame, text="Target Binary:", font=("Roboto", 13)).grid(
            row=0, column=0, sticky="w", padx=10, pady=8
        )
        self.file_hash_var = tk.StringVar(value="auto")
        self.file_hash_menu = ctk.CTkOptionMenu(
            config_frame,
            values=["auto"],
            variable=self.file_hash_var,
            width=400
        )
        self.file_hash_menu.grid(row=0, column=1, sticky="w", padx=10)

        file_hash_hint = ctk.CTkLabel(
            config_frame,
            text="Select which binary to analyze (auto-detect if only one)",
            font=("Roboto", 10),
            text_color="#777"
        )
        file_hash_hint.grid(row=0, column=2, sticky="w", padx=15)

        # Profile selection
        ctk.CTkLabel(config_frame, text="Analysis Profile:", font=("Roboto", 13)).grid(
            row=1, column=0, sticky="w", padx=10, pady=8
        )
        self.profile_var = tk.StringVar(value="quick")
        profile_menu = ctk.CTkOptionMenu(
            config_frame,
            values=["quick", "full"],
            variable=self.profile_var,
            width=200
        )
        profile_menu.grid(row=1, column=1, sticky="w", padx=10)

        profile_hint = ctk.CTkLabel(
            config_frame,
            text="Quick: Fast entropy & pattern analysis • Full: Deep Ghidra disassembly",
            font=("Roboto", 10),
            text_color="#777"
        )
        profile_hint.grid(row=1, column=2, sticky="w", padx=15)

        # Force re-analysis option
        self.force_var = tk.BooleanVar(value=False)
        force_check = ctk.CTkCheckBox(
            config_frame,
            text="Force re-analysis (ignore cache)",
            variable=self.force_var,
            font=("Roboto", 12)
        )
        force_check.grid(row=2, column=1, sticky="w", padx=10, pady=5)

        # Action buttons
        action_frame = ctk.CTkFrame(parent)
        action_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))

        self.run_static_btn = ctk.CTkButton(
            action_frame,
            text="▶ Run Static Analysis",
            command=self._run_static_analysis,
            width=200,
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

        self.export_results_btn = ctk.CTkButton(
            action_frame,
            text="📄 Export Results",
            command=self._export_results,
            width=160,
            height=40,
            state="disabled"
        )
        self.export_results_btn.pack(side="left", padx=10)

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

    def _build_dynamic_ui(self, parent: ctk.CTkFrame):
        """Build the dynamic analysis UI (stub for now)."""
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        # Premium placeholder
        premium_frame = ctk.CTkFrame(parent)
        premium_frame.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)

        icon_label = ctk.CTkLabel(
            premium_frame,
            text="🔒",
            font=("Roboto", 72)
        )
        icon_label.pack(pady=(50, 20))

        title = ctk.CTkLabel(
            premium_frame,
            text="Dynamic Analysis",
            font=("Roboto", 28, "bold")
        )
        title.pack(pady=(0, 10))

        subtitle = ctk.CTkLabel(
            premium_frame,
            text="Premium Feature • Coming Soon",
            font=("Roboto", 16),
            text_color="#f90"
        )
        subtitle.pack(pady=(0, 30))

        description = ctk.CTkLabel(
            premium_frame,
            text="Dynamic analysis uses Frida instrumentation to trace crypto operations at runtime.\n"
                 "This feature requires a premium subscription and will be available in a future update.\n\n"
                 "Features:\n"
                 "• Runtime function hooking and tracing\n"
                 "• Memory analysis for key material\n"
                 "• Call graph generation\n"
                 "• Integration with static analysis hints",
            font=("Roboto", 12),
            text_color="#aaa",
            justify="center"
        )
        description.pack(pady=20)

        upgrade_btn = ctk.CTkButton(
            premium_frame,
            text="Learn More About Premium",
            width=250,
            height=45,
            font=("Roboto", 14, "bold"),
            fg_color="#f90",
            hover_color="#e80",
            state="disabled"
        )
        upgrade_btn.pack(pady=30)

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
        """Handle mode toggle between static and dynamic."""
        mode = self._mode_map.get(selected_label, "static")
        self._current_mode = mode

        if mode == "static":
            self.dynamic_frame.pack_forget()
            self.static_frame.pack(fill="both", expand=True, pady=(0, 10))
            self.mode_description.configure(
                text="🆓 Free • Analyzes binaries for crypto patterns using Ghidra",
                text_color="#88b"
            )
        else:  # dynamic
            self.static_frame.pack_forget()
            self.dynamic_frame.pack(fill="both", expand=True, pady=(0, 10))
            self.mode_description.configure(
                text="🔒 Premium • Runtime instrumentation with Frida (Coming Soon)",
                text_color="#f90"
            )

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
        self.export_results_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self._clear_results()
        self._log_console("Starting static analysis...")
        self._set_status("Running static analysis...")

        # Run in background thread
        self._cancel_event = threading.Event()
        t = threading.Thread(target=self._static_analysis_thread, daemon=True)
        t.start()

    def _static_analysis_thread(self):
        """Background thread for static analysis."""
        try:
            from auditor.detectors.static_detection.runner import StaticRunner
            from auditor.detectors.static_detection.context import RunContext, ToolVersions

            # Update progress
            self.after(0, self.progress_bar.set, 0.1)
            self.after(0, self._log_console, "Initializing static detection runner...")

            # Create runner
            runner = StaticRunner()

            # Get selected file hash
            selected_hash_display = self.file_hash_var.get()
            if selected_hash_display == "auto":
                file_hash = ""  # Auto-detect
            else:
                # Get full hash from mapping
                file_hash = self._available_hashes.get(selected_hash_display, "")
                if file_hash:
                    self.after(0, self._log_console, f"Analyzing binary: {file_hash[:32]}...")

            # Build context
            profile = self.profile_var.get()
            force = self.force_var.get()
            
            ctx = RunContext(
                file_hash=file_hash,  # Use selected or auto-detect
                preproc_dir=self._case_workdir,
                analysis_base=self._case_workdir,
                profile=profile,
                force=force,
                tool_versions=ToolVersions()
            )

            self.after(0, self.progress_bar.set, 0.2)
            self.after(0, self._log_console, f"Running {profile} profile analysis...")

            # Run analysis
            result = runner.run(ctx)

            # Check for cancellation
            if self._cancel_event and self._cancel_event.is_set():
                self.after(0, self._on_analysis_cancelled)
                return

            # Process results
            self.after(0, self._on_analysis_complete, result)

        except Exception as e:
            self.after(0, self._on_analysis_error, str(e))

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
            self.export_results_btn.configure(state="normal")
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

    def _export_results(self):
        """Export results to a user-selected location."""
        try:
            from tkinter import filedialog
            
            filepath = filedialog.asksaveasfilename(
                title="Export Analysis Results",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if not filepath:
                return

            # Copy static_results.json to selected location
            scan_meta = getattr(self.master, "current_scan_meta", {})
            workdir = scan_meta.get("workdir", "")
            
            if workdir:
                # Find the analysis/static directory
                analysis_dir = Path(workdir) / "analysis" / "static"
                if analysis_dir.exists():
                    # Find the most recent static_results.json
                    results_files = list(analysis_dir.glob("*/static_results.json"))
                    if results_files:
                        latest = max(results_files, key=lambda p: p.stat().st_mtime)
                        
                        import shutil
                        shutil.copy(latest, filepath)
                        self._set_status(f"✅ Results exported to {filepath}")
                        self._log_console(f"Exported results to: {filepath}")
                        return

            self._set_status("❌ No results available to export", error=True)

        except Exception as e:
            self._set_status(f"❌ Export failed: {e}", error=True)

    def _clear_results(self):
        """Clear all result displays."""
        try:
            self.summary_text.delete("1.0", "end")
            self.findings_text.delete("1.0", "end")
            self.console_text.delete("1.0", "end")
        except Exception:
            pass

    def _refresh_file_hashes(self):
        """Scan workdir and populate file hash dropdown."""
        try:
            workdir = self._case_workdir or self._loaded_case_workdir
            if not workdir:
                return

            workdir_path = Path(workdir)
            preproc_dir = workdir_path / "preproc"
            
            if not preproc_dir.exists():
                return

            # Find all file hash directories
            hashes = []
            for item in preproc_dir.iterdir():
                if item.is_dir():
                    # Check if it has expected structure
                    if (item / "input.bin").exists() or (item / "metadata.json").exists():
                        hashes.append(item.name)

            # Update dropdown
            if not hashes:
                self.file_hash_menu.configure(values=["auto"])
                self.file_hash_var.set("auto")
            elif len(hashes) == 1:
                # Single hash - show it but keep auto as default
                display_value = f"{hashes[0][:16]}... (only)"
                self.file_hash_menu.configure(values=["auto", display_value])
                self.file_hash_var.set("auto")
                self._available_hashes = {display_value: hashes[0]}
            else:
                # Multiple hashes - user must select
                display_values = [f"{h[:16]}..." for h in hashes]
                all_values = ["auto"] + display_values
                self.file_hash_menu.configure(values=all_values)
                self.file_hash_var.set("auto")
                # Store mapping from display to full hash
                self._available_hashes = {f"{h[:16]}...": h for h in hashes}
                
                self._log_console(f"Found {len(hashes)} preprocessed binaries - please select one")
                
        except Exception as e:
            self._log_console(f"Error refreshing file hashes: {e}")

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

            # Hide load case UI, show analysis UI
            self.load_case_frame.pack_forget()
            self.mode_toggle.pack(side="left", padx=10)
            self.mode_description.pack(side="left", padx=15)

            # Show the appropriate analysis frame
            if self._current_mode == "static":
                self.static_frame.pack(fill="both", expand=True, pady=(0, 10))
            else:
                self.dynamic_frame.pack(fill="both", expand=True, pady=(0, 10))

            # Refresh file hash dropdown
            self._refresh_file_hashes()

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
                
                # Hide load case UI, show analysis UI
                self.load_case_frame.pack_forget()
                
                # Refresh file hash dropdown
                self._refresh_file_hashes()
                
                self._set_status(f"Ready to analyze: {workdir}")
                self._log_console(f"Loaded scan workspace: {workdir}")
            else:
                # Standalone mode - show load case UI
                self._standalone_mode = True
                self._loaded_case_workdir = None
                self._case_workdir = None
                
                # Hide mode toggle and analysis frames, show load case UI
                self.static_frame.pack_forget()
                self.dynamic_frame.pack_forget()
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
