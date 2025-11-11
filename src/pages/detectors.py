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
from typing import Optional, Dict, Any, Callable

import customtkinter as ctk


class DynamicAdvancedOptionsModal(ctk.CTkToplevel):
    """Advanced options modal for dynamic analysis configuration.

    This modal provides comprehensive configuration for dynamic analysis including:
    - Mode selection (Spawn/Attach)
    - Process ID input for attach mode
    - Timeout configuration with mode-specific ranges
    - Memory limit selection
    - Instrumenter selection (read-only display)
    - Force re-analysis option
    - Real-time validation with warnings

    The modal syncs with parent's mode selection and validates all inputs
    before allowing the user to apply settings.
    """

    # Factory defaults by mode
    DEFAULTS = {
        'spawn': {
            'timeout': 120,
            'memory_limit': 512,
            'timeout_range': (50, 500)
        },
        'attach': {
            'timeout': 60,
            'memory_limit': 256,
            'timeout_range': (30, 300)
        }
    }

    def __init__(
        self,
        parent,
        mode_var: tk.StringVar,
        current_settings: Optional[Dict[str, Any]] = None,
        on_apply: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        """Initialize the advanced options modal.

        Args:
            parent: Parent window (DetectorsPage or similar)
            mode_var: StringVar from parent containing mode ('spawn' or 'attach')
            current_settings: Dict of current settings to pre-populate
            on_apply: Callback function to receive applied settings
        """
        super().__init__(parent)

        # Store parent references
        self.parent_window = parent
        self.parent_mode_var = mode_var
        self.on_apply_callback = on_apply

        # Modal settings
        self.title("Advanced Dynamic Analysis Options")
        self.geometry("600x550")
        self.resizable(False, False)

        # Center on parent
        self.after(100, self._center_on_parent)

        # Modal behavior
        self.transient(parent)
        self.grab_set()

        # Internal state
        self._current_mode = mode_var.get()
        self._pending_settings = current_settings or {}
        self._last_applied_settings = current_settings or {}
        self._validation_errors = []
        self._validation_warnings = []

        # Create UI variables
        self._create_variables()

        # Build UI
        self._build_ui()

        # Initialize values from current settings or defaults
        self._initialize_values()

        # Sync with parent mode
        self._sync_mode_from_parent()

        # Bind mode change handler
        self.mode_var.trace_add('write', self._on_mode_changed)

        # Validate initially
        self._validate_all()

    def _create_variables(self):
        """Create all Tkinter variables for the modal."""
        # Mode selection (synced with parent)
        self.mode_var = tk.StringVar(value=self._current_mode)

        # Process ID for attach mode
        self.attach_pid_var = tk.StringVar(value="")

        # Timeout
        self.timeout_var = tk.IntVar(value=120)

        # Memory limit
        self.memory_limit_var = tk.StringVar(value="512")

        # Instrumenters (read-only display)
        self.crypto_ops_var = tk.BooleanVar(value=True)
        self.memory_scan_var = tk.BooleanVar(value=False)
        self.call_graph_var = tk.BooleanVar(value=False)

        # Force re-analysis
        self.force_var = tk.BooleanVar(value=False)

    def _build_ui(self):
        """Build the complete UI layout."""
        # Main content frame
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)
        content.grid_columnconfigure(1, weight=1)

        row = 0

        # ========== Mode Selection ==========
        mode_label = ctk.CTkLabel(
            content,
            text="Execution Mode:",
            font=("Roboto", 12, "bold"),
            width=150,
            anchor="w"
        )
        mode_label.grid(row=row, column=0, sticky="w", pady=10)

        mode_frame = ctk.CTkFrame(content, fg_color="transparent")
        mode_frame.grid(row=row, column=1, sticky="w", pady=10, padx=(10, 0))

        self.spawn_radio = ctk.CTkRadioButton(
            mode_frame,
            text="Spawn",
            variable=self.mode_var,
            value="spawn",
            font=("Roboto", 11)
        )
        self.spawn_radio.pack(side="left", padx=(0, 20))

        self.attach_radio = ctk.CTkRadioButton(
            mode_frame,
            text="Attach",
            variable=self.mode_var,
            value="attach",
            font=("Roboto", 11)
        )
        self.attach_radio.pack(side="left")

        row += 1

        # ========== Process ID Field (Attach Only) ==========
        self.pid_label = ctk.CTkLabel(
            content,
            text="Process ID:",
            font=("Roboto", 12, "bold"),
            width=150,
            anchor="w"
        )
        self.pid_label.grid(row=row, column=0, sticky="w", pady=10)

        self.pid_entry = ctk.CTkEntry(
            content,
            textvariable=self.attach_pid_var,
            placeholder_text="Enter PID to attach to",
            font=("Roboto", 11),
            width=200
        )
        self.pid_entry.grid(row=row, column=1, sticky="w", pady=10, padx=(10, 0))

        # Bind validation on PID change
        self.attach_pid_var.trace_add('write', lambda *args: self._validate_all())

        row += 1

        # ========== Timeout Slider ==========
        timeout_label = ctk.CTkLabel(
            content,
            text="Timeout:",
            font=("Roboto", 12, "bold"),
            width=150,
            anchor="w"
        )
        timeout_label.grid(row=row, column=0, sticky="w", pady=10)

        timeout_container = ctk.CTkFrame(content, fg_color="transparent")
        timeout_container.grid(row=row, column=1, sticky="ew", pady=10, padx=(10, 0))
        timeout_container.grid_columnconfigure(0, weight=1)

        self.timeout_slider = ctk.CTkSlider(
            timeout_container,
            from_=50,
            to=500,
            variable=self.timeout_var,
            command=self._on_timeout_changed
        )
        self.timeout_slider.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.timeout_value_label = ctk.CTkLabel(
            timeout_container,
            text="120s",
            font=("Roboto", 11),
            text_color="#aaa",
            width=60
        )
        self.timeout_value_label.grid(row=0, column=1)

        row += 1

        # ========== Memory Limit Dropdown ==========
        memory_label = ctk.CTkLabel(
            content,
            text="Memory Limit:",
            font=("Roboto", 12, "bold"),
            width=150,
            anchor="w"
        )
        memory_label.grid(row=row, column=0, sticky="w", pady=10)

        memory_options = ["128", "256", "512", "1024", "2048", "4096"]
        self.memory_dropdown = ctk.CTkOptionMenu(
            content,
            values=memory_options,
            variable=self.memory_limit_var,
            command=lambda *args: self._validate_all(),
            width=150,
            font=("Roboto", 11)
        )
        self.memory_dropdown.grid(row=row, column=1, sticky="w", pady=10, padx=(10, 0))

        row += 1

        # ========== Instrumenters (Read-only Display) ==========
        instr_label = ctk.CTkLabel(
            content,
            text="Instrumenters:",
            font=("Roboto", 12, "bold"),
            width=150,
            anchor="nw"
        )
        instr_label.grid(row=row, column=0, sticky="nw", pady=10)

        instr_frame = ctk.CTkFrame(content, fg_color="transparent")
        instr_frame.grid(row=row, column=1, sticky="w", pady=10, padx=(10, 0))

        self.crypto_ops_check = ctk.CTkCheckBox(
            instr_frame,
            text="Crypto Operations (always enabled)",
            variable=self.crypto_ops_var,
            font=("Roboto", 11),
            state="disabled"
        )
        self.crypto_ops_check.pack(anchor="w", pady=2)

        self.memory_scan_check = ctk.CTkCheckBox(
            instr_frame,
            text="Memory Scanning (disabled)",
            variable=self.memory_scan_var,
            font=("Roboto", 11),
            state="disabled"
        )
        self.memory_scan_check.pack(anchor="w", pady=2)

        self.call_graph_check = ctk.CTkCheckBox(
            instr_frame,
            text="Call Graph (disabled)",
            variable=self.call_graph_var,
            font=("Roboto", 11),
            state="disabled"
        )
        self.call_graph_check.pack(anchor="w", pady=2)

        row += 1

        # ========== Force Re-analysis ==========
        force_label = ctk.CTkLabel(
            content,
            text="Options:",
            font=("Roboto", 12, "bold"),
            width=150,
            anchor="w"
        )
        force_label.grid(row=row, column=0, sticky="w", pady=10)

        self.force_check = ctk.CTkCheckBox(
            content,
            text="Force re-analysis (ignore cache)",
            variable=self.force_var,
            font=("Roboto", 11),
            state="disabled"
        )
        self.force_check.grid(row=row, column=1, sticky="w", pady=10, padx=(10, 0))

        row += 1

        # ========== Validation Warnings Display ==========
        warnings_label = ctk.CTkLabel(
            content,
            text="Validation:",
            font=("Roboto", 12, "bold"),
            width=150,
            anchor="nw"
        )
        warnings_label.grid(row=row, column=0, sticky="nw", pady=10)

        self.warnings_text = ctk.CTkTextbox(
            content,
            height=80,
            font=("Roboto", 10),
            fg_color="#2b2b2b",
            wrap="word"
        )
        self.warnings_text.grid(row=row, column=1, sticky="ew", pady=10, padx=(10, 0))

        row += 1

        # ========== Action Buttons ==========
        button_frame = ctk.CTkFrame(content, fg_color="transparent")
        button_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(20, 0))
        button_frame.grid_columnconfigure(1, weight=1)

        self.apply_btn = ctk.CTkButton(
            button_frame,
            text="Apply",
            command=self._on_apply,
            width=120,
            height=36,
            font=("Roboto", 12, "bold"),
            fg_color="#2a7e3f",
            hover_color="#236633"
        )
        self.apply_btn.grid(row=0, column=0, padx=5)

        self.reset_btn = ctk.CTkButton(
            button_frame,
            text="Reset to Defaults",
            command=self._reset_to_defaults,
            width=150,
            height=36,
            font=("Roboto", 12),
            fg_color="#5a5a5a",
            hover_color="#4a4a4a"
        )
        self.reset_btn.grid(row=0, column=1, padx=5)

        self.cancel_btn = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=self._on_cancel,
            width=120,
            height=36,
            font=("Roboto", 12),
            fg_color="#8b3a3a",
            hover_color="#6b2a2a"
        )
        self.cancel_btn.grid(row=0, column=2, padx=5)

    def _initialize_values(self):
        """Initialize values from pending settings or defaults."""
        mode = self._current_mode

        # Load from pending settings if available
        if self._pending_settings:
            self.attach_pid_var.set(str(self._pending_settings.get('attach_pid', '')))
            self.timeout_var.set(self._pending_settings.get('timeout', self.DEFAULTS[mode]['timeout']))
            self.memory_limit_var.set(str(self._pending_settings.get('memory_limit', self.DEFAULTS[mode]['memory_limit'])))
            self.force_var.set(self._pending_settings.get('force', False))
        else:
            # Use factory defaults
            self.timeout_var.set(self.DEFAULTS[mode]['timeout'])
            self.memory_limit_var.set(str(self.DEFAULTS[mode]['memory_limit']))

    def _sync_mode_from_parent(self):
        """Sync mode selection from parent's mode variable."""
        parent_mode = self.parent_mode_var.get()
        if parent_mode != self.mode_var.get():
            self.mode_var.set(parent_mode)

    def _on_mode_changed(self, *args):
        """Handle mode change (spawn/attach)."""
        new_mode = self.mode_var.get()

        # Update timeout slider range
        timeout_range = self.DEFAULTS[new_mode]['timeout_range']
        self.timeout_slider.configure(from_=timeout_range[0], to=timeout_range[1])

        # Reset timeout to factory default for new mode
        self.timeout_var.set(self.DEFAULTS[new_mode]['timeout'])

        # Update memory limit to default for new mode
        self.memory_limit_var.set(str(self.DEFAULTS[new_mode]['memory_limit']))

        # Show/hide PID field based on mode
        if new_mode == "attach":
            self.pid_label.grid()
            self.pid_entry.grid()
        else:
            self.pid_label.grid_remove()
            self.pid_entry.grid_remove()

        # Update parent's mode var
        self.parent_mode_var.set(new_mode)

        # Update validation
        self._validate_all()

        # Update timeout label
        self._on_timeout_changed(self.timeout_var.get())

    def _on_timeout_changed(self, value):
        """Update timeout label when slider changes."""
        try:
            timeout_val = int(float(value))
            self.timeout_value_label.configure(text=f"{timeout_val}s")
            self._validate_all()
        except Exception:
            pass

    def _validate_all(self):
        """Validate all settings and update warnings display."""
        self._validation_errors = []
        self._validation_warnings = []

        mode = self.mode_var.get()
        timeout = self.timeout_var.get()
        memory_limit = int(self.memory_limit_var.get())

        # Validate PID for attach mode
        if mode == "attach":
            pid_str = self.attach_pid_var.get().strip()
            if not pid_str:
                self._validation_errors.append("ERROR: Process ID is required for Attach mode")
            else:
                try:
                    pid = int(pid_str)
                    if pid <= 0:
                        self._validation_errors.append("ERROR: Process ID must be positive")
                    else:
                        # Try to validate PID exists using psutil if available
                        try:
                            import psutil
                            if not psutil.pid_exists(pid):
                                self._validation_warnings.append(f"WARNING: Process ID {pid} does not exist on system")
                        except ImportError:
                            # psutil not available, skip validation
                            pass
                except ValueError:
                    self._validation_errors.append("ERROR: Process ID must be a valid integer")

        # Validate timeout
        if mode == "spawn" and timeout < 30:
            self._validation_warnings.append("WARNING: Timeout < 30s for spawn mode may be insufficient")
        elif mode == "attach" and timeout < 10:
            self._validation_warnings.append("WARNING: Timeout < 10s for attach mode may be insufficient")

        # Validate memory with crypto_ops
        if memory_limit < 256 and self.crypto_ops_var.get():
            self._validation_warnings.append("WARNING: Memory < 256 MB with crypto_ops may cause performance issues")

        # Update display
        self._update_warnings_display()

        # Enable/disable Apply button based on errors
        if self._validation_errors:
            self.apply_btn.configure(state="disabled")
        else:
            self.apply_btn.configure(state="normal")

    def _update_warnings_display(self):
        """Update the warnings text display."""
        self.warnings_text.configure(state="normal")
        self.warnings_text.delete("1.0", "end")

        if not self._validation_errors and not self._validation_warnings:
            self.warnings_text.insert("1.0", "All settings are valid.\n", "valid")
            self.warnings_text.tag_config("valid", foreground="#8f8")
        else:
            # Display errors first
            for error in self._validation_errors:
                self.warnings_text.insert("end", f"{error}\n", "error")

            # Then warnings
            for warning in self._validation_warnings:
                self.warnings_text.insert("end", f"{warning}\n", "warning")

            # Configure tags
            self.warnings_text.tag_config("error", foreground="#f88")
            self.warnings_text.tag_config("warning", foreground="#fa0")

        self.warnings_text.configure(state="disabled")

    def _reset_to_defaults(self):
        """Reset all settings to factory defaults for current mode."""
        mode = self.mode_var.get()
        defaults = self.DEFAULTS[mode]

        self.timeout_var.set(defaults['timeout'])
        self.memory_limit_var.set(str(defaults['memory_limit']))
        self.attach_pid_var.set("")
        self.force_var.set(False)

        self._validate_all()

        # Log to console for debugging
        print(f"[DynamicAdvancedOptions] Reset to defaults for mode: {mode}")

    def _on_apply(self):
        """Apply settings and close modal."""
        if self._validation_errors:
            return

        # Build settings dict
        mode = self.mode_var.get()
        settings = {
            'mode': mode,
            'timeout': self.timeout_var.get(),
            'memory_limit': int(self.memory_limit_var.get()),
            'crypto_ops': self.crypto_ops_var.get(),
            'memory_scan': self.memory_scan_var.get(),
            'call_graph': self.call_graph_var.get(),
            'force': self.force_var.get()
        }

        # Add attach_pid if in attach mode
        if mode == 'attach':
            try:
                settings['attach_pid'] = int(self.attach_pid_var.get().strip())
            except ValueError:
                settings['attach_pid'] = None
        else:
            settings['attach_pid'] = None

        # Store as last applied
        self._last_applied_settings = settings.copy()

        # Call callback if provided
        if self.on_apply_callback:
            self.on_apply_callback(settings)

        # Log for debugging
        print(f"[DynamicAdvancedOptions] Applied settings: {settings}")
        print(f"[DynamicAdvancedOptions] Validation warnings: {len(self._validation_warnings)}")

        # Close modal
        self.destroy()

    def _on_cancel(self):
        """Cancel and close modal without applying."""
        print("[DynamicAdvancedOptions] Cancelled without applying")
        self.destroy()

    def _center_on_parent(self):
        """Center the modal on parent window."""
        try:
            self.update_idletasks()

            # Get parent position and size
            parent_x = self.parent_window.winfo_rootx()
            parent_y = self.parent_window.winfo_rooty()
            parent_width = self.parent_window.winfo_width()
            parent_height = self.parent_window.winfo_height()

            # Get modal size
            modal_width = self.winfo_width()
            modal_height = self.winfo_height()

            # Calculate centered position
            x = parent_x + (parent_width - modal_width) // 2
            y = parent_y + (parent_height - modal_height) // 2

            # Set position
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass


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

        # ========== Dynamic Analysis Section (Stub) ==========
        self.dynamic_frame = ctk.CTkFrame(content)
        self._build_dynamic_ui(self.dynamic_frame)
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

        # Advanced options button (stub for now)
        self.advanced_static_btn = ctk.CTkButton(
            options_row,
            text="⚙️ Advanced Options...",
            command=self._open_static_advanced_options,
            width=180,
            height=32,
            font=("Roboto", 12)
        )
        self.advanced_static_btn.pack(side="left")

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
            text="� Open Results",
            command=self._open_results_folder,
            width=160,
            height=40,
            state="disabled"
        )
        self.open_results_btn.pack(side="left", padx=10)

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
        """Build the simplified dynamic analysis UI.

        Main panel shows only essential controls:
        - Mode selection (Spawn/Attach)
        - PID input (for Attach mode)
        - Advanced Options button
        - Action buttons and progress

        All advanced settings (timeout, memory, instrumenters, force re-analysis)
        are accessible via the Advanced Options modal.
        """
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        # Initialize instance variables for advanced settings management
        # These store the last applied settings from Advanced Options modal
        self._dynamic_advanced_settings = {}

        # Initialize timeout/memory with smart defaults (spawn mode defaults)
        # These will be updated based on mode or advanced settings
        self.dynamic_timeout_var = tk.IntVar(value=120)  # Default spawn timeout
        self.dynamic_memory_var = tk.IntVar(value=512)   # Default spawn memory

        # Initialize instrumenter flags with defaults
        self.crypto_ops_var = tk.BooleanVar(value=True)
        self.memory_scan_var = tk.BooleanVar(value=False)
        self.call_graph_var = tk.BooleanVar(value=False)

        # Initialize force re-analysis flag
        self.dynamic_force_var = tk.BooleanVar(value=False)

        # Configuration section - simplified to show only essential controls
        config_frame = ctk.CTkFrame(parent)
        config_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        config_frame.grid_columnconfigure(1, weight=1)

        # Execution mode selection
        ctk.CTkLabel(
            config_frame,
            text="Execution Mode:",
            font=("Roboto", 12, "bold")
        ).grid(row=0, column=0, sticky="w", pady=5)

        mode_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        mode_frame.grid(row=0, column=1, sticky="w", pady=5)

        self.dynamic_mode_var = tk.StringVar(value="spawn")

        spawn_radio = ctk.CTkRadioButton(
            mode_frame,
            text="Spawn (Launch binary with Frida)",
            variable=self.dynamic_mode_var,
            value="spawn",
            command=self._on_dynamic_mode_changed
        )
        spawn_radio.pack(side="left", padx=(0, 20))

        attach_radio = ctk.CTkRadioButton(
            mode_frame,
            text="Attach (Hook running process by PID)",
            variable=self.dynamic_mode_var,
            value="attach",
            command=self._on_dynamic_mode_changed
        )
        attach_radio.pack(side="left")

        # PID input for attach mode
        ctk.CTkLabel(
            config_frame,
            text="Process ID (for Attach):",
            font=("Roboto", 12, "bold")
        ).grid(row=0, column=2, sticky="w", padx=(20, 0), pady=5)

        self.dynamic_attach_pid_var = tk.StringVar(value="")
        pid_entry = ctk.CTkEntry(
            config_frame,
            textvariable=self.dynamic_attach_pid_var,
            placeholder_text="Enter PID (required for Attach mode)",
            width=200
        )
        pid_entry.grid(row=0, column=3, sticky="ew", padx=(10, 0), pady=5)

        # Advanced Options button - positioned after mode selection
        advanced_btn_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        advanced_btn_frame.grid(row=1, column=1, sticky="w", pady=(10, 5))

        self.advanced_dynamic_btn = ctk.CTkButton(
            advanced_btn_frame,
            text="⚙️ Advanced Options",
            command=self._open_dynamic_advanced_options,
            width=180,
            height=36,
            font=("Roboto", 12),
            fg_color="#5a7e9f",
            hover_color="#4a6a8f"
        )
        self.advanced_dynamic_btn.pack(side="left")

        # Action buttons
        action_frame = ctk.CTkFrame(parent)
        action_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))

        self.run_dynamic_btn = ctk.CTkButton(
            action_frame,
            text="▶ Analyze All Binaries",
            command=self._run_dynamic_analysis,
            width=220,
            height=40,
            font=("Roboto", 14, "bold"),
            fg_color="#5a7e9f",
            hover_color="#4a6a8f"
        )
        self.run_dynamic_btn.pack(side="left", padx=10)

        self.cancel_dynamic_btn = ctk.CTkButton(
            action_frame,
            text="⏹ Cancel",
            command=self._cancel_dynamic_analysis,
            width=120,
            height=40,
            state="disabled",
            fg_color="#8b3a3a",
            hover_color="#6b2a2a"
        )
        self.cancel_dynamic_btn.pack(side="left", padx=10)

        self.open_dynamic_results_btn = ctk.CTkButton(
            action_frame,
            text="📁 Open Results",
            command=self._open_dynamic_results_folder,
            width=160,
            height=40,
            state="disabled"
        )
        self.open_dynamic_results_btn.pack(side="left", padx=10)

        # Progress section
        progress_frame = ctk.CTkFrame(action_frame, fg_color="transparent")
        progress_frame.pack(side="left", fill="x", expand=True, padx=20)

        self.dynamic_progress_bar = ctk.CTkProgressBar(progress_frame, width=300)
        self.dynamic_progress_bar.pack(side="left", fill="x", expand=True)
        self.dynamic_progress_bar.set(0)

        self.dynamic_progress_label = ctk.CTkLabel(
            progress_frame,
            text="",
            font=("Roboto", 11),
            text_color="#aaa"
        )
        self.dynamic_progress_label.pack(side="left", padx=10)

        # Results display
        results_frame = ctk.CTkFrame(parent)
        results_frame.grid(row=2, column=0, sticky="nsew", padx=15, pady=(0, 15))
        results_frame.grid_rowconfigure(1, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        results_header = ctk.CTkLabel(
            results_frame,
            text="Dynamic Analysis Results",
            font=("Roboto", 16, "bold")
        )
        results_header.grid(row=0, column=0, sticky="w", padx=10, pady=10)

        # Tabbed results view
        self.dynamic_results_notebook = ctk.CTkTabview(results_frame)
        self.dynamic_results_notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Summary tab
        self.dynamic_results_notebook.add("Summary")
        dynamic_summary_text = ctk.CTkTextbox(
            self.dynamic_results_notebook.tab("Summary"),
            wrap="word",
            font=("Consolas", 11)
        )
        dynamic_summary_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.dynamic_summary_text = dynamic_summary_text

        # Traces tab
        self.dynamic_results_notebook.add("Traces")
        dynamic_traces_text = ctk.CTkTextbox(
            self.dynamic_results_notebook.tab("Traces"),
            wrap="word",
            font=("Consolas", 10)
        )
        dynamic_traces_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.dynamic_traces_text = dynamic_traces_text

        # Call Graph tab
        self.dynamic_results_notebook.add("Call Graph")
        dynamic_callgraph_text = ctk.CTkTextbox(
            self.dynamic_results_notebook.tab("Call Graph"),
            wrap="word",
            font=("Consolas", 10)
        )
        dynamic_callgraph_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.dynamic_callgraph_text = dynamic_callgraph_text

        # Console/Log tab
        self.dynamic_results_notebook.add("Console")
        dynamic_console_text = ctk.CTkTextbox(
            self.dynamic_results_notebook.tab("Console"),
            wrap="word",
            font=("Consolas", 9)
        )
        dynamic_console_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.dynamic_console_text = dynamic_console_text

        # Dynamic analysis state
        self._dynamic_analysis_running = False
        self._dynamic_cancel_event = None
        self._dynamic_batch_results = {}

    def _on_dynamic_mode_changed(self):
        """Handle dynamic mode change between spawn and attach."""
        try:
            mode = self.dynamic_mode_var.get()
            if mode == "attach":
                self._log_dynamic_console("ℹ️ Attach mode selected: Enter the PID of the process to attach to")
            else:
                self._log_dynamic_console("ℹ️ Spawn mode selected: Binary will be launched with Frida instrumentation")
        except Exception:
            pass

    def _open_dynamic_advanced_options(self):
        """Open the advanced options modal for dynamic analysis."""
        try:
            # Build current settings dict from UI state
            current_settings = {
                'mode': self.dynamic_mode_var.get(),
                'timeout': self.dynamic_timeout_var.get(),
                'memory_limit': self.dynamic_memory_var.get(),
                'crypto_ops': self.crypto_ops_var.get(),
                'memory_scan': self.memory_scan_var.get(),
                'call_graph': self.call_graph_var.get(),
                'force': self.dynamic_force_var.get()
            }

            # Add attach_pid if available
            pid_str = self.dynamic_attach_pid_var.get().strip()
            if pid_str:
                try:
                    current_settings['attach_pid'] = int(pid_str)
                except ValueError:
                    current_settings['attach_pid'] = None
            else:
                current_settings['attach_pid'] = None

            # Use last applied settings if available (session memory)
            if self._dynamic_advanced_settings:
                current_settings.update(self._dynamic_advanced_settings)

            # Open modal
            modal = DynamicAdvancedOptionsModal(
                parent=self,
                mode_var=self.dynamic_mode_var,
                current_settings=current_settings,
                on_apply=self._on_advanced_options_applied
            )

            self._log_dynamic_console("Advanced options dialog opened")

        except Exception as e:
            self._log_dynamic_console(f"Error opening advanced options: {e}")

    def _on_advanced_options_applied(self, settings: Dict[str, Any]):
        """Handle applied settings from advanced options modal.

        Updates internal variables based on settings from the Advanced Options modal.
        These settings will be used by the batch analysis thread instead of defaults.

        Args:
            settings: Dict containing all applied settings from modal
        """
        try:
            # Store in session state - these override defaults when analysis runs
            self._dynamic_advanced_settings = settings.copy()

            # Update internal variables (not visible in UI, but used by batch thread)
            self.dynamic_mode_var.set(settings['mode'])
            self.dynamic_timeout_var.set(settings['timeout'])
            self.dynamic_memory_var.set(settings['memory_limit'])

            # Update PID if provided
            if settings.get('attach_pid') is not None:
                self.dynamic_attach_pid_var.set(str(settings['attach_pid']))

            # Update instrumenter flags
            self.crypto_ops_var.set(settings.get('crypto_ops', True))
            self.memory_scan_var.set(settings.get('memory_scan', False))
            self.call_graph_var.set(settings.get('call_graph', False))

            # Update force re-analysis flag
            self.dynamic_force_var.set(settings.get('force', False))

            # Log the applied settings
            self._log_dynamic_console("⚙️ Advanced options applied:")
            self._log_dynamic_console(f"  Mode: {settings['mode']}")
            self._log_dynamic_console(f"  Timeout: {settings['timeout']}s")
            self._log_dynamic_console(f"  Memory Limit: {settings['memory_limit']} MB")

            if settings.get('attach_pid'):
                self._log_dynamic_console(f"  Attach PID: {settings['attach_pid']}")

            self._log_dynamic_console(f"  Instrumenters: crypto_ops={settings['crypto_ops']}, memory_scan={settings['memory_scan']}, call_graph={settings['call_graph']}")

            if settings.get('force'):
                self._log_dynamic_console(f"  Force re-analysis: enabled")

        except Exception as e:
            self._log_dynamic_console(f"Error applying advanced options: {e}")

    def _run_dynamic_analysis(self):
        """Run dynamic analysis in background thread."""
        if self._dynamic_analysis_running:
            return

        # Get case workdir
        try:
            if self._loaded_case_workdir:
                self._case_workdir = self._loaded_case_workdir
            else:
                scan_meta = getattr(self.master, "current_scan_meta", None)
                if not scan_meta or not scan_meta.get("workdir"):
                    self._log_dynamic_console("❌ No case loaded. Please load a case or run Setup first.")
                    return

                self._case_workdir = scan_meta.get("workdir")
        except Exception as e:
            self._log_dynamic_console(f"❌ Error: {e}")
            return

        # UI feedback
        self._dynamic_analysis_running = True
        self.run_dynamic_btn.configure(state="disabled")
        self.cancel_dynamic_btn.configure(state="normal")
        self.open_dynamic_results_btn.configure(state="disabled")
        self.dynamic_progress_bar.set(0)
        self._clear_dynamic_results()
        self._log_dynamic_console("Starting dynamic analysis...")

        # Run in background thread
        self._dynamic_cancel_event = threading.Event()
        t = threading.Thread(target=self._batch_dynamic_analysis_thread, daemon=True)
        t.start()

    def _batch_dynamic_analysis_thread(self):
        """Background thread for batch dynamic analysis of all binaries.

        Uses smart defaults based on execution mode:
        - Spawn mode: 120s timeout, 512MB memory
        - Attach mode: 60s timeout, 256MB memory

        If user has configured Advanced Options, those settings override defaults.
        """
        try:
            from auditor.detectors.dynamic_detection import DynamicRunner, DynamicContext

            # Initialize batch results
            self._dynamic_batch_results = {}

            mode = self.dynamic_mode_var.get()

            # Apply smart defaults based on mode if advanced settings not configured
            if not self._dynamic_advanced_settings:
                # Factory defaults based on mode
                if mode == "spawn":
                    timeout = 120   # Spawn mode: longer timeout for binary startup
                    memory_limit = 512  # Spawn mode: more memory for full binary execution
                    self.after(0, self._log_dynamic_console, "ℹ️ Using default spawn settings (120s, 512MB)")
                else:  # attach mode
                    timeout = 60    # Attach mode: shorter timeout for quick hooking
                    memory_limit = 256  # Attach mode: less memory needed for hooking
                    self.after(0, self._log_dynamic_console, "ℹ️ Using default attach settings (60s, 256MB)")

                # Update internal variables with defaults
                self.dynamic_timeout_var.set(timeout)
                self.dynamic_memory_var.set(memory_limit)
            else:
                # Use settings from Advanced Options modal
                timeout = self.dynamic_timeout_var.get()
                memory_limit = int(self.dynamic_memory_var.get())
                self.after(0, self._log_dynamic_console, "ℹ️ Using advanced options settings")

            force = self.dynamic_force_var.get()

            total_files = len(self._all_file_hashes)

            self.after(0, self._log_dynamic_console, f"Starting batch dynamic analysis of {total_files} binaries...")
            self.after(0, self._log_dynamic_console, f"Mode: {mode}, Timeout: {timeout}s, Memory: {memory_limit}MB")

            # Create runner once (reuse for all files)
            runner = DynamicRunner()

            # Process each file hash
            for index, file_hash in enumerate(self._all_file_hashes, 1):
                # Check for cancellation
                if self._dynamic_cancel_event and self._dynamic_cancel_event.is_set():
                    self.after(0, self._on_dynamic_batch_cancelled, index - 1, total_files)
                    return

                # Update progress
                progress = (index - 0.5) / total_files
                self.after(0, self.dynamic_progress_bar.set, progress)
                self.after(0, self._update_dynamic_batch_progress, index, total_files, file_hash)

                try:
                    # Build context for this specific file
                    hints_path = os.path.join(
                        self._case_workdir, 'analysis', 'static', file_hash, 'hints.json'
                    )

                    # Get attach_pid if in attach mode
                    attach_pid = None
                    if mode == 'attach':
                        try:
                            pid_str = self.dynamic_attach_pid_var.get().strip()
                            if not pid_str:
                                self.after(0, self._log_dynamic_console, f"❌ Attach mode requires Process ID")
                                continue
                            attach_pid = int(pid_str)
                        except ValueError:
                            self.after(0, self._log_dynamic_console, f"❌ Invalid PID: {pid_str}")
                            continue

                    ctx = DynamicContext(
                        file_hash=file_hash,
                        preproc_dir=os.path.join(self._case_workdir, 'preproc', file_hash),
                        hints_path=hints_path,
                        analysis_base=self._case_workdir,
                        mode=mode,
                        timeout=timeout,
                        memory_limit=memory_limit,
                        attach_pid=attach_pid,
                        instrumenters={
                            'crypto_ops': self.crypto_ops_var.get(),
                            'memory_scan': self.memory_scan_var.get(),
                            'call_graph': self.call_graph_var.get()
                        }
                    )

                    # Run analysis for this file
                    result = runner.run(ctx)

                    # Store result
                    self._dynamic_batch_results[file_hash] = result

                    # Log completion
                    if result.is_success():
                        status = "✓ Cached" if result.cached else "✓ Analyzed"
                        self.after(0, self._log_dynamic_console, f"{status} [{index}/{total_files}] {file_hash[:16]}...")
                    else:
                        self.after(0, self._log_dynamic_console, f"⚠️ Incomplete [{index}/{total_files}] {file_hash[:16]}...")

                except Exception as e:
                    # Log error but continue with next file
                    self._dynamic_batch_results[file_hash] = {"error": str(e)}
                    self.after(0, self._log_dynamic_console, f"✗ Error [{index}/{total_files}] {file_hash[:16]}...: {e}")

            # All files processed
            self.after(0, self.dynamic_progress_bar.set, 1.0)
            self.after(0, self._on_dynamic_batch_complete, total_files)

        except Exception as e:
            self.after(0, self._on_dynamic_analysis_error, str(e))

    def _update_dynamic_batch_progress(self, current: int, total: int, file_hash: str):
        """Update progress label with batch status."""
        try:
            percent = int((current / total) * 100)
            self.dynamic_progress_label.configure(
                text=f"Processing {current}/{total} ({percent}%) - {file_hash[:16]}..."
            )
        except Exception:
            pass

    def _cancel_dynamic_analysis(self):
        """Cancel ongoing dynamic analysis."""
        if self._dynamic_cancel_event:
            self._dynamic_cancel_event.set()
        self._log_dynamic_console("Cancellation requested...")

    def _on_dynamic_analysis_error(self, error_msg: str):
        """Handle dynamic analysis error."""
        self._dynamic_analysis_running = False
        self.run_dynamic_btn.configure(state="normal")
        self.cancel_dynamic_btn.configure(state="disabled")
        self.dynamic_progress_bar.set(0)
        self._log_dynamic_console(f"❌ Error: {error_msg}")

    def _on_dynamic_batch_complete(self, total_files: int):
        """Handle successful batch dynamic analysis completion."""
        try:
            self._dynamic_analysis_running = False
            self.run_dynamic_btn.configure(state="normal")
            self.cancel_dynamic_btn.configure(state="disabled")
            self.open_dynamic_results_btn.configure(state="normal")
            self.dynamic_progress_bar.set(1.0)
            self.dynamic_progress_label.configure(text=f"Completed {total_files}/{total_files}")

            # Count successes and errors
            successes = sum(1 for r in self._dynamic_batch_results.values() if isinstance(r, dict) and "error" not in r or hasattr(r, 'is_success') and r.is_success())
            errors = total_files - successes
            cached = sum(1 for r in self._dynamic_batch_results.values() if hasattr(r, 'cached') and r.cached)

            if errors > 0:
                self._log_dynamic_console(f"Batch analysis completed with {errors} error(s)")
            else:
                self._log_dynamic_console(f"Batch analysis completed successfully!")

            # Display aggregated results
            self._display_dynamic_batch_results()

        except Exception as e:
            self._log_dynamic_console(f"Error in batch completion: {e}")

    def _on_dynamic_batch_cancelled(self, processed: int, total: int):
        """Handle batch dynamic analysis cancellation."""
        try:
            self._dynamic_analysis_running = False
            self.run_dynamic_btn.configure(state="normal")
            self.cancel_dynamic_btn.configure(state="disabled")
            self.dynamic_progress_bar.set(0)
            self.dynamic_progress_label.configure(text="")

            self._log_dynamic_console(f"Batch analysis cancelled by user")

            # Display partial results if any
            if self._dynamic_batch_results:
                self._display_dynamic_batch_results()

        except Exception as e:
            self._log_dynamic_console(f"Error in cancellation handler: {e}")

    def _display_dynamic_batch_results(self):
        """Display aggregated results from dynamic batch analysis."""
        try:
            # Summary
            summary_lines = []
            summary_lines.append("=" * 60)
            summary_lines.append("DYNAMIC ANALYSIS SUMMARY")
            summary_lines.append("=" * 60)
            summary_lines.append(f"Total Binaries: {len(self._dynamic_batch_results)}")

            successful = sum(1 for r in self._dynamic_batch_results.values() if not isinstance(r, dict) or "error" not in r)
            errors = len(self._dynamic_batch_results) - successful
            cached = sum(1 for r in self._dynamic_batch_results.values() if hasattr(r, 'cached') and r.cached)

            summary_lines.append(f"Successful: {successful}")
            summary_lines.append(f"Errors: {errors}")
            summary_lines.append(f"Cached: {cached}")
            summary_lines.append("")
            summary_lines.append("Per-File Summary:")
            summary_lines.append("-" * 60)

            for file_hash, result in self._dynamic_batch_results.items():
                short_hash = file_hash[:16]
                if isinstance(result, dict) and "error" in result:
                    summary_lines.append(f"✗ {short_hash}... - ERROR: {result['error']}")
                elif hasattr(result, 'incomplete') and result.incomplete:
                    summary_lines.append(f"⚠️ {short_hash}... - Incomplete: {result.incomplete_reason}")
                elif hasattr(result, 'summary') and result.summary:
                    crypto_calls = result.summary.get('total_crypto_calls', 0)
                    summary_lines.append(f"✓ {short_hash}... - {crypto_calls} crypto calls detected")
                else:
                    summary_lines.append(f"✓ {short_hash}... - Completed")

            self.dynamic_summary_text.delete("1.0", "end")
            self.dynamic_summary_text.insert("1.0", "\n".join(summary_lines))

            # Aggregate findings from all traces
            all_findings = []
            trace_count = 0

            for file_hash, result in self._dynamic_batch_results.items():
                if isinstance(result, dict) and "error" in result:
                    continue

                if hasattr(result, 'trace_path') and result.trace_path and os.path.exists(result.trace_path):
                    try:
                        with open(result.trace_path, 'r', encoding='utf-8') as f:
                            for line in f:
                                if line.strip():
                                    trace_count += 1
                                    try:
                                        event = json.loads(line)
                                        if event.get('type') == 'crypto_call':
                                            all_findings.append({
                                                'file_hash': file_hash,
                                                'function': event.get('function'),
                                                'module': event.get('module'),
                                                'timestamp': event.get('timestamp')
                                            })
                                    except json.JSONDecodeError:
                                        pass
                    except Exception:
                        pass

            # Display aggregated findings
            output_lines = []
            output_lines.append("=" * 80)
            output_lines.append(f"AGGREGATED FINDINGS ({len(all_findings)} crypto calls from {successful} binaries)")
            output_lines.append("=" * 80)
            output_lines.append("")

            if not all_findings:
                output_lines.append("No cryptographic operations detected during dynamic analysis.")
            else:
                # Group by function
                functions = {}
                for finding in all_findings:
                    key = f"{finding.get('module')}!{finding.get('function')}"
                    if key not in functions:
                        functions[key] = 0
                    functions[key] += 1

                for func, count in sorted(functions.items(), key=lambda x: x[1], reverse=True):
                    output_lines.append(f"• {func}: {count} calls")

            self.dynamic_traces_text.delete("1.0", "end")
            self.dynamic_traces_text.insert("1.0", "\n".join(output_lines))

            self._log_dynamic_console("Results displayed successfully")

        except Exception as e:
            self._log_dynamic_console(f"Error displaying batch results: {e}")

    def _open_dynamic_results_folder(self):
        """Open the dynamic analysis results folder in file explorer."""
        try:
            import subprocess
            import platform

            workdir = self._case_workdir or self._loaded_case_workdir
            if not workdir:
                self._log_dynamic_console("❌ No case loaded")
                return

            workdir_path = Path(workdir)
            analysis_dir = workdir_path / "analysis" / "dynamic"

            if not analysis_dir.exists():
                self._log_dynamic_console("❌ No dynamic analysis results found")
                return

            # Open folder in file explorer (cross-platform)
            if platform.system() == "Windows":
                subprocess.run(["explorer", str(analysis_dir)], check=False)
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", str(analysis_dir)], check=False)
            else:  # Linux
                subprocess.run(["xdg-open", str(analysis_dir)], check=False)

            self._log_dynamic_console(f"Opened results folder: {analysis_dir}")

        except Exception as e:
            self._log_dynamic_console(f"❌ Failed to open folder: {e}")

    def _clear_dynamic_results(self):
        """Clear all dynamic result displays."""
        try:
            self.dynamic_summary_text.delete("1.0", "end")
            self.dynamic_traces_text.delete("1.0", "end")
            self.dynamic_callgraph_text.delete("1.0", "end")
            self.dynamic_console_text.delete("1.0", "end")
        except Exception:
            pass

    def _log_dynamic_console(self, message: str):
        """Append message to dynamic analysis console log."""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.dynamic_console_text.insert("end", f"[{timestamp}] {message}\n")
            self.dynamic_console_text.see("end")
        except Exception:
            pass

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

    def _open_static_advanced_options(self):
        """Open advanced options dialog for static analysis (stub)."""
        # TODO: Implement full advanced options dialog with tabs for:
        # - Ghidra timeout settings
        # - Policy configuration
        # - Cache options
        # - Export settings
        # For now, show a placeholder message
        from tkinter import messagebox
        messagebox.showinfo(
            "Advanced Options",
            "Advanced options configuration coming soon!\n\n"
            "This will include:\n"
            "• Ghidra timeout and policy settings\n"
            "• Cache and export options\n"
            "• Performance tuning\n"
            "• Diagnostic controls"
        )

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
            
            # Hide case summary in standalone mode if no case is loaded
            if self._standalone_mode and not self._loaded_case_workdir:
                self.summary_container.grid_remove()
            else:
                # Show it if coming from setup page
                self.summary_container.grid()
            
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
        self.open_results_btn.configure(state="disabled")
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
        try:
            from auditor.detectors.static_detection.runner import StaticRunner
            from auditor.detectors.static_detection.context import RunContext, ToolVersions

            # Initialize batch results
            self._batch_results = {}
            self._current_batch_index = 0
            
            profile = self.profile_var.get()
            force = self.force_var.get()
            
            total_files = len(self._all_file_hashes)
            
            self.after(0, self._log_console, f"Starting batch analysis of {total_files} binaries...")
            self.after(0, self._log_console, f"Profile: {profile}, Force: {force}")

            # Create runner once (reuse for all files)
            runner = StaticRunner()

            # Process each file hash
            for index, file_hash in enumerate(self._all_file_hashes, 1):
                # Check for cancellation
                if self._cancel_event and self._cancel_event.is_set():
                    self.after(0, self._on_batch_cancelled, index - 1, total_files)
                    return

                self._current_batch_index = index
                
                # Update progress
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
                        tool_versions=ToolVersions()
                    )

                    # Run analysis for this file
                    result = runner.run(ctx)
                    
                    # Store result
                    self._batch_results[file_hash] = result
                    
                    # Log completion
                    status = "✓ Cached" if result.cached else "✓ Analyzed"
                    self.after(0, self._log_console, f"{status} [{index}/{total_files}] {file_hash[:16]}...")
                    
                except Exception as e:
                    # Log error but continue with next file
                    self._batch_results[file_hash] = {"error": str(e)}
                    self.after(0, self._log_console, f"✗ Error [{index}/{total_files}] {file_hash[:16]}...: {e}")

            # All files processed
            self.after(0, self.progress_bar.set, 1.0)
            self.after(0, self._on_batch_complete, total_files)

        except Exception as e:
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
            else:
                self.dynamic_frame.pack(fill="both", expand=True, pady=(0, 10))

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
                self.dynamic_frame.pack_forget()
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
