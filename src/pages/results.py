"""Results Page for displaying analysis results.

Provides a professional three-column layout showing:
- Left: Navigation, file info, metadata
- Center: Tabbed interface with analysis results
- Right: Visualizations and metrics

Supports role-based access control (free vs premium users).
"""

from enum import Enum
import logging
import threading
from pathlib import Path
from typing import Optional, Callable

import customtkinter as ctk

from pages.results_model import ResultsDataModel
from pages.results_tabs import (
    OverviewTab, StaticTab, ExportTab
)
from pages.results_charts import VisualizationPanel
from ui.results_components import (
    MetricsCard, StatusIndicator, PremiumBadge,
    LockedFeatureView, SectionHeader, COLORS
)
from ui.account_bubble import AccountBubble

logger = logging.getLogger(__name__)


class ResultAvailability(str, Enum):
    """States for result availability."""
    AVAILABLE = "available"
    NOT_ANALYZED = "not_analyzed"
    IN_PROGRESS = "in_progress"
    FAILED = "failed"
    FILE_NOT_FOUND = "file_not_found"


class ResultsPage(ctk.CTkFrame):
    """
    Results Page: Display analysis results to users.

    Three-column layout:
    - Left (20%): Navigation, file info, status
    - Center (50%): Tabbed content area
    - Right (30%): Metrics and visualizations

    Displays static analysis results.
    """

    TAB_NAMES = {
        'overview': ('Overview', False),
        'static': ('Static Analysis', False),
        'export': ('Export & Reports', False),
    }

    def __init__(self, parent, switch_page_callback: Callable):
        """
        Initialize Results Page.

        Args:
            parent: Parent CTk window
            switch_page_callback: Callback to switch pages
        """
        super().__init__(parent, fg_color=COLORS['bg'])
        self.parent = parent
        self.switch_page = switch_page_callback

        # State
        self.case_path: Optional[str] = None
        self.file_hash: Optional[str] = None
        self.data_model: Optional[ResultsDataModel] = None
        self.current_tab = 'overview'
        self._current_gate: Optional[LockedFeatureView] = None

        # Standalone mode state
        self._standalone_mode = False
        self._loaded_case_workdir: Optional[str] = None
        self._available_cases = {}  # Maps display name to workdir path
        self._available_files = {}  # Maps file hash to file info for current case
        self._selected_file_hash: Optional[str] = None

        # Async loading state
        self._tab_loading_thread: Optional[threading.Thread] = None
        self._loading_tab_name: Optional[str] = None
        self._tabs_loaded = set()  # Tracks which tabs have been loaded
        self._tabs_lock = threading.Lock()  # Thread safety for _tabs_loaded

        # Create layout
        try:
            self._create_layout()
            self._create_tabs()

            # Account bubble (top-right, same pattern as Setup page)
            self._acct = AccountBubble(self)
            self._acct.mount(top_right_of=self)

            logger.info("ResultsPage initialized successfully")
        except Exception as e:
            logger.exception(f"Failed to initialize ResultsPage: {e}")
            raise



    # ======== Layout Creation ========

    def _create_layout(self):
        """Create three-column layout."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Load case frame (shown only in standalone mode, hidden by default)
        self.load_case_frame = ctk.CTkFrame(self, fg_color=COLORS['bg'])
        self.load_case_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.load_case_frame.grid_columnconfigure(0, weight=1)
        self._build_load_case_ui(self.load_case_frame)
        self.load_case_frame.grid_remove()  # Hidden by default

        # Main results layout (shown in pipeline mode or after loading in standalone)
        self.results_container = ctk.CTkFrame(self, fg_color=COLORS['bg'])
        self.results_container.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.results_container.grid_rowconfigure(0, weight=1)
        self.results_container.grid_columnconfigure(0, weight=0)  # Left panel: 20%
        self.results_container.grid_columnconfigure(1, weight=1)  # Center: 50%
        self.results_container.grid_columnconfigure(2, weight=0)  # Right panel: 30%

        # Left panel
        self.left_panel = ctk.CTkFrame(self.results_container, fg_color=COLORS['card_bg'], width=240)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.left_panel.grid_propagate(False)
        self._create_left_panel()

        # Center panel (tabs)
        self.center_panel = ctk.CTkFrame(self.results_container, fg_color=COLORS['bg'])
        self.center_panel.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.center_panel.grid_rowconfigure(1, weight=1)
        self.center_panel.grid_columnconfigure(0, weight=1)
        self._create_center_panel()

        # Right panel
        self.right_panel = ctk.CTkFrame(self.results_container, fg_color=COLORS['card_bg'], width=280)
        self.right_panel.grid(row=0, column=2, sticky="nsew", padx=0, pady=0)
        self.right_panel.grid_propagate(False)
        self._create_right_panel()

    def _build_load_case_ui(self, parent: ctk.CTkFrame):
        """Build the load case UI for standalone mode."""
        parent.grid_columnconfigure(0, weight=1)

        # Title
        title_label = ctk.CTkLabel(
            parent,
            text="Load Analysis Results",
            font=("Roboto", 18, "bold")
        )
        title_label.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))

        description = ctk.CTkLabel(
            parent,
            text="No active case detected. Load a case and select a file to view analysis results.",
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
            text="Case Workdir:",
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

        # File selection
        ctk.CTkLabel(
            selection_frame,
            text="Analyzed Files:",
            font=("Roboto", 12)
        ).grid(row=1, column=0, sticky="nw", pady=(15, 5))

        files_frame = ctk.CTkFrame(selection_frame)
        files_frame.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(15, 5))
        files_frame.grid_columnconfigure(0, weight=1)

        # Scrollable list of files
        self.files_listbox = ctk.CTkTextbox(
            files_frame,
            height=120,
            font=("Consolas", 10)
        )
        self.files_listbox.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.files_listbox.configure(state="disabled")

        refresh_btn = ctk.CTkButton(
            files_frame,
            text="🔄 Refresh Files",
            width=150,
            command=self._refresh_file_list
        )
        refresh_btn.grid(row=1, column=0, pady=(5, 10))

            # Action buttons
        action_frame = ctk.CTkFrame(parent, fg_color="transparent")
        action_frame.grid(row=3, column=0, sticky="ew", padx=15, pady=(0, 15))

        self.load_case_btn = ctk.CTkButton(
            action_frame,
            text="Load Case & File",
            width=150,
            height=40,
            font=("Roboto", 14, "bold"),
            fg_color="#4a9eff",
            hover_color="#357abd",
            command=self._load_selected_case,
        )
        self.load_case_btn.pack(side="left", padx=5)

        # Status for load case
        self.load_case_status = ctk.CTkLabel(
            action_frame,
            text="",
            font=("Roboto", 11),
        )
        self.load_case_status.pack(side="left", padx=15)

        # Back to Landing (standalone Results, similar to standalone Detectors)
        back_btn = ctk.CTkButton(
            action_frame,
            text="← Back to Landing",
            width=160,
            height=32,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["card_bg"],
            text_color=COLORS["text"],
            command=lambda: self.switch_page("landing"),
        )
        back_btn.pack(side="right", padx=5)


    def _create_left_panel(self):
        """Create left panel with navigation and info."""
        self.left_panel.grid_rowconfigure(2, weight=1)
        self.left_panel.grid_columnconfigure(0, weight=1)

        # File info card
        self._create_file_info_card()

        # Status card
        self._create_status_card()

        # Spacer
        spacer = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        spacer.grid(row=2, column=0, sticky="nsew")

        # Back button
        back_btn = ctk.CTkButton(
            self.left_panel,
            text="← Back to Landing",
            command=lambda: self.switch_page("landing"),
            fg_color=COLORS['primary'],
            hover_color=COLORS['primary_hover'],
            height=36
        )
        back_btn.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 12))

    def _create_file_info_card(self):
        """Create file information card."""
        card = ctk.CTkFrame(
            self.left_panel,
            fg_color=COLORS['bg'],
            corner_radius=8
        )
        card.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            card,
            text="File Information",
            font=("Roboto", 11, "bold"),
            text_color=COLORS['text']
        )
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))

        # File name
        self.file_name_label = ctk.CTkLabel(
            card,
            text="File: -",
            font=("Roboto", 9),
            text_color=COLORS['text_secondary'],
            wraplength=220
        )
        self.file_name_label.grid(row=1, column=0, sticky="ew", padx=8, pady=2)

        # Hash (truncated)
        self.file_hash_label = ctk.CTkLabel(
            card,
            text="Hash: -",
            font=("Roboto", 8),
            text_color=COLORS['text_secondary'],
            wraplength=220
        )
        self.file_hash_label.grid(row=2, column=0, sticky="ew", padx=8, pady=2)

        # Size
        self.file_size_label = ctk.CTkLabel(
            card,
            text="Size: -",
            font=("Roboto", 9),
            text_color=COLORS['text_secondary']
        )
        self.file_size_label.grid(row=3, column=0, sticky="ew", padx=8, pady=(2, 8))

    def _create_status_card(self):
        """Create status information card."""
        card = ctk.CTkFrame(
            self.left_panel,
            fg_color=COLORS['bg'],
            corner_radius=8
        )
        card.grid(row=1, column=0, sticky="ew", padx=12, pady=8)
        card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            card,
            text="Analysis Status",
            font=("Roboto", 11, "bold"),
            text_color=COLORS['text']
        )
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))

        # Static status
        self.static_status = StatusIndicator(
            card,
            status='pending',
            label='Static Analysis'
        )
        self.static_status.grid(row=1, column=0, sticky="ew", padx=8, pady=4)


        # Analysis date
        self.analysis_date_label = ctk.CTkLabel(
            card,
            text="Date: -",
            font=("Roboto", 8),
            text_color=COLORS['text_secondary']
        )
        self.analysis_date_label.grid(row=3, column=0, sticky="ew", padx=8, pady=(4, 8))


    def _create_center_panel(self):
        """Create center panel with tab bar and content."""
        # Tab bar
        tab_bar = ctk.CTkFrame(self.center_panel, fg_color=COLORS['card_bg'], height=40)
        tab_bar.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
        tab_bar.grid_propagate(False)
        tab_bar.grid_columnconfigure(0, weight=1)

        # Tab buttons
        self.tab_buttons = {}
        for i, (tab_key, (tab_label, _)) in enumerate(self.TAB_NAMES.items()):
            btn = ctk.CTkButton(
                tab_bar,
                text=tab_label,
                command=lambda tk=tab_key: self._switch_tab(tk),
                width=80,
                height=32,
                fg_color="transparent",
                text_color=COLORS['text'],
                border_color=COLORS['border'],
                border_width=1,
                font=("Roboto", 10),
                anchor="center"
            )
            btn.grid(row=0, column=i, padx=2, pady=4, sticky="ew")
            self.tab_buttons[tab_key] = btn

        # Tab content frame
        self.tab_content = ctk.CTkFrame(self.center_panel, fg_color=COLORS['bg'])
        self.tab_content.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.tab_content.grid_rowconfigure(0, weight=1)
        self.tab_content.grid_columnconfigure(0, weight=1)

        # Loading indicator (hidden by default)
        self.loading_indicator = ctk.CTkFrame(self.tab_content, fg_color=COLORS['bg'])
        self.loading_indicator.grid(row=0, column=0, sticky="nsew")
        self.loading_indicator.grid_rowconfigure(0, weight=1)
        self.loading_indicator.grid_columnconfigure(0, weight=1)

        # Loading label
        loading_label = ctk.CTkLabel(
            self.loading_indicator,
            text="Loading tab data...",
            font=("Roboto", 14),
            text_color=COLORS['text_secondary']
        )
        loading_label.grid(row=0, column=0)

        # Hide by default
        self.loading_indicator.grid_remove()

    def _create_right_panel(self):
        """Create right panel with visualizations."""
        self.right_panel.grid_rowconfigure(0, weight=1)
        self.right_panel.grid_columnconfigure(0, weight=1)

        # Create visualization panel
        self.visualization_panel = VisualizationPanel(self.right_panel)
        self.visualization_panel.grid(row=0, column=0, sticky="nsew")

    def _create_tabs(self):
        """Create tab instances."""
        self.tabs = {
            'overview': OverviewTab(self.tab_content),
            'static': StaticTab(self.tab_content),
            'export': ExportTab(self.tab_content),
        }

    # ======== Tab Management ========

    def _switch_tab(self, tab_name: str):
        """Switch to a specific tab (async loading)."""
        # Check access for premium tabs
        if self.TAB_NAMES[tab_name][1]:  # is_premium
            if not self._is_user_premium():
                self._show_premium_gate(tab_name)
                return

        self.current_tab = tab_name

        # Hide premium gate if visible
        if self._current_gate and self._current_gate.winfo_exists():
            self._current_gate.grid_remove()

        # Hide all tab content and show loading
        for name, tab in self.tabs.items():
            if tab.winfo_exists():
                tab.grid_remove()

        # Check if tab is already loaded
        with self._tabs_lock:
            tab_already_loaded = tab_name in self._tabs_loaded

        if tab_already_loaded:
            # Tab is already loaded, show it immediately
            tab = self.tabs[tab_name]
            if tab.winfo_exists():
                self.loading_indicator.grid_remove()
                tab.grid(row=0, column=0, sticky="nsew")
            self._update_tab_button_styles()
        else:
            # Tab not loaded yet, show loading indicator and load in background
            self.loading_indicator.grid()
            self._loading_tab_name = tab_name

            # Cancel any existing loading thread
            if self._tab_loading_thread and self._tab_loading_thread.is_alive():
                # Thread is still running, don't create another one
                return

            # Spawn background thread to load tab data
            self._tab_loading_thread = threading.Thread(
                target=self._load_tab_background,
                args=(tab_name,),
                daemon=True
            )
            self._tab_loading_thread.start()

    def _load_tab_background(self, tab_name: str):
        """Load tab data in background thread."""
        try:
            if not self.data_model:
                self.after(0, lambda: self._on_tab_load_complete(tab_name, False))
                return

            tab = self.tabs[tab_name]

            # Call load_data synchronously in background thread
            tab.load_data(self.data_model)

            # Mark tab as loaded
            with self._tabs_lock:
                self._tabs_loaded.add(tab_name)

            # Update UI on main thread
            self.after(0, lambda: self._on_tab_load_complete(tab_name, True))

        except Exception as e:
            logger.exception(f"Error loading tab {tab_name}: {e}")
            self.after(0, lambda: self._on_tab_load_complete(tab_name, False))

    def _on_tab_load_complete(self, tab_name: str, success: bool):
        """Called when tab loading completes (on main thread)."""
        try:
            if not success:
                logger.error(f"Failed to load tab {tab_name}")
                self.loading_indicator.grid()
                return

            # Hide loading indicator
            self.loading_indicator.grid_remove()

            # Show the loaded tab
            if tab_name == self.current_tab:
                tab = self.tabs[tab_name]
                if tab.winfo_exists():
                    tab.grid(row=0, column=0, sticky="nsew")

            # Update tab button styles
            self._update_tab_button_styles()

        except Exception as e:
            logger.exception(f"Error completing tab load for {tab_name}: {e}")

    def _update_tab_button_styles(self):
        """Update tab button appearance based on current tab."""
        for tab_key, btn in self.tab_buttons.items():
            if tab_key == self.current_tab:
                btn.configure(
                    fg_color=COLORS['primary'],
                    border_width=0
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    border_width=1
                )

    # ======== Data Loading ========

    def load(self, case_path: str, file_hash: str):
        """
        Load analysis results.

        Args:
            case_path: Path to the case folder
            file_hash: SHA256 hash of the analyzed file

        Raises:
            Exception: If data loading or UI update fails
        """
        try:
            self.case_path = case_path
            self.file_hash = file_hash

            # Load data
            self.data_model = ResultsDataModel(case_path, file_hash)
            self.data_model.load_all()

            # Update UI
            self._update_file_info()
            self._update_status()
            self._update_metrics()
            self._switch_tab('overview')

            logger.info(f"Loaded results for {file_hash} from {case_path}")
        except Exception as e:
            logger.exception(f"Failed to load results: {e}")
            raise

    def _update_file_info(self):
        """Update file information display."""
        if not self.data_model:
            return

        # File name
        file_name = self.data_model.metadata.file_name or "Unknown"
        self.file_name_label.configure(text=f"File: {file_name}")

        # Hash (truncated)
        hash_short = self.file_hash[:16] if self.file_hash else "-"
        self.file_hash_label.configure(text=f"Hash: {hash_short}...")

        # Size
        size = self.data_model.metadata.file_size or 0
        if size:
            size_mb = size / (1024 * 1024)
            self.file_size_label.configure(text=f"Size: {size_mb:.2f} MB")
        else:
            self.file_size_label.configure(text="Size: -")

    def _update_status(self):
        """Update analysis status display."""
        if not self.data_model:
            return

        # Static status
        static_status = 'completed' if self.data_model.has_static_results() else 'failed'
        self.static_status.configure(
            fg_color=COLORS['card_bg'],
            border_width=0
        )
        # Update status indicator (would need to recreate or enhance)


        # Analysis date
        date_str = self.data_model.metadata.analysis_date or "-"
        self.analysis_date_label.configure(text=f"Date: {date_str[:10]}")

    def _update_metrics(self):
        """Update visualizations in right panel."""
        if self.data_model:
            self.visualization_panel.update_charts(self.data_model)

    # ======== Access Control ========

    def _is_user_premium(self) -> bool:
        """Check if current user is premium."""
        return getattr(self.parent, 'current_user_role', 'free') == 'premium'

    def _show_premium_gate(self, feature_name: str):
        """Show premium gate for locked feature."""
        # Hide all tabs instead of destroying them
        for tab in self.tabs.values():
            tab.grid_remove()

        # Destroy previous gate if it exists
        if hasattr(self, '_current_gate') and self._current_gate:
            try:
                self._current_gate.destroy()
            except Exception:
                pass

        # Create and show new locked view
        self._current_gate = LockedFeatureView(
            self.tab_content,
            feature_name=feature_name,
            on_upgrade=self._open_upgrade_page
        )
        self._current_gate.grid(row=0, column=0, sticky="nsew")

    def _open_upgrade_page(self):
        """Open upgrade/premium page (placeholder)."""
        logger.info("Upgrade clicked - would open premium page")
        # In future: self.switch_page("premium")

    def reset_pipeline_state(self):
        """
        Clear previous pipeline results so that the next entry opens
        in standalone 'Load Analysis Results' mode.
        """
        try:
            # Drop pipeline identifiers
            self.case_path = None
            self.file_hash = None
            self.data_model = None

            # Force standalone semantics
            self._standalone_mode = True
            self._loaded_case_workdir = None
            self._available_files = {}
            self._selected_file_hash = None

            # Tabs will be lazily reloaded
            with self._tabs_lock:
                self._tabs_loaded.clear()
            self.current_tab = "overview"
        except Exception:
            pass


    # ======== On Page Enter ========

    def on_enter(self):
        """Called when page is displayed."""
        logger.info("ResultsPage: on_enter called")

        # Check if we have case_path and file_hash already set (from detectors pipeline)
        if self.case_path and self.file_hash:
            # Coming from detectors page - normal pipeline flow
            self._standalone_mode = False
            self._loaded_case_workdir = None

            # Hide load case UI
            self.load_case_frame.grid_remove()

            # Show results UI
            self.results_container.grid()

            # Refresh data
            if self.data_model:
                self._update_metrics()

            logger.info(f"Pipeline mode: Loaded case {self.case_path}, file {self.file_hash[:16]}...")
        else:
            # Standalone mode - show load case UI
            self._standalone_mode = True
            self._loaded_case_workdir = None
            self.case_path = None
            self.file_hash = None

            # Hide results UI
            self.results_container.grid_remove()

            # Show load case UI
            self.load_case_frame.grid()

            # Try to auto-populate workdir if possible
            try:
                from auditor.setup_flow.output import get_default_workdir
                default_wd = str(get_default_workdir())
                self.case_workdir_entry.delete(0, "end")
                self.case_workdir_entry.insert(0, default_wd)
            except Exception:
                pass

            logger.info("Standalone mode: No active case. Please load a case and select a file.")
                    # (keep your existing logger above this if you like)

        # --- Refresh Account Bubble (non-fatal if anything fails) ---
        try:
            profile = None
            app = self.parent
            if hasattr(app, "fetch_user_profile"):
                try:
                    profile = app.fetch_user_profile()
                except Exception:
                    profile = None

            if hasattr(self, "_acct") and hasattr(self._acct, "refresh"):
                self._acct.refresh(profile)
        except Exception as e:
            logger.warning(f"AccountBubble refresh error on ResultsPage: {e}")


    def on_resize(self, width: int, height: int):
        """Called when window is resized."""
        pass

    # ======== Standalone Mode: Case/File Loading ========

    def _browse_case_workdir(self):
        """Browse for a case workdir."""
        try:
            from tkinter import filedialog
            workdir = filedialog.askdirectory(
                title="Select Case Workdir",
                initialdir=self.case_workdir_entry.get() or "."
            )
            if workdir:
                self.case_workdir_entry.delete(0, "end")
                self.case_workdir_entry.insert(0, workdir)
                # Auto-refresh files when workdir changes
                self._refresh_file_list()
        except Exception as e:
            self._set_load_case_status(f"❌ Browse error: {e}", error=True)
            logger.exception(f"Browse error: {e}")

    def _refresh_file_list(self):
        """Scan the analysis directory for available files with results."""
        try:
            workdir = self.case_workdir_entry.get().strip()
            if not workdir:
                self._set_load_case_status("⚠️ Please enter a workdir first", error=True)
                return

            workdir_path = Path(workdir)
            if not workdir_path.exists():
                self._set_load_case_status(f"⚠️ Workdir not found: {workdir}", error=True)
                return

            # Look for analysis/static directory
            analysis_dir = workdir_path / "analysis"
            if not analysis_dir.exists():
                self._set_load_case_status("⚠️ No analysis directory found", error=True)
                return

            # Collect all files with analysis results
            self._available_files = {}
            files_found = []

            # Check static results
            static_dir = analysis_dir / "static"
            if static_dir.exists():
                for hash_dir in static_dir.iterdir():
                    if hash_dir.is_dir():
                        file_hash = hash_dir.name
                        results_file = hash_dir / "static_results.json"
                        if results_file.exists():
                            self._available_files[file_hash] = {
                                "workdir": str(workdir_path),
                                "has_static": True,
                            }
                            files_found.append(f"📄 {file_hash[:16]}... (static)")


            # Update files listbox
            self.files_listbox.configure(state="normal")
            self.files_listbox.delete("1.0", "end")

            if files_found:
                for file_info in files_found:
                    self.files_listbox.insert("end", file_info + "\n")
                self._set_load_case_status(f"✓ Found {len(self._available_files)} file(s)", error=False)
            else:
                self.files_listbox.insert("end", "No analyzed files found in this case.\n")
                self._set_load_case_status("⚠️ No analyzed files found", error=True)

            self.files_listbox.configure(state="disabled")

        except Exception as e:
            self._set_load_case_status(f"❌ Scan error: {e}", error=True)
            logger.exception(f"File list refresh error: {e}")

    def _load_selected_case(self):
        """Load the selected case and file."""
        try:
            workdir = self.case_workdir_entry.get().strip()

            if not workdir:
                self._set_load_case_status("⚠️ Please enter a workdir", error=True)
                return

            if not self._available_files:
                self._set_load_case_status("⚠️ No files available. Click Refresh first.", error=True)
                return

            # Get the first available file (user can select later)
            file_hash = list(self._available_files.keys())[0]

            # Validate workdir structure
            workdir_path = Path(workdir)
            analysis_dir = workdir_path / "analysis"

            if not analysis_dir.exists():
                self._set_load_case_status("⚠️ Invalid case structure: missing analysis directory", error=True)
                return

            # Load the case and file
            self._loaded_case_workdir = str(workdir_path)
            self.case_path = str(workdir_path)
            self.file_hash = file_hash
            self._standalone_mode = True

            # Hide load case UI
            self.load_case_frame.grid_remove()

            # Show results UI
            self.results_container.grid()

            # Load and display results
            try:
                self.load(self.case_path, self.file_hash)
                self._set_load_case_status(f"✅ Loaded: {file_hash[:16]}...", error=False)
                logger.info(f"Standalone mode: Loaded case {self.case_path}, file {file_hash[:16]}...")
            except Exception as load_err:
                self._set_load_case_status(f"❌ Failed to load results: {load_err}", error=True)
                logger.exception(f"Results load error: {load_err}")
                # Show the load case UI again on error
                self.results_container.grid_remove()
                self.load_case_frame.grid()

        except Exception as e:
            self._set_load_case_status(f"❌ Load error: {e}", error=True)
            logger.exception(f"Case load error: {e}")

    def _set_load_case_status(self, message: str, error: bool = False):
        """Update load case status label."""
        try:
            color = "#f88" if error else "#8f8"
            self.load_case_status.configure(text=message, text_color=color)
        except Exception:
            pass
