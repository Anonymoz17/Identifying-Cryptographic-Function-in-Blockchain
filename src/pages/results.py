"""Results Page for displaying analysis results.

Provides a professional three-column layout showing:
- Left: Navigation, file info, metadata
- Center: Tabbed interface with analysis results
- Right: Visualizations and metrics

Supports role-based access control (free vs premium users).
"""

import os
import logging
from pathlib import Path
from typing import Optional, Callable
from enum import Enum

import customtkinter as ctk

from pages.results_model import ResultsDataModel
from pages.results_tabs import (
    OverviewTab, StaticTab, DynamicTab, ExportTab
)
from pages.results_charts import VisualizationPanel
from ui.results_components import (
    MetricsCard, StatusIndicator, PremiumBadge,
    LockedFeatureView, SectionHeader, COLORS
)

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

    Supports free users (static only) and premium users (static + dynamic).
    """

    TAB_NAMES = {
        'overview': ('Overview', False),
        'static': ('Static Analysis', False),
        'dynamic': ('Dynamic Analysis', False),  # All tabs free for now
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

        # Create layout
        try:
            self._create_layout()
            self._create_tabs()
            logger.info("ResultsPage initialized successfully")
        except Exception as e:
            logger.exception(f"Failed to initialize ResultsPage: {e}")
            raise

    # ======== Layout Creation ========

    def _create_layout(self):
        """Create three-column layout."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)  # Left panel: 20%
        self.grid_columnconfigure(1, weight=1)  # Center: 50%
        self.grid_columnconfigure(2, weight=0)  # Right panel: 30%

        # Left panel
        self.left_panel = ctk.CTkFrame(self, fg_color=COLORS['card_bg'], width=240)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.left_panel.grid_propagate(False)
        self._create_left_panel()

        # Center panel (tabs)
        self.center_panel = ctk.CTkFrame(self, fg_color=COLORS['bg'])
        self.center_panel.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.center_panel.grid_rowconfigure(1, weight=1)
        self.center_panel.grid_columnconfigure(0, weight=1)
        self._create_center_panel()

        # Right panel
        self.right_panel = ctk.CTkFrame(self, fg_color=COLORS['card_bg'], width=280)
        self.right_panel.grid(row=0, column=2, sticky="nsew", padx=0, pady=0)
        self.right_panel.grid_propagate(False)
        self._create_right_panel()

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
            text="← Back to Detectors",
            command=lambda: self.switch_page("detectors"),
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

        # Dynamic status
        self.dynamic_status = StatusIndicator(
            card,
            status='pending',
            label='Dynamic Analysis'
        )
        self.dynamic_status.grid(row=2, column=0, sticky="ew", padx=8, pady=4)

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
            'dynamic': DynamicTab(self.tab_content, on_continue_analysis=self._continue_dynamic_analysis),
            'export': ExportTab(self.tab_content),
        }

    def _continue_dynamic_analysis(self):
        """Handle continue dynamic analysis button click."""
        # Switch back to detectors page to run analysis again
        logger.info("User clicked continue dynamic analysis button")
        self.switch_page("detectors")

    # ======== Tab Management ========

    def _switch_tab(self, tab_name: str):
        """Switch to a specific tab."""
        # Check access for premium tabs
        if self.TAB_NAMES[tab_name][1]:  # is_premium
            if not self._is_user_premium():
                self._show_premium_gate(tab_name)
                return

        self.current_tab = tab_name

        # Hide premium gate if visible
        if self._current_gate and self._current_gate.winfo_exists():
            self._current_gate.grid_remove()

        # Show/hide tabs
        for name, tab in self.tabs.items():
            if name == tab_name:
                # Validate tab still exists before using it
                if tab.winfo_exists():
                    tab.grid(row=0, column=0, sticky="nsew")
                    if self.data_model:
                        tab.load_data(self.data_model)
                else:
                    logger.warning(f"Tab {tab_name} widget does not exist, skipping")
            else:
                if tab.winfo_exists():
                    tab.grid_remove()

        # Update tab button styles
        self._update_tab_button_styles()

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

        # Dynamic status
        dynamic_status = 'completed' if self.data_model.has_dynamic_results() else 'pending'

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

    # ======== On Page Enter ========

    def on_enter(self):
        """Called when page is displayed."""
        logger.info("ResultsPage: on_enter called")
        # Refresh data if already loaded
        if self.data_model:
            self._update_metrics()

    def on_resize(self, width: int, height: int):
        """Called when window is resized."""
        pass
