"""Overview tab for Results Page.

Shows high-level summary of analysis results including:
- Key statistics (findings count, confidence levels)
- Analysis status and timestamps
- Quick action buttons
- Summary cards for static and dynamic analysis
"""

from typing import TYPE_CHECKING
import customtkinter as ctk
from ui.results_components import MetricsCard, StatusIndicator, SectionHeader, COLORS

if TYPE_CHECKING:
    from pages.results_model import ResultsDataModel


class OverviewTab(ctk.CTkFrame):
    """Overview tab showing high-level analysis summary."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS['bg'], **kwargs)
        self.data_model: 'ResultsDataModel' = None

        # Create scrollable content area
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=COLORS['bg']
        )
        self.scroll_frame.pack(fill="both", expand=True, padx=0, pady=0)
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        # Build UI structure
        self._build_header()
        self._build_static_section()
        self._build_dynamic_section()
        self._build_summary_section()

    def _build_header(self):
        """Build header with quick stats."""
        header_frame = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=16, pady=(16, 8))
        header_frame.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header_frame,
            text="📊 Analysis Summary",
            font=("Roboto", 16, "bold"),
            text_color=COLORS['text']
        )
        title.pack(anchor="w", pady=(0, 12))

        # Quick stats row
        stats_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        stats_frame.pack(fill="x", padx=0, pady=0)
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.total_findings_card = MetricsCard(
            stats_frame,
            label="Total Findings",
            value="0",
            unit="",
            icon="🔍"
        )
        self.total_findings_card.grid(row=0, column=0, padx=4, pady=4, sticky="ew")

        self.avg_confidence_card = MetricsCard(
            stats_frame,
            label="Avg Confidence",
            value="0%",
            unit="",
            icon="📈"
        )
        self.avg_confidence_card.grid(row=0, column=1, padx=4, pady=4, sticky="ew")

        self.dynamic_calls_card = MetricsCard(
            stats_frame,
            label="Crypto Calls",
            value="0",
            unit="",
            icon="📞",
            color=COLORS['success']
        )
        self.dynamic_calls_card.grid(row=0, column=2, padx=4, pady=4, sticky="ew")

        self.unique_functions_card = MetricsCard(
            stats_frame,
            label="Functions",
            value="0",
            unit="",
            icon="⚙️",
            color=COLORS['success']
        )
        self.unique_functions_card.grid(row=0, column=3, padx=4, pady=4, sticky="ew")

    def _build_static_section(self):
        """Build static analysis results section."""
        section = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=12)
        section.grid_columnconfigure(0, weight=1)

        # Section header
        header = SectionHeader(
            section,
            title="🔍 Static Analysis Results"
        )
        header.pack(fill="x", padx=0, pady=(0, 12))

        # Static results card
        card = ctk.CTkFrame(section, fg_color=COLORS['card_bg'], corner_radius=8)
        card.pack(fill="x", padx=0, pady=0)
        card.grid_columnconfigure(0, weight=1)

        # Status row
        self.static_status = StatusIndicator(
            card,
            status='pending',
            label='Status: Loading analysis data...'
        )
        self.static_status.pack(anchor="w", padx=12, pady=(12, 8))

        # Findings breakdown
        breakdown_frame = ctk.CTkFrame(card, fg_color="transparent")
        breakdown_frame.pack(fill="x", padx=12, pady=8)
        breakdown_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.high_conf_label = ctk.CTkLabel(
            breakdown_frame,
            text="High Confidence: 0",
            font=("Roboto", 11),
            text_color=COLORS['success']
        )
        self.high_conf_label.grid(row=0, column=0, sticky="w", padx=4, pady=4)

        self.med_conf_label = ctk.CTkLabel(
            breakdown_frame,
            text="Medium Confidence: 0",
            font=("Roboto", 11),
            text_color=COLORS['warning']
        )
        self.med_conf_label.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        self.low_conf_label = ctk.CTkLabel(
            breakdown_frame,
            text="Low Confidence: 0",
            font=("Roboto", 11),
            text_color=COLORS['danger']
        )
        self.low_conf_label.grid(row=0, column=2, sticky="w", padx=4, pady=4)

        # Finding types
        types_label = ctk.CTkLabel(
            card,
            text="Finding Types:",
            font=("Roboto", 10, "bold"),
            text_color=COLORS['text_secondary']
        )
        types_label.pack(anchor="w", padx=12, pady=(8, 4))

        self.types_text = ctk.CTkLabel(
            card,
            text="None yet",
            font=("Roboto", 10),
            text_color=COLORS['text'],
            justify="left",
            wraplength=400
        )
        self.types_text.pack(anchor="w", padx=12, pady=(0, 12))

    def _build_dynamic_section(self):
        """Build dynamic analysis results section."""
        section = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=12)
        section.grid_columnconfigure(0, weight=1)

        # Section header
        header = SectionHeader(
            section,
            title="📞 Dynamic Analysis Results"
        )
        header.pack(fill="x", padx=0, pady=(0, 12))

        # Dynamic results card
        card = ctk.CTkFrame(section, fg_color=COLORS['card_bg'], corner_radius=8)
        card.pack(fill="x", padx=0, pady=0)
        card.grid_columnconfigure(0, weight=1)

        # Status row
        self.dynamic_status = StatusIndicator(
            card,
            status='pending',
            label='Status: No dynamic analysis data'
        )
        self.dynamic_status.pack(anchor="w", padx=12, pady=(12, 8))

        # Events summary
        summary_frame = ctk.CTkFrame(card, fg_color="transparent")
        summary_frame.pack(fill="x", padx=12, pady=8)
        summary_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.total_events_label = ctk.CTkLabel(
            summary_frame,
            text="Total Events: 0",
            font=("Roboto", 11),
            text_color=COLORS['text']
        )
        self.total_events_label.grid(row=0, column=0, sticky="w", padx=4, pady=4)

        self.crypto_ops_label = ctk.CTkLabel(
            summary_frame,
            text="Crypto Operations: 0",
            font=("Roboto", 11),
            text_color=COLORS['text']
        )
        self.crypto_ops_label.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        self.unique_funcs_label = ctk.CTkLabel(
            summary_frame,
            text="Unique Functions: 0",
            font=("Roboto", 11),
            text_color=COLORS['text']
        )
        self.unique_funcs_label.grid(row=0, column=2, sticky="w", padx=4, pady=4)

        # Event types
        types_label = ctk.CTkLabel(
            card,
            text="Event Types:",
            font=("Roboto", 10, "bold"),
            text_color=COLORS['text_secondary']
        )
        types_label.pack(anchor="w", padx=12, pady=(8, 4))

        self.dyn_types_text = ctk.CTkLabel(
            card,
            text="None yet",
            font=("Roboto", 10),
            text_color=COLORS['text'],
            justify="left",
            wraplength=400
        )
        self.dyn_types_text.pack(anchor="w", padx=12, pady=(0, 12))

    def _build_summary_section(self):
        """Build overall summary section."""
        section = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=12)
        section.grid_columnconfigure(0, weight=1)

        # Section header
        header = SectionHeader(
            section,
            title="📋 Analysis Metadata"
        )
        header.pack(fill="x", padx=0, pady=(0, 12))

        # Metadata card
        card = ctk.CTkFrame(section, fg_color=COLORS['card_bg'], corner_radius=8)
        card.pack(fill="x", padx=0, pady=0)
        card.grid_columnconfigure(0, weight=1)

        self.metadata_text = ctk.CTkLabel(
            card,
            text="Loading metadata...",
            font=("Roboto", 10),
            text_color=COLORS['text_secondary'],
            justify="left",
            wraplength=500
        )
        self.metadata_text.pack(anchor="w", padx=12, pady=12)

    def load_data(self, data_model: 'ResultsDataModel'):
        """Load data into the tab."""
        self.data_model = data_model
        self._update_display()

    def _update_display(self):
        """Update all display elements with current data."""
        if not self.data_model:
            return

        stats = self.data_model.get_statistics()

        # Update header cards using the new update_value() method
        static_stats = stats['static']
        self.total_findings_card.update_value(
            str(static_stats['total_findings'])
        )

        avg_conf = static_stats['average_confidence']
        conf_text = f"{avg_conf:.0%}"
        self.avg_confidence_card.update_value(
            conf_text
        )

        # Dynamic stats
        dyn_stats = stats['dynamic']
        self.dynamic_calls_card.update_value(
            str(dyn_stats['total_calls'])
        )

        self.unique_functions_card.update_value(
            str(dyn_stats['unique_functions'])
        )

        # Update static section
        if self.data_model.has_static_results():
            self.static_status.configure(fg_color=COLORS['card_bg'])
            status_text = f"✓ {static_stats['total_findings']} findings detected"
            # Update confidence breakdown (with safe defaults)
            conf_range = static_stats.get('by_confidence_range', {'high': 0, 'medium': 0, 'low': 0})
            self.high_conf_label.configure(
                text=f"High Confidence (0.8-1.0): {conf_range.get('high', 0)}"
            )
            self.med_conf_label.configure(
                text=f"Medium Confidence (0.5-0.8): {conf_range.get('medium', 0)}"
            )
            self.low_conf_label.configure(
                text=f"Low Confidence (0.0-0.5): {conf_range.get('low', 0)}"
            )

            # Finding types breakdown (with safe handling)
            by_type = static_stats.get('by_type', {})
            types_str = ", ".join(
                f"{ftype} ({count})"
                for ftype, count in by_type.items()
            ) or "None"
            self.types_text.configure(text=types_str)
        else:
            status_text = "⏳ Static analysis not yet performed"
            self.types_text.configure(text="None")

        # Update dynamic section (with safe defaults)
        if self.data_model.has_dynamic_results():
            dynamic_status = "✓ Dynamic analysis completed"
            self.total_events_label.configure(
                text=f"Total Events: {dyn_stats.get('total_calls', 0)}"
            )
            self.unique_funcs_label.configure(
                text=f"Unique Functions: {dyn_stats.get('unique_functions', 0)}"
            )

            # Event types (safe handling)
            dyn_by_type = dyn_stats.get('by_type', {})
            types_str = ", ".join(
                f"{etype} ({count})"
                for etype, count in dyn_by_type.items()
            ) or "None"
            self.dyn_types_text.configure(text=types_str)
        else:
            dynamic_status = "⏳ Dynamic analysis not available"
            self.dyn_types_text.configure(text="None")

        # Update metadata (with safe defaults)
        try:
            meta = self.data_model.metadata
            analysis_date = getattr(meta, 'analysis_date', 'Unknown') or 'Unknown'
            file_hash = self.data_model.file_hash[:32] if self.data_model.file_hash else 'Unknown'
            static_status = getattr(meta, 'static_status', 'Unknown')
            if static_status:
                static_status = static_status.title()
            else:
                static_status = 'Unknown'
            dynamic_status = getattr(meta, 'dynamic_status', 'Unknown')
            if dynamic_status:
                dynamic_status = dynamic_status.title()
            else:
                dynamic_status = 'Unknown'

            metadata_info = f"""Analysis Date: {analysis_date}
File Hash: {file_hash}...
Static Status: {static_status}
Dynamic Status: {dynamic_status}
"""
        except Exception as e:
            logger.warning(f"Failed to update metadata: {e}")
            metadata_info = "Metadata unavailable"

        self.metadata_text.configure(text=metadata_info)
