"""Static Analysis tab for Results Page.

Shows detailed static analysis findings with:
- Filterable findings table
- Confidence slider filtering
- Finding type checkboxes
- Detailed finding view on selection
- Copy-to-clipboard functionality
"""

from typing import TYPE_CHECKING, Optional
import customtkinter as ctk
from ui.results_components import (
    FilterPanel, SectionHeader, FindingsTable, CopyButton, COLORS
)

if TYPE_CHECKING:
    from pages.results_model import ResultsDataModel


class StaticTab(ctk.CTkFrame):
    """Tab showing static analysis findings with filtering."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS['bg'], **kwargs)
        self.data_model: 'ResultsDataModel' = None
        self.current_filters = {}
        self.selected_finding = None

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Filter panel
        self.filter_panel = FilterPanel(
            self,
            on_change=self._on_filter_changed,
            finding_types=['constant_table', 'signature_pattern', 'instruction_pattern']
        )
        self.filter_panel.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))

        # Content area
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        content.grid_rowconfigure(1, weight=1)
        content.grid_columnconfigure((0, 1), weight=1)

        # Left side - Findings table
        left_section = ctk.CTkFrame(content, fg_color="transparent")
        left_section.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 8))
        left_section.grid_rowconfigure(1, weight=1)
        left_section.grid_columnconfigure(0, weight=1)

        header = SectionHeader(
            left_section,
            title="Findings"
        )
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 8))

        # Findings table
        self.findings_table = FindingsTable(left_section)
        self.findings_table.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)

        # Right side - Details panel
        details_frame = ctk.CTkFrame(content, fg_color=COLORS['card_bg'], corner_radius=8)
        details_frame.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(8, 0))
        details_frame.grid_rowconfigure(1, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)

        detail_header = ctk.CTkLabel(
            details_frame,
            text="Finding Details",
            font=("Roboto", 12, "bold"),
            text_color=COLORS['text']
        )
        detail_header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))

        # Details scroll area
        self.details_scroll = ctk.CTkScrollableFrame(
            details_frame,
            fg_color="transparent"
        )
        self.details_scroll.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.details_scroll.grid_columnconfigure(0, weight=1)

        # No selection message
        self.no_selection_label = ctk.CTkLabel(
            self.details_scroll,
            text="Select a finding to view details",
            font=("Roboto", 11),
            text_color=COLORS['text_secondary']
        )
        self.no_selection_label.pack(pady=20)

    def load_data(self, data_model: 'ResultsDataModel'):
        """Load data into the tab."""
        self.data_model = data_model
        self._refresh_findings()

    def _on_filter_changed(self, filters: dict):
        """Handle filter change."""
        self.current_filters = filters
        self._refresh_findings()

    def _refresh_findings(self):
        """Refresh the findings table with current filters."""
        if not self.data_model:
            return

        # Clear table
        for widget in self.findings_table.scroll_frame.winfo_children():
            widget.destroy()

        # Get filtered findings
        min_conf = self.current_filters.get('min_confidence', 0.0)
        findings = self.data_model.get_static_findings(min_confidence=min_conf)

        if not findings:
            no_results = ctk.CTkLabel(
                self.findings_table.scroll_frame,
                text="No findings match the current filters",
                font=("Roboto", 11),
                text_color=COLORS['text_secondary']
            )
            no_results.pack(pady=20)
            return

        # Populate table
        for finding in findings:
            self.findings_table.add_finding(
                finding_id=finding.id,
                name=finding.name or finding.type,
                confidence=finding.confidence,
                finding_type=finding.type,
                on_click=lambda f=finding: self._show_finding_details(f)
            )

    def _show_finding_details(self, finding):
        """Show details for selected finding."""
        self.selected_finding = finding

        # Clear previous details
        for widget in self.details_scroll.winfo_children():
            widget.destroy()

        # Build details view
        details_content = ctk.CTkFrame(self.details_scroll, fg_color="transparent")
        details_content.pack(fill="x", padx=0, pady=0)
        details_content.grid_columnconfigure(0, weight=1)

        # Finding ID
        id_frame = ctk.CTkFrame(details_content, fg_color="transparent")
        id_frame.pack(fill="x", padx=0, pady=4)
        id_frame.grid_columnconfigure(0, weight=1)

        id_label = ctk.CTkLabel(
            id_frame,
            text="ID:",
            font=("Roboto", 10, "bold"),
            text_color=COLORS['text_secondary']
        )
        id_label.grid(row=0, column=0, sticky="w")

        id_value = ctk.CTkLabel(
            id_frame,
            text=finding.id,
            font=("Roboto", 10),
            text_color=COLORS['primary']
        )
        id_value.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        # Type
        type_label = ctk.CTkLabel(
            details_content,
            text=f"Type: {finding.type}",
            font=("Roboto", 10),
            text_color=COLORS['text']
        )
        type_label.pack(anchor="w", padx=0, pady=4)

        # Confidence
        conf_color = self._get_confidence_color(finding.confidence)
        conf_label = ctk.CTkLabel(
            details_content,
            text=f"Confidence: {finding.confidence:.0%}",
            font=("Roboto", 10),
            text_color=conf_color
        )
        conf_label.pack(anchor="w", padx=0, pady=4)

        # Address
        if finding.address:
            addr_frame = ctk.CTkFrame(details_content, fg_color="transparent")
            addr_frame.pack(fill="x", padx=0, pady=4)
            addr_frame.grid_columnconfigure(0, weight=1)

            addr_label = ctk.CTkLabel(
                addr_frame,
                text="Address:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            addr_label.grid(row=0, column=0, sticky="w")

            addr_value = ctk.CTkLabel(
                addr_frame,
                text=finding.address,
                font=("Roboto", 10),
                text_color=COLORS['primary']
            )
            addr_value.grid(row=0, column=1, sticky="ew", padx=(4, 0))

            # Copy button
            copy_btn = CopyButton(
                addr_frame,
                text="Copy",
                copy_text=finding.address,
                width=50,
                height=24
            )
            copy_btn.grid(row=0, column=2, sticky="e", padx=(4, 0))

        # Separator
        sep = ctk.CTkFrame(details_content, height=1, fg_color=COLORS['border'])
        sep.pack(fill="x", padx=0, pady=8)

        # Evidence
        if finding.evidence:
            evidence_label = ctk.CTkLabel(
                details_content,
                text="Evidence:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            evidence_label.pack(anchor="w", padx=0, pady=(8, 4))

            evidence_text = ctk.CTkLabel(
                details_content,
                text=finding.evidence,
                font=("Roboto", 9),
                text_color=COLORS['text'],
                justify="left",
                wraplength=250
            )
            evidence_text.pack(anchor="w", padx=0, pady=(0, 8))

        # Additional data
        if finding.additional_data:
            additional_label = ctk.CTkLabel(
                details_content,
                text="Additional Info:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            additional_label.pack(anchor="w", padx=0, pady=(8, 4))

            for key, value in finding.additional_data.items():
                info_text = ctk.CTkLabel(
                    details_content,
                    text=f"{key}: {value}",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                    wraplength=250,
                    justify="left"
                )
                info_text.pack(anchor="w", padx=0, pady=2)

    @staticmethod
    def _get_confidence_color(confidence: float) -> str:
        """Get color based on confidence level."""
        if confidence >= 0.8:
            return COLORS['success']  # green
        elif confidence >= 0.5:
            return COLORS['warning']  # yellow
        else:
            return COLORS['danger']  # red
