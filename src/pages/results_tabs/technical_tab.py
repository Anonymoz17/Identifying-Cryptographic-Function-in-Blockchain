"""Technical Details tab for Results Page.

Shows raw analysis metadata and technical information.
"""

from typing import TYPE_CHECKING
import customtkinter as ctk
import json
from ui.results_components import SectionHeader, CopyButton, COLORS

if TYPE_CHECKING:
    from pages.results_model import ResultsDataModel


class TechnicalTab(ctk.CTkFrame):
    """Tab showing technical metadata and raw data."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS['bg'], **kwargs)
        self.data_model: 'ResultsDataModel' = None

        # Create scrollable content
        scroll = ctk.CTkScrollableFrame(self, fg_color=COLORS['bg'])
        scroll.pack(fill="both", expand=True, padx=16, pady=16)
        scroll.grid_columnconfigure(0, weight=1)

        # Header
        header = SectionHeader(scroll, title="⚙️ Technical Details")
        header.pack(fill="x", padx=0, pady=(0, 16))

        # Metadata section
        self._build_metadata_section(scroll)

        # Raw statistics section
        self._build_stats_section(scroll)

    def _build_metadata_section(self, parent):
        """Build metadata display section."""
        section = ctk.CTkFrame(parent, fg_color="transparent")
        section.pack(fill="x", padx=0, pady=(0, 16))
        section.grid_columnconfigure(0, weight=1)

        # Title with buttons
        header_frame = ctk.CTkFrame(section, fg_color="transparent")
        header_frame.pack(fill="x", padx=0, pady=(0, 8))
        header_frame.grid_columnconfigure(1, weight=1)

        title = ctk.CTkLabel(
            header_frame,
            text="Analysis Metadata",
            font=("Roboto", 12, "bold"),
            text_color=COLORS['text']
        )
        title.grid(row=0, column=0, sticky="w")

        # Copy button
        copy_btn = ctk.CTkButton(
            header_frame,
            text="Copy",
            command=self._copy_metadata,
            width=80,
            height=24,
            font=("Roboto", 9),
            fg_color=COLORS['primary'],
            hover_color=COLORS['primary']
        )
        copy_btn.grid(row=0, column=1, sticky="e", padx=(8, 0))

        # Metadata card
        card = ctk.CTkFrame(section, fg_color=COLORS['card_bg'], corner_radius=8)
        card.pack(fill="x", padx=0, pady=0)
        card.grid_columnconfigure(0, weight=1)

        self.metadata_textbox = ctk.CTkTextbox(
            card,
            height=200,
            font=("Consolas", 9),
            text_color=COLORS['text'],
            fg_color=COLORS['bg'],
            border_color=COLORS['border'],
            border_width=1
        )
        self.metadata_textbox.pack(fill="both", expand=True, padx=8, pady=8)
        self.metadata_textbox.configure(state="disabled")

    def _build_stats_section(self, parent):
        """Build statistics display section."""
        section = ctk.CTkFrame(parent, fg_color="transparent")
        section.pack(fill="x", padx=0, pady=0)
        section.grid_columnconfigure(0, weight=1)

        # Title with buttons
        header_frame = ctk.CTkFrame(section, fg_color="transparent")
        header_frame.pack(fill="x", padx=0, pady=(0, 8))
        header_frame.grid_columnconfigure(1, weight=1)

        title = ctk.CTkLabel(
            header_frame,
            text="Analysis Statistics",
            font=("Roboto", 12, "bold"),
            text_color=COLORS['text']
        )
        title.grid(row=0, column=0, sticky="w")

        # Copy button
        copy_btn = ctk.CTkButton(
            header_frame,
            text="Copy",
            command=self._copy_statistics,
            width=80,
            height=24,
            font=("Roboto", 9),
            fg_color=COLORS['primary'],
            hover_color=COLORS['primary']
        )
        copy_btn.grid(row=0, column=1, sticky="e", padx=(8, 0))

        # Stats card
        card = ctk.CTkFrame(section, fg_color=COLORS['card_bg'], corner_radius=8)
        card.pack(fill="x", padx=0, pady=0)
        card.grid_columnconfigure(0, weight=1)

        self.stats_textbox = ctk.CTkTextbox(
            card,
            height=200,
            font=("Consolas", 9),
            text_color=COLORS['text'],
            fg_color=COLORS['bg'],
            border_color=COLORS['border'],
            border_width=1
        )
        self.stats_textbox.pack(fill="both", expand=True, padx=8, pady=8)
        self.stats_textbox.configure(state="disabled")

    def _copy_metadata(self):
        """Copy metadata to clipboard."""
        try:
            meta = self.data_model.metadata
            metadata_json = json.dumps(meta.to_dict(), indent=2)
            self.winfo_toplevel().clipboard_clear()
            self.winfo_toplevel().clipboard_append(metadata_json)
            # Show feedback (would need status label to show "Copied!")
        except Exception as e:
            pass  # Silently fail

    def _copy_statistics(self):
        """Copy statistics to clipboard."""
        try:
            stats = self.data_model.get_statistics()
            stats_json = json.dumps(stats, indent=2)
            self.winfo_toplevel().clipboard_clear()
            self.winfo_toplevel().clipboard_append(stats_json)
            # Show feedback (would need status label to show "Copied!")
        except Exception as e:
            pass  # Silently fail

    def load_data(self, data_model: 'ResultsDataModel'):
        """Load data into the tab."""
        self.data_model = data_model
        self._update_display()

    def _update_display(self):
        """Update technical display."""
        if not self.data_model:
            return

        # Update metadata
        meta = self.data_model.metadata
        metadata_json = json.dumps(meta.to_dict(), indent=2)

        self.metadata_textbox.configure(state="normal")
        self.metadata_textbox.delete("1.0", "end")
        self.metadata_textbox.insert("1.0", metadata_json)
        self.metadata_textbox.configure(state="disabled")

        # Update statistics
        stats = self.data_model.get_statistics()
        stats_json = json.dumps(stats, indent=2)

        self.stats_textbox.configure(state="normal")
        self.stats_textbox.delete("1.0", "end")
        self.stats_textbox.insert("1.0", stats_json)
        self.stats_textbox.configure(state="disabled")
