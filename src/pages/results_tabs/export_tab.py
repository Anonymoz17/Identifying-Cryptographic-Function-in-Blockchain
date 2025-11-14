"""Export & Reporting tab for Results Page."""

from typing import TYPE_CHECKING
import customtkinter as ctk
import tkinter.filedialog as filedialog
import threading
from pathlib import Path

from ui.results_components import SectionHeader, COLORS
from pages.results_export import ExportEngine

if TYPE_CHECKING:
    from pages.results_model import ResultsDataModel


class ExportTab(ctk.CTkFrame):
    """Tab for exporting results in various formats."""

    EXPORT_FORMATS = {
        "PDF Report": {
            "ext": "pdf",
            "desc": "Professional audit report with charts",
            "premium": False,
            "func": ExportEngine.export_to_pdf,
        },
        "JSON Data": {
            "ext": "json",
            "desc": "Machine-readable data with charts as base64",
            "premium": False,
            "func": ExportEngine.export_to_json,
        },
        "TXT Report": {
            "ext": "txt",
            "desc": "Markdown-formatted text report",
            "premium": False,
            "func": ExportEngine.export_to_txt,
        },
    }

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS['bg'], **kwargs)
        self.data_model: 'ResultsDataModel' = None
        self.export_thread = None

        # Create scrollable content
        scroll = ctk.CTkScrollableFrame(self, fg_color=COLORS['bg'])
        scroll.pack(fill="both", expand=True, padx=0, pady=0)
        scroll.grid_columnconfigure(0, weight=1)

        # Header
        header_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        header_frame.pack(fill="x", padx=16, pady=(16, 8))
        header_frame.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header_frame,
            text="📥 Export Analysis Results",
            font=("Roboto", 16, "bold"),
            text_color=COLORS['text']
        )
        title.pack(anchor="w", pady=(0, 12))

        # Format selection section
        self._build_format_section(scroll)

        # Status section
        self._build_status_section(scroll)

    def _build_format_section(self, parent):
        """Build format selection section."""
        section = ctk.CTkFrame(parent, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=(0, 16))
        section.grid_columnconfigure(0, weight=1)

        header = SectionHeader(section, title="Select Export Format")
        header.pack(fill="x", padx=0, pady=(0, 12))

        # Format cards
        self.format_buttons = {}
        self.selected_format = ctk.StringVar(value="PDF Report")

        for fmt_name, fmt_info in self.EXPORT_FORMATS.items():
            self._create_format_card(section, fmt_name, fmt_info)

        # Export button section
        button_frame = ctk.CTkFrame(section, fg_color="transparent")
        button_frame.pack(fill="x", padx=0, pady=(16, 0))
        button_frame.grid_columnconfigure(1, weight=1)

        self.export_btn = ctk.CTkButton(
            button_frame,
            text="Export",
            command=self._on_export_click,
            width=120,
            height=40,
            fg_color=COLORS['primary'],
            hover_color=COLORS['primary'],
            font=("Roboto", 11, "bold")
        )
        self.export_btn.grid(row=0, column=0, sticky="w", padx=0)

    def _create_format_card(self, parent, fmt_name: str, fmt_info: dict):
        """Create a format selection card."""
        card = ctk.CTkFrame(parent, fg_color=COLORS['card_bg'], corner_radius=8)
        card.pack(fill="x", padx=0, pady=6)
        card.grid_columnconfigure(1, weight=1)

        # Radio button
        radio_var = ctk.StringVar(value=fmt_name)
        radio = ctk.CTkRadioButton(
            card,
            text="",
            variable=self.selected_format,
            value=fmt_name,
            fg_color=COLORS['primary'],
            hover_color=COLORS['primary']
        )
        radio.grid(row=0, column=0, sticky="w", padx=12, pady=10)

        # Format info
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.grid(row=0, column=1, sticky="ew", padx=12, pady=10)
        info_frame.grid_columnconfigure(0, weight=1)

        name_label = ctk.CTkLabel(
            info_frame,
            text=fmt_name,
            font=("Roboto", 11, "bold"),
            text_color=COLORS['text']
        )
        name_label.pack(anchor="w", pady=(0, 2))

        desc_label = ctk.CTkLabel(
            info_frame,
            text=fmt_info['desc'],
            font=("Roboto", 9),
            text_color=COLORS['text_secondary']
        )
        desc_label.pack(anchor="w", pady=0)

        self.format_buttons[fmt_name] = radio

    def _build_status_section(self, parent):
        """Build status/progress section."""
        section = ctk.CTkFrame(parent, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=0)
        section.grid_columnconfigure(0, weight=1)

        # Status label
        self.status_label = ctk.CTkLabel(
            section,
            text="Ready to export",
            font=("Roboto", 10),
            text_color=COLORS['text_secondary']
        )
        self.status_label.pack(anchor="w", padx=0, pady=(16, 8))

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            section,
            height=6,
            fg_color=COLORS['card_bg'],
            progress_color=COLORS['primary']
        )
        self.progress_bar.pack(fill="x", padx=0, pady=(0, 8))
        self.progress_bar.set(0)

    def _on_export_click(self):
        """Handle export button click."""
        if not self.data_model:
            self.status_label.configure(text="No data loaded", text_color=COLORS['danger'])
            return

        fmt_name = self.selected_format.get()
        fmt_info = self.EXPORT_FORMATS[fmt_name]

        # Show save dialog
        filetypes = [(f"{fmt_name}", f"*.{fmt_info['ext']}")]
        filepath = filedialog.asksaveasfilename(
            defaultextension=f".{fmt_info['ext']}",
            filetypes=filetypes,
            initialfile=ExportEngine._get_filename(
                "case",
                self.data_model.file_hash[:8] if self.data_model.file_hash else "unknown",
                fmt_info['ext']
            )
        )

        if not filepath:
            return

        # Start export in background
        self.export_btn.configure(state="disabled")
        self.status_label.configure(text="Exporting...", text_color=COLORS['primary'])
        self.progress_bar.set(0.5)

        # Export in thread
        self.export_thread = threading.Thread(
            target=self._perform_export,
            args=(fmt_info, filepath, fmt_name),
            daemon=True
        )
        self.export_thread.start()

    def _perform_export(self, fmt_info: dict, filepath: str, fmt_name: str):
        """Perform the actual export in background thread."""
        try:
            output_dir = str(Path(filepath).parent)
            case_name = Path(filepath).stem

            # Call appropriate export function
            success = fmt_info['func'](
                self.data_model,
                output_dir,
                case_name,
                self.data_model.file_hash or "unknown"
            )

            # Update UI
            if success:
                self.status_label.configure(
                    text=f"Successfully exported to {fmt_name}",
                    text_color=COLORS['success']
                )
                self.progress_bar.set(1.0)
            else:
                self.status_label.configure(
                    text=f"Export failed for {fmt_name}",
                    text_color=COLORS['danger']
                )
                self.progress_bar.set(0)

        except Exception as e:
            self.status_label.configure(
                text=f"Error: {str(e)[:50]}",
                text_color=COLORS['danger']
            )
            self.progress_bar.set(0)

        finally:
            self.export_btn.configure(state="normal")

    def load_data(self, data_model: 'ResultsDataModel'):
        """Load data into the tab."""
        self.data_model = data_model
        if data_model:
            self.status_label.configure(text="Ready to export", text_color=COLORS['text_secondary'])
        else:
            self.status_label.configure(text="No data available", text_color=COLORS['danger'])
