"""Dynamic Analysis tab for Results Page (Premium).

Shows dynamic analysis execution traces including:
- Function call patterns
- Crypto operation traces
- Execution timeline
- Function frequency statistics
- Premium-only features with gating
"""

from typing import TYPE_CHECKING
import customtkinter as ctk
from ui.results_components import SectionHeader, MetricsCard, COLORS, LockedFeatureView, PremiumBadge
from pages.results_charts import VisualizationEngine

if TYPE_CHECKING:
    from pages.results_model import ResultsDataModel


class DynamicTab(ctk.CTkFrame):
    """Tab showing dynamic analysis results (Premium only)."""

    def __init__(self, master, on_continue_analysis=None, **kwargs):
        super().__init__(master, fg_color=COLORS['bg'], **kwargs)
        self.data_model: 'ResultsDataModel' = None
        self.on_continue_analysis = on_continue_analysis  # Callback for continue button

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create scrollable content
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=COLORS['bg']
        )
        self.scroll_frame.pack(fill="both", expand=True, padx=0, pady=0)
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        # Build sections
        self._build_header()
        self._build_summary_section()
        self._build_functions_section()
        self._build_charts_section()
        self._build_action_section()

    def _build_header(self):
        """Build header with overview."""
        header_frame = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=16, pady=(16, 8))
        header_frame.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header_frame,
            text="📞 Dynamic Execution Analysis",
            font=("Roboto", 16, "bold"),
            text_color=COLORS['text']
        )
        title.pack(anchor="w", pady=(0, 12))

        # Quick stats
        stats_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        stats_frame.pack(fill="x", padx=0, pady=0)
        stats_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.total_calls_card = MetricsCard(
            stats_frame,
            label="Total Calls",
            value="0",
            unit="",
            icon="📞"
        )
        self.total_calls_card.grid(row=0, column=0, padx=4, pady=4, sticky="ew")

        self.unique_functions_card = MetricsCard(
            stats_frame,
            label="Unique Functions",
            value="0",
            unit="",
            icon="⚙️"
        )
        self.unique_functions_card.grid(row=0, column=1, padx=4, pady=4, sticky="ew")

        self.execution_time_card = MetricsCard(
            stats_frame,
            label="Execution Time",
            value="0s",
            unit="",
            icon="⏱️"
        )
        self.execution_time_card.grid(row=0, column=2, padx=4, pady=4, sticky="ew")

    def _build_summary_section(self):
        """Build execution summary section."""
        section = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=12)
        section.grid_columnconfigure(0, weight=1)

        header = SectionHeader(
            section,
            title="🎯 Execution Summary"
        )
        header.pack(fill="x", padx=0, pady=(0, 12))

        # Summary card
        card = ctk.CTkFrame(section, fg_color=COLORS['card_bg'], corner_radius=8)
        card.pack(fill="x", padx=0, pady=0)
        card.grid_columnconfigure(0, weight=1)

        self.summary_text = ctk.CTkLabel(
            card,
            text="Loading dynamic analysis data...",
            font=("Roboto", 10),
            text_color=COLORS['text_secondary'],
            justify="left",
            wraplength=500
        )
        self.summary_text.pack(anchor="w", padx=12, pady=12)

    def _build_functions_section(self):
        """Build function calls section."""
        section = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=12)
        section.grid_columnconfigure(0, weight=1)

        header = SectionHeader(
            section,
            title="📊 Cryptographic Functions Called"
        )
        header.pack(fill="x", padx=0, pady=(0, 12))

        # Functions card
        card = ctk.CTkFrame(section, fg_color=COLORS['card_bg'], corner_radius=8)
        card.pack(fill="x", padx=0, pady=0)
        card.grid_columnconfigure(0, weight=1)

        # Functions list frame
        self.functions_frame = ctk.CTkScrollableFrame(
            card,
            fg_color="transparent"
        )
        self.functions_frame.pack(fill="both", expand=True, padx=12, pady=12)
        self.functions_frame.grid_columnconfigure(0, weight=1)

        # Placeholder
        self.no_functions_label = ctk.CTkLabel(
            self.functions_frame,
            text="No function data available",
            font=("Roboto", 10),
            text_color=COLORS['text_secondary']
        )
        self.no_functions_label.pack(pady=20)

    def _build_charts_section(self):
        """Build dynamic charts section."""
        section = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=12)
        section.grid_columnconfigure(0, weight=1)

        header = SectionHeader(
            section,
            title="📈 Dynamic Call Analysis"
        )
        header.pack(fill="x", padx=0, pady=(0, 12))

        # Chart card
        self.chart_card = ctk.CTkFrame(section, fg_color=COLORS['card_bg'], corner_radius=8)
        self.chart_card.pack(fill="x", padx=0, pady=0)
        self.chart_card.grid_columnconfigure(0, weight=1)
        self.chart_card.grid_rowconfigure(0, weight=1)

        # Placeholder for chart
        self.chart_placeholder = ctk.CTkLabel(
            self.chart_card,
            text="Loading chart...",
            font=("Roboto", 10),
            text_color=COLORS['text_secondary']
        )
        self.chart_placeholder.pack(padx=12, pady=12)

    def _update_chart(self):
        """Update the dynamic call frequency chart."""
        if not self.data_model or not self.data_model.dynamic_calls:
            self.chart_placeholder.configure(text="No dynamic data available for chart")
            return

        try:
            # Create execution timeline chart
            chart_img = VisualizationEngine.create_execution_timeline(
                self.data_model.dynamic_calls,
                width=380,
                height=280
            )

            if chart_img:
                # Clear placeholder
                self.chart_placeholder.pack_forget()

                # Create image label if not exists
                if not hasattr(self, 'chart_image_label'):
                    self.chart_image_label = ctk.CTkLabel(self.chart_card, text="")
                    self.chart_image_label.pack(padx=12, pady=12)

                # Convert to CTK image
                ctk_img = ctk.CTkImage(chart_img, size=(380, 280))
                self.chart_image_label.configure(image=ctk_img, text="")
                # Keep reference to prevent garbage collection
                self.chart_image_label.ctk_image = ctk_img
            else:
                self.chart_placeholder.configure(text="Unable to generate chart")
        except Exception as e:
            self.chart_placeholder.configure(text=f"Chart error: {str(e)[:50]}")

    def load_data(self, data_model: 'ResultsDataModel'):
        """Load data into the tab."""
        self.data_model = data_model
        self._update_display()

    def _update_display(self):
        """Update display with dynamic data."""
        if not self.data_model:
            return

        if not self.data_model.has_dynamic_results():
            self.summary_text.configure(
                text="No dynamic analysis data available. Run dynamic analysis to see results."
            )
            return

        # Update stats
        stats = self.data_model.get_statistics()
        dyn_stats = stats['dynamic']

        total_calls = dyn_stats['total_calls']
        unique_funcs = dyn_stats['unique_functions']

        # Update cards
        self.total_calls_card.winfo_children()[2].configure(text=str(total_calls))
        self.unique_functions_card.winfo_children()[2].configure(text=str(unique_funcs))

        # Summary text
        summary_msg = f"""Analysis completed with {total_calls} crypto operation calls detected.
Calls span {unique_funcs} unique cryptographic functions across the execution trace.

Event Types Detected:"""

        for event_type, count in dyn_stats['by_type'].items():
            summary_msg += f"\n• {event_type}: {count}"

        self.summary_text.configure(text=summary_msg)

        # Clear functions list
        for widget in self.functions_frame.winfo_children():
            widget.destroy()

        # Add function items
        if self.data_model.dynamic_calls:
            # Group calls by function
            function_calls = {}
            for call in self.data_model.dynamic_calls:
                if call.function_name:
                    if call.function_name not in function_calls:
                        function_calls[call.function_name] = 0
                    function_calls[call.function_name] += 1

            # Sort by count (descending)
            sorted_funcs = sorted(function_calls.items(), key=lambda x: x[1], reverse=True)

            for func_name, count in sorted_funcs:
                func_item = ctk.CTkFrame(self.functions_frame, fg_color="transparent")
                func_item.pack(fill="x", padx=0, pady=4)
                func_item.grid_columnconfigure(0, weight=1)

                # Function name
                name_label = ctk.CTkLabel(
                    func_item,
                    text=func_name,
                    font=("Roboto", 10),
                    text_color=COLORS['primary']
                )
                name_label.grid(row=0, column=0, sticky="w")

                # Call count
                count_label = ctk.CTkLabel(
                    func_item,
                    text=f"{count} call{'s' if count != 1 else ''}",
                    font=("Roboto", 10),
                    text_color=COLORS['success']
                )
                count_label.grid(row=0, column=1, sticky="e")
        else:
            self.no_functions_label.pack(pady=20)

        # Generate and display chart
        self._update_chart()

    def _build_action_section(self):
        """Build action section with continue button."""
        section = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        section.pack(fill="x", padx=16, pady=16)
        section.grid_columnconfigure(0, weight=1)

        # Continue Analysis button
        if self.on_continue_analysis:
            btn_frame = ctk.CTkFrame(section, fg_color="transparent")
            btn_frame.pack(fill="x", padx=0, pady=0)

            continue_btn = ctk.CTkButton(
                btn_frame,
                text="▶ Continue Dynamic Analysis",
                command=self.on_continue_analysis,
                fg_color=COLORS['primary'],
                hover_color=COLORS['primary_hover'],
                text_color="white",
                font=("Roboto", 11, "bold"),
                height=40,
                corner_radius=8
            )
            continue_btn.pack(fill="x", padx=0, pady=0)

            # Info text
            info_text = ctk.CTkLabel(
                section,
                text="Click to run another dynamic analysis with different parameters or trace depth.",
                font=("Roboto", 9),
                text_color=COLORS['text_secondary'],
                wraplength=500
            )
            info_text.pack(anchor="w", padx=0, pady=(8, 0))
