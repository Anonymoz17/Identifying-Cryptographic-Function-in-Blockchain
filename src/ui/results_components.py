"""Reusable UI components for the Results Page.

Provides common UI widgets used across the Results Page and its tabs.
All components use the dark theme with customtkinter.
"""

from typing import Optional, Callable, List, Dict, Any
import customtkinter as ctk


# ============ Colors & Theme ============
# These should match the app theme
COLORS = {
    'bg': '#0F1117',
    'card_bg': '#1E2631',
    'text': '#DDE2E8',
    'text_secondary': '#8A94A6',
    'primary': '#0066CC',
    'primary_hover': '#0052A3',
    'success': '#28A745',
    'success_hover': '#218838',
    'danger': '#DC3545',
    'danger_hover': '#C82333',
    'warning': '#FFC107',
    'warning_text': '#000000',
    'border': '#30363D',
}


# ============ MetricsCard ============
class MetricsCard(ctk.CTkFrame):
    """
    Display a metric with label, value, and optional trend indicator.

    Example:
        card = MetricsCard(parent, label="Total Findings", value="42", unit="")
        card.pack(padx=10, pady=10)
    """

    def __init__(
        self,
        master,
        label: str = "",
        value: str = "-",
        unit: str = "",
        icon: str = "",
        color: str = None,
        **kwargs
    ):
        """
        Initialize the metrics card.

        Args:
            master: Parent widget
            label: Card label (e.g., "Total Findings")
            value: Main value to display
            unit: Unit text (e.g., "findings")
            icon: Emoji or text icon
            color: Override color for the value text
        """
        super().__init__(
            master,
            fg_color=COLORS['card_bg'],
            corner_radius=8,
            **kwargs
        )

        self.grid_columnconfigure(0, weight=1)

        # Icon + label row
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 4))
        header_frame.grid_columnconfigure(1, weight=1)

        if icon:
            icon_label = ctk.CTkLabel(
                header_frame,
                text=icon,
                font=("Arial", 14)
            )
            icon_label.grid(row=0, column=0, padx=(0, 8))

        label_widget = ctk.CTkLabel(
            header_frame,
            text=label,
            font=("Roboto", 11),
            text_color=COLORS['text_secondary']
        )
        label_widget.grid(row=0, column=1, sticky="ew")

        # Value row
        value_color = color or COLORS['primary']
        value_label = ctk.CTkLabel(
            self,
            text=value,
            font=("Roboto", 22, "bold"),
            text_color=value_color
        )
        value_label.grid(row=1, column=0, sticky="ew", padx=12, pady=(4, 4))

        # Unit row (if provided)
        if unit:
            unit_label = ctk.CTkLabel(
                self,
                text=unit,
                font=("Roboto", 10),
                text_color=COLORS['text_secondary']
            )
            unit_label.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
        else:
            self.grid_rowconfigure(1, minsize=40)
            self.grid_rowconfigure(2, minsize=8)

        # Store reference to value label for updates
        self.value_label = value_label

    def update_value(self, text: str):
        """Update the value displayed in the card."""
        try:
            self.value_label.configure(text=text)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to update metric value: {e}")


# ============ StatusIndicator ============
class StatusIndicator(ctk.CTkFrame):
    """
    Display status with icon and text.

    Example:
        status = StatusIndicator(parent, status="completed", label="Static Analysis")
        status.pack(pady=10)
    """

    STATUS_ICONS = {
        'completed': ('✓', '#28A745'),
        'in_progress': ('⏳', '#0066CC'),
        'pending': ('◦', '#8A94A6'),
        'failed': ('✗', '#DC3545'),
        'warning': ('⚠', '#FFC107'),
    }

    def __init__(
        self,
        master,
        status: str = 'pending',
        label: str = "",
        **kwargs
    ):
        """
        Initialize the status indicator.

        Args:
            master: Parent widget
            status: One of completed, in_progress, pending, failed, warning
            label: Text label
        """
        super().__init__(
            master,
            fg_color="transparent",
            **kwargs
        )

        self.grid_columnconfigure(1, weight=1)

        icon, color = self.STATUS_ICONS.get(status, ('?', COLORS['text_secondary']))

        icon_label = ctk.CTkLabel(
            self,
            text=icon,
            font=("Arial", 16),
            text_color=color
        )
        icon_label.grid(row=0, column=0, padx=(0, 8))

        text_label = ctk.CTkLabel(
            self,
            text=label,
            font=("Roboto", 11),
            text_color=COLORS['text']
        )
        text_label.grid(row=0, column=1, sticky="ew")


# ============ PremiumBadge ============
class PremiumBadge(ctk.CTkFrame):
    """
    Display a "PREMIUM" badge for premium-only features.

    Example:
        badge = PremiumBadge(parent)
        badge.pack(padx=10, pady=5)
    """

    def __init__(self, master, text: str = "PREMIUM", **kwargs):
        """Initialize the premium badge."""
        super().__init__(
            master,
            fg_color=COLORS['primary'],
            corner_radius=4,
            **kwargs
        )

        label = ctk.CTkLabel(
            self,
            text=text,
            font=("Roboto", 9, "bold"),
            text_color="white"
        )
        label.pack(padx=6, pady=2)


# ============ LockedFeatureView ============
class LockedFeatureView(ctk.CTkFrame):
    """
    Display a locked/premium feature view with upgrade button.

    Example:
        locked = LockedFeatureView(
            parent,
            feature_name="Dynamic Analysis",
            on_upgrade=self._open_upgrade
        )
        locked.pack(fill="both", expand=True)
    """

    def __init__(
        self,
        master,
        feature_name: str = "Feature",
        on_upgrade: Optional[Callable] = None,
        **kwargs
    ):
        """
        Initialize the locked feature view.

        Args:
            master: Parent widget
            feature_name: Name of the locked feature
            on_upgrade: Callback when upgrade button is clicked
        """
        super().__init__(
            master,
            fg_color=COLORS['card_bg'],
            **kwargs
        )

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Content frame
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        content.grid_columnconfigure(0, weight=1)

        # Lock icon
        icon = ctk.CTkLabel(
            content,
            text="🔒",
            font=("Arial", 48),
            text_color=COLORS['warning']
        )
        icon.grid(row=0, column=0, pady=20)

        # Title
        title = ctk.CTkLabel(
            content,
            text=f"{feature_name} Requires Premium",
            font=("Roboto", 16, "bold"),
            text_color=COLORS['text']
        )
        title.grid(row=1, column=0, pady=10)

        # Description
        desc = ctk.CTkLabel(
            content,
            text="Upgrade your account to unlock this feature",
            font=("Roboto", 11),
            text_color=COLORS['text_secondary'],
            wraplength=400
        )
        desc.grid(row=2, column=0, pady=10)

        # Upgrade button
        if on_upgrade:
            upgrade_btn = ctk.CTkButton(
                content,
                text="Upgrade to Premium",
                command=on_upgrade,
                fg_color=COLORS['success'],
                hover_color=COLORS['success_hover'],
                font=("Roboto", 11, "bold")
            )
            upgrade_btn.grid(row=3, column=0, pady=20)


# ============ FilterPanel ============
class FilterPanel(ctk.CTkFrame):
    """
    Filtering controls for findings (confidence slider, type filters, search).

    Example:
        filters = FilterPanel(
            parent,
            on_change=self._on_filter_change,
            finding_types=['constant_table', 'signature_pattern']
        )
        filters.pack(fill="x", padx=10, pady=10)
    """

    # Debounce settings (milliseconds)
    SLIDER_DEBOUNCE_MS = 300

    def __init__(
        self,
        master,
        on_change: Optional[Callable] = None,
        finding_types: Optional[List[str]] = None,
        **kwargs
    ):
        """
        Initialize the filter panel.

        Args:
            master: Parent widget
            on_change: Callback when filter changes (returns filter dict)
            finding_types: Available finding types to filter by
        """
        super().__init__(
            master,
            fg_color=COLORS['card_bg'],
            corner_radius=8,
            **kwargs
        )

        self.on_change = on_change
        self.finding_types = finding_types or []
        self._debounce_timer = None  # Timer for debounced slider changes

        # Confidence slider
        conf_frame = ctk.CTkFrame(self, fg_color="transparent")
        conf_frame.pack(fill="x", padx=12, pady=(12, 8))
        conf_frame.grid_columnconfigure(1, weight=1)

        conf_label = ctk.CTkLabel(
            conf_frame,
            text="Max Confidence:",
            font=("Roboto", 10),
            text_color=COLORS['text_secondary']
        )
        conf_label.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self.conf_var = ctk.DoubleVar(value=0.0)
        conf_slider = ctk.CTkSlider(
            conf_frame,
            from_=0.0,
            to=1.0,
            variable=self.conf_var,
            command=self._on_slider_change,  # Changed to debounced handler
            progress_color=COLORS['primary']
        )
        conf_slider.grid(row=0, column=1, sticky="ew", padx=8)

        self.conf_label = ctk.CTkLabel(
            conf_frame,
            text="0%",
            font=("Roboto", 10),
            text_color=COLORS['primary']
        )
        self.conf_label.grid(row=0, column=2, padx=(8, 0))

    def _on_slider_change(self, value=None):
        """Handle slider movement with debouncing (prevents page reset on drag)."""
        # Update label immediately for visual feedback
        self.conf_label.configure(text=f"{int(self.conf_var.get() * 100)}%")

        # Cancel previous debounce timer if still pending
        if self._debounce_timer:
            self.after_cancel(self._debounce_timer)

        # Schedule the actual filter change after user stops dragging
        self._debounce_timer = self.after(
            self.SLIDER_DEBOUNCE_MS,
            self._on_filter_change
        )

    def _on_filter_change(self):
        """Handle filter change (called after debounce)."""
        if self.on_change:
            filters = {
                'min_confidence': self.conf_var.get(),
            }
            self.on_change(filters)
        self._debounce_timer = None  # Clear timer reference

    def get_filters(self) -> dict:
        """Get current filter values."""
        return {
            'min_confidence': self.conf_var.get(),
        }


# ============ FindingsTable ============
class FindingsTable(ctk.CTkFrame):
    """
    Display findings in a table-like format (scrollable frame with rows).

    Features:
    - Clickable rows with visual selection feedback
    - Sortable columns (click header to sort)
    - Current selection tracking

    Example:
        table = FindingsTable(parent)
        table.pack(fill="both", expand=True, padx=10, pady=10)
        table.add_finding("Finding 1", "0.95", "constant_table")
    """

    def __init__(self, master, on_sort_column: Optional[Callable] = None, **kwargs):
        """Initialize the findings table.

        Args:
            master: Parent widget
            on_sort_column: Callback when column header is clicked (receives column name: 'confidence', 'name', 'type')
        """
        super().__init__(
            master,
            fg_color="transparent",
            **kwargs
        )

        self.grid_columnconfigure(0, weight=1)
        self.on_sort_column = on_sort_column

        # Selection tracking
        self.selected_row_frame = None  # Current selected row widget
        self.row_frames = []  # All row frames for deselection

        # Sort state
        self.sort_column = None  # 'confidence', 'name', etc.
        self.sort_ascending = True

        # Header
        header = ctk.CTkFrame(self, fg_color=COLORS['card_bg'], height=40)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 1))
        header.grid_columnconfigure(1, weight=1)

        id_h = ctk.CTkLabel(header, text="ID", font=("Roboto", 10, "bold"))
        id_h.grid(row=0, column=0, padx=12, pady=8, sticky="w")

        # Clickable column headers
        name_h = ctk.CTkLabel(
            header,
            text="Finding",
            font=("Roboto", 10, "bold"),
            text_color=COLORS['text']
        )
        name_h.grid(row=0, column=1, padx=12, pady=8, sticky="ew")
        if on_sort_column:
            name_h.configure(cursor="hand2")
            name_h.bind("<Button-1>", lambda e: on_sort_column('name'))

        conf_h = ctk.CTkLabel(
            header,
            text="Confidence ▲▼",
            font=("Roboto", 10, "bold"),
            text_color=COLORS['text']
        )
        conf_h.grid(row=0, column=2, padx=12, pady=8, sticky="e")
        if on_sort_column:
            conf_h.configure(cursor="hand2")
            conf_h.bind("<Button-1>", lambda e: on_sort_column('confidence'))

        type_h = ctk.CTkLabel(
            header,
            text="Type",
            font=("Roboto", 10, "bold"),
            text_color=COLORS['text']
        )
        type_h.grid(row=0, column=3, padx=12, pady=8, sticky="e")
        if on_sort_column:
            type_h.configure(cursor="hand2")
            type_h.bind("<Button-1>", lambda e: on_sort_column('type'))

        # Scrollable content
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=COLORS['card_bg'],
            corner_radius=0
        )
        self.scroll_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 0))
        self.scroll_frame.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.row_count = 0

    def add_finding(
        self,
        finding_id: str,
        name: str,
        confidence: float,
        finding_type: str,
        address: Optional[str] = None,
        on_click: Optional[Callable] = None
    ):
        """
        Add a finding row to the table.

        Args:
            finding_id: Finding ID
            name: Finding name/description
            confidence: Confidence score (0.0-1.0)
            finding_type: Type of finding
            address: Hex address (optional, for location info)
            on_click: Callback when row is clicked
        """
        # Create row with background that can change for selection
        row_frame = ctk.CTkFrame(
            self.scroll_frame,
            fg_color="transparent",
            height=40,
            corner_radius=4
        )
        row_frame.pack(fill="x", padx=8, pady=2)
        row_frame.grid_columnconfigure(1, weight=1)

        # Store for selection tracking
        self.row_frames.append(row_frame)

        # ID
        id_label = ctk.CTkLabel(
            row_frame,
            text=finding_id[:8],
            font=("Roboto", 9),
            text_color=COLORS['text_secondary']
        )
        id_label.grid(row=0, column=0, padx=12, pady=6, sticky="w")

        # Name
        name_label = ctk.CTkLabel(
            row_frame,
            text=name[:40],
            font=("Roboto", 10),
            text_color=COLORS['text']
        )
        name_label.grid(row=0, column=1, padx=12, pady=6, sticky="ew")

        # Confidence with color
        conf_color = self._get_confidence_color(confidence)
        conf_label = ctk.CTkLabel(
            row_frame,
            text=f"{confidence:.0%}",
            font=("Roboto", 10, "bold"),
            text_color=conf_color
        )
        conf_label.grid(row=0, column=2, padx=12, pady=6, sticky="e")

        # Type
        type_label = ctk.CTkLabel(
            row_frame,
            text=finding_type[:15],
            font=("Roboto", 9),
            text_color=COLORS['text_secondary']
        )
        type_label.grid(row=0, column=3, padx=12, pady=6, sticky="e")

        if on_click:
            row_frame.configure(cursor="hand2")
            # Create a wrapper to handle selection
            def on_row_click(event=None):
                self._select_row(row_frame)
                on_click()

            row_frame.bind("<Button-1>", on_row_click)
            # Also bind child widgets to propagate clicks
            for child in row_frame.winfo_children():
                child.bind("<Button-1>", on_row_click)

        self.row_count += 1

    def _select_row(self, row_frame):
        """Highlight a row as selected."""
        # Deselect previous row
        if self.selected_row_frame:
            self.selected_row_frame.configure(fg_color="transparent")

        # Select new row
        row_frame.configure(fg_color=COLORS['primary_hover'])
        self.selected_row_frame = row_frame

    def clear_table(self):
        """Clear all rows from the table."""
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        self.row_frames.clear()
        self.selected_row_frame = None
        self.row_count = 0

    @staticmethod
    def _get_confidence_color(confidence: float) -> str:
        """Get color based on confidence level."""
        if confidence >= 0.8:
            return '#28A745'  # green
        elif confidence >= 0.5:
            return '#FFC107'  # yellow
        else:
            return '#DC3545'  # red


# ============ CopyButton ============
class CopyButton(ctk.CTkButton):
    """
    Button that copies text to clipboard when clicked.

    Example:
        copy_btn = CopyButton(parent, text="Copy Address", copy_text="0x1234...")
        copy_btn.pack(padx=10, pady=10)
    """

    def __init__(
        self,
        master,
        copy_text: str = "",
        feedback_text: str = "Copied!",
        **kwargs
    ):
        """
        Initialize the copy button.

        Args:
            master: Parent widget
            copy_text: Text to copy to clipboard
            feedback_text: Text to show briefly after copying
        """
        super().__init__(master, **kwargs)

        self.copy_text = copy_text
        self.feedback_text = feedback_text
        self.original_text = self.cget("text") or "Copy"
        self.configure(command=self._copy)

    def _copy(self):
        """Copy text and show feedback."""
        try:
            # Copy to clipboard
            self.master.clipboard_clear()
            self.master.clipboard_append(self.copy_text)

            # Show feedback
            original = self.original_text
            self.configure(text=self.feedback_text, state="disabled")
            self.after(1500, lambda: self.configure(
                text=original,
                state="normal"
            ))
        except Exception as e:
            print(f"Error copying: {e}")


# ============ SectionHeader ============
class SectionHeader(ctk.CTkFrame):
    """
    Header for a section with title and optional action button.

    Example:
        header = SectionHeader(
            parent,
            title="Static Findings",
            button_text="Export",
            button_command=self._export
        )
        header.pack(fill="x", padx=10, pady=10)
    """

    def __init__(
        self,
        master,
        title: str = "",
        button_text: Optional[str] = None,
        button_command: Optional[Callable] = None,
        **kwargs
    ):
        """Initialize the section header."""
        super().__init__(
            master,
            fg_color="transparent",
            **kwargs
        )

        self.grid_columnconfigure(1, weight=1)

        # Title
        title_label = ctk.CTkLabel(
            self,
            text=title,
            font=("Roboto", 14, "bold"),
            text_color=COLORS['text']
        )
        title_label.grid(row=0, column=0, sticky="w")

        # Optional button
        if button_text and button_command:
            btn = ctk.CTkButton(
                self,
                text=button_text,
                command=button_command,
                width=100,
                height=28,
                font=("Roboto", 10),
                fg_color=COLORS['primary'],
                hover_color=COLORS['primary_hover']
            )
            btn.grid(row=0, column=1, sticky="e")
