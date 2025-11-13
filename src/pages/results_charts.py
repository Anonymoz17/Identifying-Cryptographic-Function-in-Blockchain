"""Visualization engine for Results Page charts.

Provides matplotlib-based charts that display analysis statistics.
Charts are rendered as images and integrated into CTK frames.
"""

from typing import TYPE_CHECKING, Optional, Dict, Any, List
import customtkinter as ctk
from PIL import Image, ImageDraw
import io
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.backends.backend_agg import FigureCanvasAgg

if TYPE_CHECKING:
    from pages.results_model import ResultsDataModel

# Use non-interactive backend
matplotlib.use('Agg')

# Chart styling to match dark theme
CHART_STYLE = {
    'bg_color': '#0F1117',
    'text_color': '#DDE2E8',
    'grid_color': '#30363D',
    'primary_color': '#0066CC',
    'primary_light': '#3384FF',
    'success_color': '#28A745',
    'danger_color': '#DC3545',
    'warning_color': '#FFC107',
    'chart_edge': '#FFFFFF',
}


class VisualizationEngine:
    """Generates matplotlib charts compatible with CTK."""

    @staticmethod
    def _setup_style():
        """Configure matplotlib style for dark theme."""
        plt.rcParams['figure.facecolor'] = CHART_STYLE['bg_color']
        plt.rcParams['axes.facecolor'] = CHART_STYLE['bg_color']
        plt.rcParams['axes.edgecolor'] = CHART_STYLE['grid_color']
        plt.rcParams['text.color'] = CHART_STYLE['text_color']
        plt.rcParams['axes.labelcolor'] = CHART_STYLE['text_color']
        plt.rcParams['xtick.color'] = CHART_STYLE['text_color']
        plt.rcParams['ytick.color'] = CHART_STYLE['text_color']
        plt.rcParams['grid.color'] = CHART_STYLE['grid_color']
        plt.rcParams['legend.facecolor'] = CHART_STYLE['bg_color']
        plt.rcParams['legend.edgecolor'] = CHART_STYLE['grid_color']

    @staticmethod
    def figure_to_image(fig, width: int = 400, height: int = 300) -> Image.Image:
        """Convert matplotlib figure to PIL Image."""
        # Set explicit figure size and DPI
        dpi = 100
        fig.set_dpi(dpi)
        fig.set_size_inches(width / dpi, height / dpi)

        # Draw the figure
        canvas = FigureCanvasAgg(fig)
        canvas.draw()

        # Get raw data from buffer - canvas size should match fig size
        buf = canvas.buffer_rgba()
        canvas_width, canvas_height = canvas.get_width_height()

        # Convert RGBA buffer to PIL Image
        img = Image.frombytes('RGBA', (canvas_width, canvas_height), buf, 'raw', 'RGBA', 0, 1)

        # Convert RGBA to RGB
        img = img.convert('RGB')

        # Always resize to target dimensions to ensure consistency
        if img.size != (width, height):
            img = img.resize((width, height), Image.Resampling.LANCZOS)

        return img

    @staticmethod
    def create_confidence_histogram(findings: List[Any], width: int = 450, height: int = 340) -> Optional[Image.Image]:
        """Create histogram of finding confidence scores.

        Args:
            findings: List of Finding objects with confidence attribute
            width: Image width (optimized for 450px)
            height: Image height (optimized for 340px)

        Returns:
            PIL Image or None if no findings
        """
        if not findings:
            return None

        VisualizationEngine._setup_style()

        confidences = [f.confidence * 100 for f in findings]

        fig, ax = plt.subplots(figsize=(6, 4.5), dpi=80)
        bars = ax.hist(confidences, bins=10, color=CHART_STYLE['primary_color'],
                       edgecolor=CHART_STYLE['chart_edge'], alpha=0.85, linewidth=1.5)

        ax.set_xlabel('Confidence (%)', color=CHART_STYLE['text_color'], fontsize=10)
        ax.set_ylabel('Count', color=CHART_STYLE['text_color'], fontsize=10)
        ax.set_title('Finding Confidence Distribution', color=CHART_STYLE['text_color'],
                    fontsize=12, fontweight='bold', pad=15)
        ax.grid(True, alpha=0.25, color=CHART_STYLE['grid_color'], linestyle='--', linewidth=0.5)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color(CHART_STYLE['grid_color'])
        ax.spines['bottom'].set_color(CHART_STYLE['grid_color'])

        fig.subplots_adjust(left=0.1, right=0.95, top=0.88, bottom=0.12)

        img = VisualizationEngine.figure_to_image(fig, width, height)
        plt.close(fig)

        return img

    @staticmethod
    def create_finding_types_pie(stats: Dict[str, Any], width: int = 450, height: int = 340) -> Optional[Image.Image]:
        """Create pie chart of finding types.

        Args:
            stats: Statistics dict containing 'static' -> 'by_type' data
            width: Image width (optimized for 450px)
            height: Image height (optimized for 340px)

        Returns:
            PIL Image or None if no data
        """
        if not stats or 'static' not in stats or 'by_type' not in stats['static']:
            return None

        by_type = stats['static']['by_type']
        if not by_type:
            return None

        VisualizationEngine._setup_style()

        types = list(by_type.keys())
        counts = list(by_type.values())

        # Color palette for pie chart
        colors = [
            CHART_STYLE['primary_color'],
            CHART_STYLE['success_color'],
            CHART_STYLE['warning_color'],
            CHART_STYLE['danger_color'],
            '#6366F1',
            '#EC4899',
            '#14B8A6',
            '#8B5CF6',
        ]
        colors = (colors * ((len(types) // len(colors)) + 1))[:len(types)]

        fig, ax = plt.subplots(figsize=(5, 4), dpi=80)
        wedges, texts, autotexts = ax.pie(
            counts,
            labels=types,
            autopct='%1.1f%%',
            colors=colors,
            wedgeprops={'edgecolor': CHART_STYLE['bg_color'], 'linewidth': 2},
            textprops={'color': CHART_STYLE['text_color'], 'fontsize': 9, 'weight': 'bold'}
        )

        # Style percentage text
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(8)

        ax.set_title('Finding Types Breakdown', color=CHART_STYLE['text_color'],
                    fontsize=12, fontweight='bold', pad=15)

        fig.subplots_adjust(left=0.1, right=0.95, top=0.9, bottom=0.1)

        img = VisualizationEngine.figure_to_image(fig, width, height)
        plt.close(fig)

        return img

    @staticmethod
    def create_top_patterns_bar(stats: Dict[str, Any], top_n: int = 8, width: int = 450, height: int = 340) -> Optional[Image.Image]:
        """Create bar chart of top finding patterns.

        Args:
            stats: Statistics dict containing 'static' -> 'by_type' data
            top_n: Number of top patterns to show
            width: Image width (optimized for 450px)
            height: Image height (optimized for 340px)

        Returns:
            PIL Image or None if no data
        """
        if not stats or 'static' not in stats or 'by_type' not in stats['static']:
            return None

        by_type = stats['static']['by_type']
        if not by_type:
            return None

        VisualizationEngine._setup_style()

        # Sort by count and take top N
        sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:top_n]
        types = [t[0] for t in sorted_types]
        counts = [t[1] for t in sorted_types]

        fig, ax = plt.subplots(figsize=(6, 4.5), dpi=80)
        bars = ax.barh(types, counts, color=CHART_STYLE['success_color'],
                       edgecolor=CHART_STYLE['chart_edge'], alpha=0.85, linewidth=1.5)

        # Add value labels on bars
        for i, (bar, count) in enumerate(zip(bars, counts)):
            ax.text(count + 0.2, bar.get_y() + bar.get_height() / 2, str(count),
                   va='center', color=CHART_STYLE['success_color'], fontsize=9, fontweight='bold')

        ax.set_xlabel('Count', color=CHART_STYLE['text_color'], fontsize=10)
        ax.set_title(f'Top {len(types)} Finding Types', color=CHART_STYLE['text_color'],
                    fontsize=12, fontweight='bold', pad=15)
        ax.grid(True, alpha=0.25, axis='x', color=CHART_STYLE['grid_color'], linestyle='--', linewidth=0.5)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color(CHART_STYLE['grid_color'])
        ax.spines['bottom'].set_color(CHART_STYLE['grid_color'])
        ax.invert_yaxis()

        fig.subplots_adjust(left=0.2, right=0.95, top=0.88, bottom=0.12)

        img = VisualizationEngine.figure_to_image(fig, width, height)
        plt.close(fig)

        return img

    @staticmethod
    def create_execution_timeline(dynamic_calls: List[Any], width: int = 450, height: int = 340) -> Optional[Image.Image]:
        """Create execution timeline chart for static analysis.

        Args:
            static_calls: List of DynamicCall objects with timestamps
            width: Image width (optimized for 450px)
            height: Image height (optimized for 340px)

        Returns:
            PIL Image or None if no data
        """
        if not static_calls:
            return None

        VisualizationEngine._setup_style()

        # Count calls by type
        by_type = {}
        for call in static_calls:
            call_type = getattr(call, 'call_type', 'unknown')
            by_type[call_type] = by_type.get(call_type, 0) + 1

        types = list(by_type.keys())
        counts = list(by_type.values())

        fig, ax = plt.subplots(figsize=(6, 4.5), dpi=80)

        if len(types) > 0:
            bars = ax.bar(range(len(types)), counts, color=CHART_STYLE['primary_color'],
                         edgecolor=CHART_STYLE['chart_edge'], alpha=0.85, linewidth=1.5)

            # Add value labels on bars
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                if height > 0:
                    ax.text(bar.get_x() + bar.get_width() / 2., height + 0.1,
                           str(int(count)), ha='center', va='bottom',
                           color=CHART_STYLE['primary_color'], fontsize=9, fontweight='bold')

        ax.set_xticks(range(len(types)) if types else [])
        ax.set_xticklabels(types, rotation=45, ha='right', fontsize=9)
        ax.set_ylabel('Count', color=CHART_STYLE['text_color'], fontsize=10)
        ax.set_title('Dynamic Call Types Frequency', color=CHART_STYLE['text_color'],
                    fontsize=12, fontweight='bold', pad=15)
        ax.grid(True, alpha=0.25, axis='y', color=CHART_STYLE['grid_color'], linestyle='--', linewidth=0.5)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color(CHART_STYLE['grid_color'])
        ax.spines['bottom'].set_color(CHART_STYLE['grid_color'])

        fig.subplots_adjust(left=0.1, right=0.95, top=0.88, bottom=0.15)

        img = VisualizationEngine.figure_to_image(fig, width, height)
        plt.close(fig)

        return img


class ChartPanel(ctk.CTkFrame):
    """Frame that displays a chart image with title."""

    def __init__(self, master, title: str = "", width: int = 420, height: int = 320, **kwargs):
        """Initialize chart panel.

        Args:
            master: Parent widget
            title: Chart title
            width: Chart display width (default 420px for better visibility)
            height: Chart display height (default 320px for better visibility)
        """
        super().__init__(master, fg_color='#1E2631', corner_radius=8, border_width=1, border_color='#30363D', **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Store dimensions for responsive sizing
        self.chart_width = width
        self.chart_height = height

        # Title with icon
        title_label = ctk.CTkLabel(
            self,
            text=title,
            font=('Roboto', 11, 'bold'),
            text_color='#DDE2E8'
        )
        title_label.grid(row=0, column=0, sticky='ew', padx=12, pady=(10, 6))

        # Image label with padding for better visibility
        self.image_label = ctk.CTkLabel(
            self,
            text='',
            fg_color='#0F1117',
            corner_radius=4
        )
        self.image_label.grid(row=1, column=0, sticky='nsew', padx=10, pady=(0, 10))

    def set_image(self, pil_image: Optional[Image.Image]):
        """Set the chart image.

        Args:
            pil_image: PIL Image object or None
        """
        if pil_image is None:
            self.image_label.configure(text='No data available', text_color='#8A94A6')
        else:
            # Convert PIL image to CTK image with responsive sizing
            ctk_image = ctk.CTkImage(pil_image, size=(self.chart_width, self.chart_height))
            self.image_label.configure(image=ctk_image, text='')
            # Keep reference to prevent garbage collection
            self.image_label.ctk_image = ctk_image


class VisualizationPanel(ctk.CTkFrame):
    """Right-side panel showing visualizations."""

    def __init__(self, master, **kwargs):
        """Initialize visualization panel."""
        super().__init__(master, fg_color='#0F1117', **kwargs)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Header frame
        header_frame = ctk.CTkFrame(self, fg_color='transparent', height=40)
        header_frame.pack(fill='x', padx=12, pady=(12, 8))
        header_frame.pack_propagate(False)

        header_label = ctk.CTkLabel(
            header_frame,
            text='📊 Analysis Visualizations',
            font=('Roboto', 12, 'bold'),
            text_color='#DDE2E8'
        )
        header_label.pack(side='left', padx=0, pady=0)

        # Scrollable frame for charts with better padding
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color='#0F1117'
        )
        self.scroll_frame.pack(fill='both', expand=True, padx=6, pady=(0, 8))
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        # Chart sizes optimized for visibility (increased from 380x280)
        # These sizes are now responsive and better utilize the panel space
        chart_width = 450
        chart_height = 340

        # Create chart panels with better spacing and visibility
        self.confidence_chart = ChartPanel(
            self.scroll_frame,
            title='📈 Confidence Distribution',
            width=chart_width,
            height=chart_height
        )
        self.confidence_chart.pack(fill='x', padx=0, pady=(0, 12))

        self.types_chart = ChartPanel(
            self.scroll_frame,
            title='🎯 Finding Types Breakdown',
            width=chart_width,
            height=chart_height
        )
        self.types_chart.pack(fill='x', padx=0, pady=(0, 12))

        self.patterns_chart = ChartPanel(
            self.scroll_frame,
            title='⭐ Top Finding Types',
            width=chart_width,
            height=chart_height
        )
        self.patterns_chart.pack(fill='x', padx=0, pady=0)

    def update_charts(self, data_model: 'ResultsDataModel'):
        """Update all charts with data from model.

        Args:
            data_model: ResultsDataModel instance
        """
        if not data_model:
            return

        # Get filtered findings for confidence chart
        findings = data_model.get_static_findings()
        if findings:
            conf_img = VisualizationEngine.create_confidence_histogram(findings, width=450, height=340)
            self.confidence_chart.set_image(conf_img)
        else:
            self.confidence_chart.set_image(None)

        # Get statistics for pie and bar charts
        stats = data_model.get_statistics()
        if stats:
            types_img = VisualizationEngine.create_finding_types_pie(stats, width=450, height=340)
            self.types_chart.set_image(types_img)

            patterns_img = VisualizationEngine.create_top_patterns_bar(stats, width=450, height=340)
            self.patterns_chart.set_image(patterns_img)
        else:
            self.types_chart.set_image(None)
            self.patterns_chart.set_image(None)
