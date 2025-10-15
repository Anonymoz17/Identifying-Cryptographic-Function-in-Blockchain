# pages/reports.py
import customtkinter as ctk

from roles import is_premium
from ui.card import Card
from ui.grid import grid_evenly


class ReportsPage(ctk.CTkFrame):
    def __init__(self, master, switch_page, get_role, export_json_cb, export_pdf_cb):
        super().__init__(master)
        self.get_role = get_role
        self.export_json_cb = export_json_cb
        self.export_pdf_cb = export_pdf_cb

        title = ctk.CTkLabel(self, text="Reports", font=("Roboto", 28, "bold"))
        title.pack(anchor="w", padx=24, pady=(16, 8))

        self.wrap = ctk.CTkFrame(self, fg_color="transparent")
        self.wrap.pack(fill="both", expand=True, padx=24, pady=12)
        self.wrap.grid_columnconfigure(0, weight=1)

        # Cards container (grid)
        self.cards_frame = ctk.CTkFrame(self.wrap, fg_color="transparent")
        self.cards_frame.pack(fill="both", expand=False)

        # Create cards (always the same)
        self.card_json = Card(
            self.cards_frame,
            title="Export JSON",
            subtitle="Machine-readable report for pipelines",
            command=self.export_json_cb,
        )

        self.card_pdf = Card(
            self.cards_frame,
            title="Export PDF",
            subtitle="Polished, ready-to-share report",
            command=self.export_pdf_cb,
        )

        self.cards = [self.card_json, self.card_pdf]

        # Initial layout & role application
        self._layout()
        self.apply_role(self.get_role())

        # Make it responsive: recompute columns on resize
        self.bind("<Configure>", self._on_resize)

    def apply_role(self, role: str | None):
        premium = is_premium(role)
        self.card_pdf.set_locked(not premium, "🔒 Premium feature")

    def _layout(self):
        # Simple breakpoint: 1 col on narrow screens, else 2
        w = max(self.winfo_width(), 1)
        num_cols = 1 if w < 640 else 2
        grid_evenly(self.cards_frame, self.cards, num_cols=num_cols)

    def _on_resize(self, _evt):
        self._layout()
