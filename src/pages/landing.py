# pages/landing.py
import customtkinter as ctk

from ui.card import Card
from ui.grid import grid_evenly
from roles import is_premium


class LandingPage(ctk.CTkFrame):
    """
    Styled like Login/Register:
    - Centered card with rounded corners and subtle border
    - Function tiles arranged in a tidy grid inside the card
    - Logout button at bottom right
    """

    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        # ===== Base layout (center container) =====
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center")

        # ===== Main card =====
        self.card = ctk.CTkFrame(
            container,
            corner_radius=16,
            border_width=1,
            border_color="#374151",
            fg_color=("#111827", "#111827"),  # dark gray like login
        )
        self.card.grid(row=0, column=0, padx=16, pady=16, sticky="nsew")
        self.card.grid_columnconfigure(0, weight=1)

        # ===== Header =====
        title = ctk.CTkLabel(
            self.card,
            text="Welcome to CryptoScope",
            font=("Segoe UI", 24, "bold"),
            text_color="#E5E7EB",
        )
        subtitle = ctk.CTkLabel(
            self.card,
            text="Select a feature to get started",
            font=("Segoe UI", 12),
            text_color="#9CA3AF",
        )
        title.grid(row=0, column=0, padx=20, pady=(20, 4), sticky="w")
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # ===== Tiles area =====
        self.tiles_wrap = ctk.CTkFrame(self.card, fg_color="transparent")
        self.tiles_wrap.grid(row=2, column=0, padx=20, pady=(4, 10), sticky="ew")
        self.tiles_wrap.grid_columnconfigure(0, weight=1)

        self.tiles = []
        self._build_tiles()

        # ===== Divider =====
        ctk.CTkFrame(self.card, height=1, fg_color="#1F2937").grid(
            row=3, column=0, padx=20, pady=(8, 8), sticky="ew"
        )

        # ===== Logout =====
        self.logout_btn = ctk.CTkButton(
            self.card,
            text="Logout",
            height=32,
            width=100,
            corner_radius=8,
            fg_color="transparent",
            hover_color="#1F2937",
            border_width=1,
            border_color="#374151",
            text_color="#E5E7EB",
            command=lambda: self.winfo_toplevel().logout(),
        )
        self.logout_btn.grid(row=4, column=0, padx=20, pady=(6, 16), sticky="e")

        # initial layout
        self._cols = None
        self._layout_tiles()
        self.bind("<Configure>", lambda e: self._layout_tiles())

    # -------------------------------------------------------------------------
    def _build_tiles(self):
        """Build tile cards that lead to the other pages."""
        app = self.winfo_toplevel()
        role = getattr(app, "current_user_role", None)
        premium = is_premium(role)

        def _tile(title, subtitle, target, premium_only=False):
            card = Card(
                self.tiles_wrap,
                title=title,
                subtitle=subtitle,
                command=lambda: self.switch_page(target),
                min_h=130,
            )
            if premium_only and not premium:
                card.set_locked(True, "🔒 Premium feature")
            self.tiles.append(card)

        # Main actions
        _tile("Upload / Analyze", "Add files or GitHub repo", "dashboard")
        _tile("Analysis", "View uploaded files and run analysis", "analysis")
        _tile("Advisor", "Compare crypto algorithms", "advisor")
        _tile("Auditor", "Start engagements & audits", "auditor")
        _tile("Reports", "Export JSON / PDF", "reports", premium_only=False)

    # -------------------------------------------------------------------------
    def _layout_tiles(self):
        w = max(self.winfo_width(), 1)
        cols = 1 if w < 720 else (2 if w < 1000 else 3)
        if cols != self._cols:
            self._cols = cols
            grid_evenly(self.tiles_wrap, self.tiles, num_cols=cols)

    # -------------------------------------------------------------------------
    def on_enter(self):
        self._layout_tiles()

    def on_resize(self, w, h):
        self._layout_tiles()
