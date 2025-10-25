# src/pages/landing.py
"""
CryptoScope Landing Page
Unified with theme.py palette.
"""

import customtkinter as ctk
from ui.theme import (
    BG, CARD_BG, BORDER, TEXT, MUTED,
    PRIMARY, PRIMARY_H, OUTLINE_BR, OUTLINE_H,
    TITLE_FONT, HEADING_FONT, BODY_FONT
)


class LandingPage(ctk.CTkFrame):
    """Main hub after login — gateway to Dashboard, Advisor, Auditor, Reports."""

    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page

        # === HEADER ===
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(24, 12))

        title = ctk.CTkLabel(header, text="CryptoScope", font=TITLE_FONT, text_color=TEXT)
        subtitle = ctk.CTkLabel(
            header,
            text="Identify, analyze, and audit cryptographic functions across blockchain projects.",
            font=("Segoe UI", 13),
            text_color=MUTED,
            wraplength=800,
        )
        title.grid(row=0, column=0, sticky="w")
        subtitle.grid(row=1, column=0, sticky="w", pady=(4, 0))

        logout_btn = ctk.CTkButton(
            header,
            text="Logout",
            width=90,
            height=32,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: self.winfo_toplevel().logout(),
        )
        header.grid_columnconfigure(0, weight=1)
        logout_btn.grid(row=0, column=1, rowspan=2, sticky="e")

        # === BODY / MAIN SECTIONS ===
        grid = ctk.CTkFrame(self, fg_color=BG)
        grid.pack(fill="both", expand=True, padx=40, pady=(10, 30))
        grid.grid_columnconfigure((0, 1), weight=1)
        grid.grid_rowconfigure((0, 1), weight=1)

        # Card generator
        def create_card(title_text, desc_text, button_text, command, row, col):
            card = ctk.CTkFrame(
                grid,
                corner_radius=12,
                border_width=1,
                border_color=BORDER,
                fg_color=CARD_BG,
            )
            card.grid(row=row, column=col, padx=20, pady=20, sticky="nsew")
            card.grid_propagate(False)
            card.configure(height=200, width=350)

            ctk.CTkLabel(
                card,
                text=title_text,
                font=HEADING_FONT,
                text_color=TEXT,
            ).pack(anchor="w", padx=20, pady=(18, 4))

            ctk.CTkLabel(
                card,
                text=desc_text,
                font=BODY_FONT,
                text_color=MUTED,
                wraplength=300,
                justify="left",
            ).pack(anchor="w", padx=20, pady=(0, 16))

            ctk.CTkButton(
                card,
                text=button_text,
                width=140,
                height=36,
                corner_radius=8,
                fg_color=PRIMARY,
                hover_color=PRIMARY_H,
                text_color="#041007",
                command=command,
            ).pack(anchor="center")

        # === PAGE CARDS ===
        create_card(
            "Analyse",
            "Upload files or scan GitHub repositories for cryptographic analysis.",
            "Open Dashboard",
            lambda: self.switch_page("dashboard"),
            0, 0,
        )

        create_card(
            "Advisor",
            "Access recommendations and migration strategies for detected algorithms.",
            "Open Advisor",
            lambda: self.switch_page("advisor"),
            0, 1,
        )

        create_card(
            "Auditor",
            "Audit compliance of blockchain projects with cryptographic standards.",
            "Open Auditor",
            lambda: self.switch_page("auditor"),
            1, 0,
        )

        create_card(
            "Reports",
            "View and export previous analysis results as JSON or PDF summaries.",
            "Open Reports",
            lambda: self.switch_page("reports"),
            1, 1,
        )

        # === FOOTER ===
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=40, pady=(0, 16))

        ctk.CTkLabel(
            footer,
            text="© 2025 CryptoScope — Blockchain Cryptographic Analysis Platform",
            font=("Segoe UI", 10),
            text_color=MUTED,
        ).pack(side="left")
