# src/pages/landing.py
"""
CryptoScope Landing Page
- Three horizontal cards: Setup, Detectors, Reports
- Responsive with grid only (no place/pack mixing)
- Footer pinned to bottom
- Uses ui.theme
- Includes top-right Account Bubble (human silhouette)
"""

from pathlib import Path
from typing import Optional, Tuple

import customtkinter as ctk

# Pillow for CTkImage
try:
    from PIL import Image
except Exception:
    Image = None  # type: ignore

from ui.theme import (
    BG,
    TEXT,
    MUTED,
    BORDER,
    CARD_BG,
    OUTLINE_BR,
    OUTLINE_H,
    PRIMARY,
    PRIMARY_H,
    TITLE_FONT,
    HEADING_FONT,
    BODY_FONT,
)

ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"
ICON_SETUP = ASSETS_DIR / "icon_setup.png"
ICON_DETECT = ASSETS_DIR / "icon_detectors.png"
ICON_RESULTS = ASSETS_DIR / "icon_results.png"


def _load_ctk_image(path: Path, size: Tuple[int, int]) -> Optional[ctk.CTkImage]:
    """Load a CTkImage with graceful fallback (returns None if missing)."""
    try:
        if Image is None or not path.exists():
            return None
        img = Image.open(path).convert("RGBA").resize(size, Image.LANCZOS)
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception:
        return None


class LandingPage(ctk.CTkFrame):
    """Hub → Setup, Detectors, Reports, with account bubble."""

    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page

        # Keep CTkImage refs
        self._img_refs: list[ctk.CTkImage] = []
        self._icon_px = 96
        self._maxw = 1200  # cap content width
        self._acct_win: Optional[ctk.CTkToplevel] = None

        # ===== Root grid: header, content, footer =====
        self.grid_rowconfigure(0, weight=0)  # header
        self.grid_rowconfigure(1, weight=1)  # content
        self.grid_rowconfigure(2, weight=0)  # footer
        self.grid_columnconfigure(0, weight=1)

        # ===== HEADER =====
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(22, 10))
        header.grid_columnconfigure(0, weight=1)
        header.grid_columnconfigure(1, weight=0)
        header.grid_columnconfigure(2, weight=0)

        title = ctk.CTkLabel(header, text="CryptoScope", font=TITLE_FONT, text_color=TEXT)
        subtitle = ctk.CTkLabel(
            header,
            text="Identify, analyze, and audit cryptographic functions across blockchain projects.",
            font=("Segoe UI", 12),
            text_color=MUTED,
            wraplength=900,
        )
        title.grid(row=0, column=0, sticky="w")
        subtitle.grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Logout button
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
        logout_btn.grid(row=0, column=1, rowspan=2, padx=(12, 0), sticky="e")

        # Account bubble (human silhouette)
        acct_btn = ctk.CTkButton(
            header,
            text="👤",
            width=40,
            height=32,
            corner_radius=16,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=self._toggle_account_bubble,
        )
        acct_btn.grid(row=0, column=2, rowspan=2, padx=(10, 0), sticky="e")

        # ===== CONTENT WRAPPER =====
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)

        center = ctk.CTkFrame(content, fg_color="transparent")
        center.grid(row=0, column=0, sticky="n")
        # Centering helpers
        center.grid_columnconfigure(0, weight=1)
        center.grid_columnconfigure(1, weight=0)  # holds cards
        center.grid_columnconfigure(2, weight=1)

        # Row that holds the 3 cards
        self.cards = ctk.CTkFrame(center, fg_color="transparent")
        self.cards.grid(row=0, column=1, sticky="n", padx=24, pady=(10, 10))
        for i in range(3):
            self.cards.grid_columnconfigure(i, weight=1, uniform="cards")
        self.cards.grid_rowconfigure(0, weight=1)

        # Load icons (initial size)
        self._setup_icon = _load_ctk_image(ICON_SETUP, (self._icon_px, self._icon_px))
        self._detect_icon = _load_ctk_image(ICON_DETECT, (self._icon_px, self._icon_px))
        self._results_icon = _load_ctk_image(ICON_RESULTS, (self._icon_px, self._icon_px))
        for ic in (self._setup_icon, self._detect_icon, self._results_icon):
            if ic:
                self._img_refs.append(ic)

        # Build the three cards
        self._card_setup = self._create_card(
            col=0,
            title_text="Setup",
            desc_text="Pick input, set workspace and Case ID. Start preprocessing and view console when needed.\n",
            btn_text="Open Setup",
            icon=self._setup_icon,
            command=lambda: self.switch_page("setup"),
        )
        self._card_detect = self._create_card(
            col=1,
            title_text="Detectors",
            desc_text="Run static detections on prepared inputs. See algorithms, libraries, locations, evidence and confidence.",
            btn_text="Open Detectors",
            icon=self._detect_icon,
            command=lambda: self.switch_page("detectors"),
        )
        self._card_results = self._create_card(
            col=2,
            title_text="Reports",
            desc_text="Review findings, generate and export PDF/JSON/TXT reports for archival or sharing.\n",
            btn_text="Open Reports",
            icon=self._results_icon,
            command=lambda: self.switch_page("results"),
        )

        # Keep responsive without mixing geometry managers
        self.bind("<Configure>", self._on_resize)

        # ===== FOOTER (pinned) =====
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=24, pady=(10, 14))
        ctk.CTkLabel(
            footer,
            text="© 2025 CryptoScope — Blockchain Cryptographic Analysis Platform",
            font=("Segoe UI", 10),
            text_color=MUTED,
        ).pack(side="left")

    # ----- Helpers -----
    def _create_card(self, col: int, title_text: str, desc_text: str, btn_text: str,
                     icon: Optional[ctk.CTkImage], command):
        card = ctk.CTkFrame(
            self.cards,
            corner_radius=14,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        card.grid(row=0, column=col, padx=10, pady=6, sticky="nsew")

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=18, pady=18)

        # Light plate behind icon to pop on dark BG
        plate = ctk.CTkFrame(inner, fg_color="#0f172a", corner_radius=12)  # slightly lighter than page
        plate.pack(anchor="center")
        plate.pack_propagate(False)
        plate.configure(width=140, height=140)

        icon_label = ctk.CTkLabel(plate, image=icon, text="")
        icon_label.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(inner, text=title_text, font=HEADING_FONT, text_color=TEXT).pack(
            anchor="center", pady=(12, 4)
        )

        desc = ctk.CTkLabel(
            inner, text=desc_text, font=BODY_FONT, text_color=MUTED, justify="center", wraplength=320
        )
        desc.pack(anchor="center", pady=(0, 12))

        btn = ctk.CTkButton(
            inner,
            text=btn_text,
            width=160,
            height=36,
            corner_radius=10,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=command,
        )
        btn.pack(anchor="center")

        # keep refs for resize tuning
        card._icon_label = icon_label      # type: ignore[attr-defined]
        card._desc_label = desc            # type: ignore[attr-defined]
        card._plate = plate                # type: ignore[attr-defined]
        return card

    def _on_resize(self, _event=None):
        """Keep cards readable; dynamically adjust description wrap & icon size."""
        try:
            total_w = self.winfo_width()
            usable = min(total_w - 48, self._maxw)
            col_w = max(300, usable // 3 - 16)

            # Keep the plate and icon proportionate
            plate_size = max(110, min(170, int(col_w * 0.38)))
            icon_px = max(72, min(128, int(plate_size * 0.66)))

            wrap = max(260, min(380, col_w - 60))
            for card in (self._card_setup, self._card_detect, self._card_results):
                card._desc_label.configure(wraplength=wrap)  # type: ignore[attr-defined]
                card._plate.configure(width=plate_size, height=plate_size)  # type: ignore[attr-defined]

            if icon_px != self._icon_px:
                self._icon_px = icon_px
                self._reload_icons()
        except Exception:
            pass

    def _reload_icons(self):
        setup_ic = _load_ctk_image(ICON_SETUP, (self._icon_px, self._icon_px))
        detect_ic = _load_ctk_image(ICON_DETECT, (self._icon_px, self._icon_px))
        results_ic = _load_ctk_image(ICON_RESULTS, (self._icon_px, self._icon_px))
        fresh = [setup_ic, detect_ic, results_ic]
        self._img_refs = [ic for ic in fresh if ic]
        if setup_ic:
            self._card_setup._icon_label.configure(image=setup_ic)      # type: ignore[attr-defined]
        if detect_ic:
            self._card_detect._icon_label.configure(image=detect_ic)    # type: ignore[attr-defined]
        if results_ic:
            self._card_results._icon_label.configure(image=results_ic)  # type: ignore[attr-defined]

    # ===== Account bubble =====
    def _toggle_account_bubble(self):
        """Open/close a small profile window with user info. Safe defaults if app has no user."""
        if self._acct_win and self._acct_win.winfo_exists():
            self._acct_win.destroy()
            self._acct_win = None
            return

        app = self.winfo_toplevel()
        # Try to fetch details from app; fall back to safe defaults
        user = getattr(app, "current_user", {}) or {}
        email = user.get("email") or getattr(app, "user_email", "user@example.com")
        name = user.get("name") or getattr(app, "user_name", "User")
        tier = getattr(app, "account_tier", "Free")

        win = ctk.CTkToplevel(self)
        win.title("Account")
        win.transient(app)  # behave like a small panel
        win.resizable(False, False)
        win.configure(fg_color=BG)
        self._acct_win = win

        # Layout
        win.grid_columnconfigure(0, weight=1)
        header = ctk.CTkLabel(win, text="👤  Account", font=HEADING_FONT, text_color=TEXT)
        header.grid(row=0, column=0, sticky="w", padx=16, pady=(16, 8))

        body = ctk.CTkFrame(win, fg_color=CARD_BG, corner_radius=12, border_width=1, border_color=BORDER)
        body.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 12))
        body.grid_columnconfigure(1, weight=1)

        def row(r, k, v):
            ctk.CTkLabel(body, text=k, font=BODY_FONT, text_color=MUTED).grid(row=r, column=0, sticky="w", padx=12, pady=6)
            ctk.CTkLabel(body, text=v, font=BODY_FONT, text_color=TEXT).grid(row=r, column=1, sticky="w", padx=12, pady=6)

        row(0, "Name", name)
        row(1, "Email", email)
        row(2, "Plan", tier)

        btns = ctk.CTkFrame(win, fg_color="transparent")
        btns.grid(row=2, column=0, sticky="e", padx=16, pady=(0, 14))

        ctk.CTkButton(
            btns,
            text="Close",
            width=80,
            height=30,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: (win.destroy(), setattr(self, "_acct_win", None)),
        ).pack(side="right")
