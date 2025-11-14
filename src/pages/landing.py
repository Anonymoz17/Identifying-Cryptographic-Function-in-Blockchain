# src/pages/landing.py
"""
CryptoScope Landing Page
- Three horizontal cards: Setup, Detectors, Reports
- Responsive: cards scale with window; icons keep readable size
- Footer (copyright) pinned to bottom
- Uses ui.theme for colors/typography
"""

from pathlib import Path
from typing import Optional, Tuple

import customtkinter as ctk

# Pillow for image loading (CTkImage needs PIL.Image)
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
    """Load a CTkImage (RGBA) with graceful fallback if Pillow or the file is missing."""
    try:
        if Image is None or not path.exists():
            return None
        img = Image.open(path).convert("RGBA").resize(size, Image.LANCZOS)
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception:
        return None


class LandingPage(ctk.CTkFrame):
    """Main hub after login — gateway to Setup, Detectors, Reports."""

    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page

        # Keep refs to CTkImage objects so they don’t get GC’d
        self._img_refs: list[ctk.CTkImage] = []
        # Current icon size; updated on resize
        self._icon_px = 96

        # ===== Root layout (grid) =====
        # 3 rows: header (auto), content (expand), footer (auto)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)
        self.grid_columnconfigure(0, weight=1)

        # ===== HEADER =====
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(22, 10))
        header.grid_columnconfigure(0, weight=1)

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
        logout_btn.grid(row=0, column=1, rowspan=2, sticky="e")

        # ===== CONTENT WRAPPER (centers, caps max width) =====
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.grid(row=1, column=0, sticky="nsew")
        wrapper.grid_rowconfigure(0, weight=1)
        wrapper.grid_columnconfigure(0, weight=1)

        # Inner frame with a max width so cards don’t stretch too wide on large monitors
        self._maxw = 1200  # cap center content
        self._center = ctk.CTkFrame(wrapper, fg_color="transparent")
        self._center.grid(row=0, column=0)
        self._center.bind("<Configure>", lambda e: self._on_center_configure())

        # Cards row
        self.cards = ctk.CTkFrame(self._center, fg_color="transparent")
        self.cards.pack(fill="x", padx=24, pady=10)
        for i in range(3):
            self.cards.grid_columnconfigure(i, weight=1, uniform="cards")
        self.cards.grid_rowconfigure(0, weight=1)

        # Load initial icons
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
            desc_text="Pick input, set workspace and case ID. Start preprocessing and watch console when needed.",
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
            desc_text="Review findings, generate and export PDF/JSON/TXT reports for archival or sharing.",
            btn_text="Open Reports",
            icon=self._results_icon,
            command=lambda: self.switch_page("results"),
        )

        # Resize handling to keep things neat and responsive
        self.bind("<Configure>", self._on_resize)

        # ===== FOOTER (pinned to bottom) =====
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=24, pady=(10, 14))
        ctk.CTkLabel(
            footer,
            text="© 2025 CryptoScope — Blockchain Cryptographic Analysis Platform",
            font=("Segoe UI", 10),
            text_color=MUTED,
        ).pack(side="left")

    # ----- UI helpers -----
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
        # An inner frame to control padding/content layout
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=18, pady=18)

        # icon
        icon_label = ctk.CTkLabel(inner, image=icon, text="")
        icon_label.pack(anchor="center", pady=(4, 10))

        # title
        ctk.CTkLabel(inner, text=title_text, font=HEADING_FONT, text_color=TEXT).pack(
            anchor="center", pady=(0, 4)
        )

        # description (wrap updated on resize)
        desc = ctk.CTkLabel(
            inner, text=desc_text, font=BODY_FONT, text_color=MUTED, justify="center", wraplength=320
        )
        desc.pack(anchor="center", pady=(0, 12))

        # button
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

        # keep references for resize tuning
        card._icon_label = icon_label      # type: ignore[attr-defined]
        card._desc_label = desc            # type: ignore[attr-defined]
        return card

    def _on_center_configure(self):
        # Center content and cap max width
        # The parent (wrapper) decides where this sits; here we just ensure it's not super wide.
        try:
            parent = self._center.nametowidget(self._center.winfo_parent())
            pw = parent.winfo_width()
            cw = min(pw, self._maxw)
            # Place centered
            self._center.place(relx=0.5, rely=0.5, anchor="center", width=cw)
        except Exception:
            pass

    def _on_resize(self, _event=None):
        # Determine dynamic card width and adjust wrap + icon size.
        # Heuristic: make three equal columns within max width.
        try:
            total_w = self.winfo_width()
            usable = min(total_w - 48, self._maxw)  # account for side padding
            col_w = max(300, usable // 3 - 16)      # keep each card >= 300px wide

            # Update description wraplength per card so text doesn’t look cramped/wide
            wrap = max(260, min(360, col_w - 60))
            for card in (self._card_setup, self._card_detect, self._card_results):
                card._desc_label.configure(wraplength=wrap)  # type: ignore[attr-defined]

            # Update icon size: don’t shrink below 72 or exceed 112
            new_icon = max(72, min(112, int(col_w * 0.28)))
            if new_icon != self._icon_px:
                self._icon_px = new_icon
                self._reload_icons()
        except Exception:
            pass

    def _reload_icons(self):
        # Recreate CTkImages at the new size and set them back on the labels.
        setup_ic = _load_ctk_image(ICON_SETUP, (self._icon_px, self._icon_px))
        detect_ic = _load_ctk_image(ICON_DETECT, (self._icon_px, self._icon_px))
        results_ic = _load_ctk_image(ICON_RESULTS, (self._icon_px, self._icon_px))
        fresh = [setup_ic, detect_ic, results_ic]
        # keep references to avoid GC
        self._img_refs = [ic for ic in fresh if ic]
        if setup_ic:
            self._card_setup._icon_label.configure(image=setup_ic)      # type: ignore[attr-defined]
        if detect_ic:
            self._card_detect._icon_label.configure(image=detect_ic)    # type: ignore[attr-defined]
        if results_ic:
            self._card_results._icon_label.configure(image=results_ic)  # type: ignore[attr-defined]
