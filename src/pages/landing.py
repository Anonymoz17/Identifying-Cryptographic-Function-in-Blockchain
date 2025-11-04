# src/pages/landing.py
"""
CryptoScope Landing Page — icon plates + larger icons + responsive layout.
"""
from pathlib import Path
from typing import Optional

import customtkinter as ctk

try:
    from PIL import Image
except Exception:
    Image = None  # type: ignore

from ui.theme import (
    BG, BODY_FONT, BORDER, CARD_BG, HEADING_FONT, MUTED,
    OUTLINE_BR, OUTLINE_H, PRIMARY, PRIMARY_H, TEXT, TITLE_FONT,
    PLATE_BG, PLATE_BORDER,   # <-- added
)

ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"


def _load_ctk_image(path: Path, size: tuple[int, int]) -> Optional[ctk.CTkImage]:
    try:
        if Image is None or not path.exists():
            return None
        img = Image.open(path).convert("RGBA").resize(size, Image.LANCZOS)
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception:
        return None


class LandingPage(ctk.CTkFrame):
    """Main hub after login — gateway to Dashboard and Auditor."""

    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page
        self._img_refs: list[ctk.CTkImage] = []
        self._icon_analyze = None
        self._icon_auditor = None

        # ===== Header =====
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(24, 12))

        self.title_lbl = ctk.CTkLabel(header, text="CryptoScope", font=TITLE_FONT, text_color=TEXT)
        self.subtitle_lbl = ctk.CTkLabel(
            header,
            text="Identify, analyze, and audit cryptographic functions across blockchain projects.",
            font=BODY_FONT, text_color=MUTED, wraplength=800, justify="left",
        )
        self.title_lbl.grid(row=0, column=0, sticky="w")
        self.subtitle_lbl.grid(row=1, column=0, sticky="w", pady=(4, 0))

        logout_btn = ctk.CTkButton(
            header, text="Logout", width=90, height=32, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=OUTLINE_BR,
            hover_color=OUTLINE_H, text_color=TEXT,
            command=lambda: self.winfo_toplevel().logout(),
        )
        header.grid_columnconfigure(0, weight=1)
        logout_btn.grid(row=0, column=1, rowspan=2, sticky="e")

        # ===== Centering container (max width) =====
        center_wrap = ctk.CTkFrame(self, fg_color="transparent")
        center_wrap.pack(fill="both", expand=True, padx=20, pady=(6, 20))

        self.center = ctk.CTkFrame(center_wrap, fg_color="transparent")
        self.center.pack(expand=True)  # width set in _relayout()

        # ===== Cards grid =====
        self.grid_frame = ctk.CTkFrame(self.center, fg_color="transparent")
        self.grid_frame.pack(fill="x", expand=True)
        self.grid_frame.grid_columnconfigure((0, 1), weight=1)

        # preload icons (resized in _relayout)
        self._icon_analyze = _load_ctk_image(ASSETS_DIR / "icon_analyze.png", size=(64, 64))
        self._icon_auditor = _load_ctk_image(ASSETS_DIR / "icon_auditor.png", size=(64, 64))
        for ic in (self._icon_analyze, self._icon_auditor):
            if ic:
                self._img_refs.append(ic)

        # build cards
        self.card_analyze = self._create_card(
            parent=self.grid_frame,
            title_text="Analyse",
            desc_text="Upload files or scan GitHub repositories for cryptographic analysis.",
            button_text="Open Dashboard",
            command=lambda: self.switch_page("dashboard"),
            icon=self._icon_analyze,
            row=0, col=0,
        )
        self.card_auditor = self._create_card(
            parent=self.grid_frame,
            title_text="Auditor",
            desc_text="Audit compliance of blockchain projects with cryptographic standards.",
            button_text="Open Auditor",
            command=lambda: self.switch_page("setup"),
            icon=self._icon_auditor,
            row=0, col=1,
        )

        # ===== Footer =====
        footer = ctk.CTkFrame(self.center, fg_color="transparent")
        footer.pack(fill="x", pady=(6, 0))
        ctk.CTkLabel(
            footer,
            text="© 2025 CryptoScope — Blockchain Cryptographic Analysis Platform",
            font=BODY_FONT, text_color=MUTED,
        ).pack(side="left")

        # listen to window resize
        try:
            self.bind("<Configure>", lambda e: self._relayout())
        except Exception:
            pass

    # ---------- components ----------
    def _create_card(
        self,
        parent: ctk.CTkFrame,
        title_text: str,
        desc_text: str,
        button_text: str,
        command,
        icon: Optional[ctk.CTkImage],
        row: int,
        col: int,
    ) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, corner_radius=12, border_width=1, border_color=BORDER, fg_color=CARD_BG)
        card.grid(row=row, column=col, padx=16, pady=16, sticky="nsew")
        card.grid_columnconfigure(2, weight=1)  # text column stretches

        # --- ICON PLATE (makes the icon stand out on dark)
        plate_size = 68  # will be adjusted in _relayout
        plate = ctk.CTkFrame(
            card, width=plate_size, height=plate_size,
            corner_radius=14, fg_color=PLATE_BG, border_width=1, border_color=PLATE_BORDER,
        )
        plate.grid_propagate(False)
        plate.grid(row=0, column=0, rowspan=3, padx=(16, 12), pady=(16, 12), sticky="n")

        icon_lbl = None
        if icon:
            icon_lbl = ctk.CTkLabel(plate, image=icon, text="")
            icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        # title + desc + button
        title_lbl = ctk.CTkLabel(card, text=title_text, font=HEADING_FONT, text_color=TEXT)
        title_lbl.grid(row=0, column=1, sticky="w", padx=(4, 16), pady=(16, 2))

        desc_lbl = ctk.CTkLabel(
            card, text=desc_text, font=BODY_FONT, text_color=MUTED, wraplength=420, justify="left"
        )
        desc_lbl.grid(row=1, column=1, columnspan=2, sticky="we", padx=(4, 16), pady=(0, 10))

        btn = ctk.CTkButton(
            card, text=button_text, width=180, height=38, corner_radius=10,
            fg_color=PRIMARY, hover_color=PRIMARY_H, text_color=TEXT, command=command,
        )
        btn.grid(row=2, column=1, sticky="w", padx=(4, 0), pady=(6, 16))

        # keep references for dynamic resize
        card._plate = plate
        card._icon_lbl = icon_lbl
        card._desc_lbl = desc_lbl
        card._btn = btn
        return card

    # ---------- responsive layout ----------
    def _relayout(self):
        # window width
        try:
            w = self.winfo_width()
        except Exception:
            w = 1100

        # Center content width: clamp
        max_w = 1200
        min_w = 760
        content_w = max(min_w, min(max_w, int(w * 0.92)))
        try:
            self.center.configure(width=content_w)
        except Exception:
            pass

        # Narrow vs wide layout
        narrow = content_w < 980

        # re-create a simple grid layout depending on width
        self.grid_frame.grid_forget()
        self.grid_frame = ctk.CTkFrame(self.center, fg_color="transparent")
        self.grid_frame.pack(fill="x", expand=True)
        if narrow:
            self.grid_frame.grid_columnconfigure(0, weight=1)
            self.card_analyze.grid_forget()
            self.card_auditor.grid_forget()
            self.card_analyze.grid(row=0, column=0, padx=12, pady=10, sticky="nsew")
            self.card_auditor.grid(row=1, column=0, padx=12, pady=10, sticky="nsew")
        else:
            self.grid_frame.grid_columnconfigure((0, 1), weight=1)
            self.card_analyze.grid_forget()
            self.card_auditor.grid_forget()
            self.card_analyze.grid(row=0, column=0, padx=16, pady=16, sticky="nsew")
            self.card_auditor.grid(row=0, column=1, padx=16, pady=16, sticky="nsew")

        # Icon + plate sizing
        icon_px = 84 if not narrow else 72     # bigger icons
        plate_px = 88 if not narrow else 76

        self._resize_plate_and_icon(self.card_analyze, ASSETS_DIR / "icon_analyze.png", plate_px, icon_px)
        self._resize_plate_and_icon(self.card_auditor, ASSETS_DIR / "icon_auditor.png", plate_px, icon_px)

        # wraplength & button width
        wrap = 480 if not narrow else 540
        try:
            self.card_analyze._desc_lbl.configure(wraplength=wrap)
            self.card_auditor._desc_lbl.configure(wraplength=wrap)
            self.card_analyze._btn.configure(width=190 if not narrow else 180)
            self.card_auditor._btn.configure(width=190 if not narrow else 180)
        except Exception:
            pass

        # subtitle wrap
        try:
            self.subtitle_lbl.configure(wraplength=min(950, int(content_w * 0.78)))
        except Exception:
            pass

    def _resize_plate_and_icon(self, card: ctk.CTkFrame, path: Path, plate_px: int, icon_px: int):
        # plate resizing
        try:
            card._plate.configure(width=plate_px, height=plate_px)
        except Exception:
            pass

        # icon resizing
        try:
            if card._icon_lbl is None:
                return
            img = _load_ctk_image(path, (icon_px, icon_px))
            if img:
                self._img_refs.append(img)
                card._icon_lbl.configure(image=img)
        except Exception:
            pass

    # Router hooks
    def on_enter(self):
        self._relayout()

    def on_resize(self, w, h):
        self._relayout()
