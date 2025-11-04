# src/pages/landing.py
"""
CryptoScope Landing Page — stable resize (root-only events + debounced),
sticky footer, centered cards, icon plates, bigger icons.
"""
from pathlib import Path
from typing import Optional, Dict, Tuple

import customtkinter as ctk

try:
    from PIL import Image
except Exception:
    Image = None  # type: ignore

from ui.theme import (
    BG, BODY_FONT, BORDER, CARD_BG, HEADING_FONT, MUTED,
    OUTLINE_BR, OUTLINE_H, PRIMARY, PRIMARY_H, TEXT, TITLE_FONT,
    PLATE_BG, PLATE_BORDER,
)

ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"


def _load_ctk_image(path: Path, size: Tuple[int, int]) -> Optional[ctk.CTkImage]:
    try:
        if Image is None or not path.exists():
            return None
        img = Image.open(path).convert("RGBA").resize(size, Image.LANCZOS)
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception:
        return None


class LandingPage(ctk.CTkFrame):
    """Main hub after login — gateway to Dashboard and Auditor (no resize jitter)."""

    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page

        # --- resize state (root-only, debounced) ---
        self._relayout_job: Optional[str] = None
        self._img_cache: Dict[Tuple[Path, int], ctk.CTkImage] = {}  # (path, px) -> CTkImage
        self._current_icon_px: Optional[int] = None
        self._is_narrow: Optional[bool] = None
        self._last_root_size: Tuple[int, int] = (0, 0)

        # ===== Header =====
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(24, 10))

        self.title_lbl = ctk.CTkLabel(header, text="CryptoScope", font=TITLE_FONT, text_color=TEXT)
        self.subtitle_lbl = ctk.CTkLabel(
            header,
            text="Identify, analyze, and audit cryptographic functions across blockchain projects.",
            font=BODY_FONT, text_color=MUTED, wraplength=900, justify="left",
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

        # ===== Body (fills remaining) =====
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=0)

        # 3-column grid to center content horizontally
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(2, weight=1)

        # centered container (width clamped in _relayout)
        self.center = ctk.CTkFrame(body, fg_color="transparent")
        self.center.grid(row=0, column=1, sticky="n", pady=(6, 8))

        # cards row (never recreated)
        self.grid_frame = ctk.CTkFrame(self.center, fg_color="transparent")
        self.grid_frame.pack(fill="x", expand=True)
        self.grid_frame.grid_columnconfigure((0, 1), weight=1)

        # icons (paths; images are cached per size)
        self.icon_analyze_path = ASSETS_DIR / "icon_analyze.png"
        self.icon_auditor_path = ASSETS_DIR / "icon_auditor.png"

        # build cards once
        self.card_analyze = self._create_card(
            self.grid_frame, "Analyse",
            "Upload files or scan GitHub repositories for cryptographic analysis.",
            "Open Dashboard", lambda: self.switch_page("dashboard"),
        )
        self.card_auditor = self._create_card(
            self.grid_frame, "Auditor",
            "Audit compliance of blockchain projects with cryptographic standards.",
            "Open Auditor", lambda: self.switch_page("setup"),
        )
        self.card_analyze.grid(row=0, column=0, padx=14, pady=12, sticky="n")
        self.card_auditor.grid(row=0, column=1, padx=14, pady=12, sticky="n")

        # ===== Sticky footer (always at bottom) =====
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=40, pady=(0, 12))
        ctk.CTkLabel(
            footer,
            text="© 2025 CryptoScope — Blockchain Cryptographic Analysis Platform",
            font=BODY_FONT, text_color=MUTED,
        ).pack(side="left")

        # Bind ONLY the root window's Configure to avoid child-trigger loops
        root = self.winfo_toplevel()
        root.bind("<Configure>", self._on_root_configure)

        # first layout
        self._relayout()

    # ---------- card factory ----------
    def _create_card(self, parent, title_text, desc_text, button_text, command):
        card = ctk.CTkFrame(parent, corner_radius=12, border_width=1, border_color=BORDER, fg_color=CARD_BG)
        card.grid_propagate(False)

        plate = ctk.CTkFrame(
            card, width=116, height=116, corner_radius=18,
            fg_color=PLATE_BG, border_width=1, border_color=PLATE_BORDER,
        )
        plate.place(x=16, y=16)

        icon_lbl = ctk.CTkLabel(plate, text="")  # image set later
        icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.place(x=16 + 116 + 14, y=16)

        title_lbl = ctk.CTkLabel(content, text=title_text, font=HEADING_FONT, text_color=TEXT)
        title_lbl.pack(anchor="w")
        desc_lbl = ctk.CTkLabel(content, text=desc_text, font=BODY_FONT, text_color=MUTED,
                                wraplength=520, justify="left")
        desc_lbl.pack(anchor="w", pady=(2, 10))
        btn = ctk.CTkButton(
            content, text=button_text, width=200, height=40, corner_radius=10,
            fg_color=PRIMARY, hover_color=PRIMARY_H, text_color=TEXT, command=command,
        )
        btn.pack(anchor="w")

        # refs
        card._plate = plate
        card._icon_lbl = icon_lbl
        card._content = content
        card._desc_lbl = desc_lbl
        card._btn = btn
        return card

    # ---------- root-only debounced resize ----------
    def _on_root_configure(self, event):
        # Ignore non-root events (paranoia) and tiny/no changes
        if event.widget is not self.winfo_toplevel():
            return
        new_size = (event.width, event.height)
        old_w, old_h = self._last_root_size
        if abs(new_size[0] - old_w) < 2 and abs(new_size[1] - old_h) < 2:
            return
        self._last_root_size = new_size

        # debounce
        if self._relayout_job:
            try:
                self.after_cancel(self._relayout_job)
            except Exception:
                pass
        self._relayout_job = self.after(80, self._relayout)

    # ---------- layout / sizing ----------
    def _relayout(self):
        self._relayout_job = None

        # current root width
        try:
            win_w = self.winfo_toplevel().winfo_width()
        except Exception:
            win_w = 1100

        # clamp content width (keeps center neat)
        max_w, min_w = 1200, 840
        content_w = max(min_w, min(max_w, int(win_w * 0.92)))
        try:
            self.center.configure(width=content_w)
        except Exception:
            pass

        narrow = content_w < 980
        if narrow != self._is_narrow:
            self._is_narrow = narrow
            # re-grid cards without recreation
            self.card_analyze.grid_forget()
            self.card_auditor.grid_forget()
            if narrow:
                self.grid_frame.grid_columnconfigure(0, weight=1)
                self.grid_frame.grid_columnconfigure(1, weight=0)
                self.card_analyze.grid(row=0, column=0, padx=12, pady=10, sticky="n")
                self.card_auditor.grid(row=1, column=0, padx=12, pady=10, sticky="n")
            else:
                self.grid_frame.grid_columnconfigure((0, 1), weight=1)
                self.card_analyze.grid(row=0, column=0, padx=14, pady=12, sticky="n")
                self.card_auditor.grid(row=0, column=1, padx=14, pady=12, sticky="n")

        # card sizing
        card_width = min(760, int(content_w * (0.96 if narrow else 0.47)))
        card_height = 190
        left_pad = 16 + 116 + 14

        for card in (self.card_analyze, self.card_auditor):
            try:
                card.configure(width=card_width, height=card_height)
                card._content.place_configure(x=left_pad, y=16)
                card._desc_lbl.configure(wraplength=max(420, card_width - left_pad - 24))
                card._btn.configure(width=210 if not narrow else 200)
            except Exception:
                pass

        # icon + plate (size buckets; cached images)
        icon_px = 108 if not narrow else 96
        plate_px = 124 if not narrow else 116
        if self._current_icon_px != icon_px:
            self._current_icon_px = icon_px
            self._apply_icon(self.card_analyze, self.icon_analyze_path, plate_px, icon_px)
            self._apply_icon(self.card_auditor, self.icon_auditor_path, plate_px, icon_px)

        # subtitle wrap
        try:
            self.subtitle_lbl.configure(wraplength=min(1000, int(content_w * 0.82)))
        except Exception:
            pass

    def _apply_icon(self, card: ctk.CTkFrame, path: Path, plate_px: int, icon_px: int):
        try:
            card._plate.configure(width=plate_px, height=plate_px,
                                  corner_radius=max(16, plate_px // 7))
        except Exception:
            pass

        key = (path, icon_px)
        img = self._img_cache.get(key)
        if img is None:
            maybe = _load_ctk_image(path, (icon_px, icon_px))
            if maybe is not None:
                self._img_cache[key] = maybe
                img = maybe
        if img is not None:
            try:
                card._icon_lbl.configure(image=img)
            except Exception:
                pass

    # Router hooks intentionally do NOT call _relayout to avoid loops during window init
    def on_enter(self):
        pass

    def on_resize(self, w, h):
        pass
