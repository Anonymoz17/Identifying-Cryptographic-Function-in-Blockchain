# src/pages/advisor.py
"""
CryptoScope Advisor Page
--------------------------------
- Unified with ui.theme (no inline colors)
- Space for recommendations / scoring / migration guidance
- Consistent header + footer actions
"""

from typing import Optional, Dict, Any, List
import customtkinter as ctk
from ui.theme import (
    BG, CARD_BG, BORDER, TEXT, MUTED,
    PRIMARY, PRIMARY_H, OUTLINE_BR, OUTLINE_H,
    HEADING_FONT, BODY_FONT
)


class AdvisorPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page

        # ===== Header =====
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(16, 6))

        title = ctk.CTkLabel(header, text="Advisor", font=HEADING_FONT, text_color=TEXT)
        subtitle = ctk.CTkLabel(
            header,
            text="Recommendations and migration guidance based on your analysis.",
            font=("Segoe UI", 12),
            text_color=MUTED,
        )
        title.grid(row=0, column=0, sticky="w")
        subtitle.grid(row=1, column=0, sticky="w")

        logout_btn = ctk.CTkButton(
            header,
            text="Logout",
            width=84,
            height=30,
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

        # ===== Main Content Wrapper =====
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=22, pady=(4, 16))
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        # ===== Overview / Context Card =====
        hero = ctk.CTkFrame(
            main,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        hero.grid(row=0, column=0, sticky="ew", pady=(4, 10))
        hero.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hero, text="Project Overview",
            font=HEADING_FONT, text_color=TEXT
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))

        self.project_summary = ctk.CTkTextbox(
            hero,
            height=80,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            wrap="word",
        )
        self.project_summary.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 14))
        self.project_summary.insert(
            "1.0",
            "Summary of your last analysis will appear here.\n"
            "Tip: You can paste findings or notes to get tailored suggestions.",
        )
        self.project_summary.configure(state="disabled")

        # ===== Recommendations + Actions Row =====
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=22, pady=(0, 6))
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=1)

        # --- Left: Recommendations ---
        recommendations = ctk.CTkFrame(
            row,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        recommendations.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        recommendations.grid_columnconfigure(0, weight=1)
        recommendations.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            recommendations, text="Recommendations",
            font=HEADING_FONT, text_color=TEXT
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))

        self.reco_box = ctk.CTkTextbox(
            recommendations,
            wrap="word",
            height=260,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
        )
        self.reco_box.grid(row=1, column=0, sticky="nsew", padx=16, pady=(6, 14))
        self._fill_placeholder_recommendations()

        # --- Right: Algorithm & Migration Hints ---
        right_col = ctk.CTkFrame(
            row,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        right_col.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right_col.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            right_col, text="Algorithms / Migration",
            font=HEADING_FONT, text_color=TEXT
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))

        # A small list-like area for hints:
        self.hints = ctk.CTkTextbox(
            right_col,
            height=120,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            wrap="word",
        )
        self.hints.grid(row=1, column=0, sticky="ew", padx=16, pady=(6, 10))
        self._fill_placeholder_hints()

        actions = ctk.CTkFrame(right_col, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            actions,
            text="Refresh from Last Analysis",
            height=36,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color=BG,
            command=self._refresh_from_last_analysis,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))

        ctk.CTkButton(
            actions,
            text="⬅ Back to Landing",
            height=36,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: self.switch_page("landing"),
        ).grid(row=0, column=1, sticky="ew", padx=(6, 0))

    # ===== Internal Methods =====
    def _fill_placeholder_recommendations(self):
        self.reco_box.insert(
            "1.0",
            "- AES detected in multiple files. Consider centralizing key management.\n"
            "- SHA-256 usage looks correct; verify no raw password hashing.\n"
            "- Consider migrating legacy RSA-1024 to RSA-2048 or ECC (P-256).\n"
            "- Avoid custom crypto primitives; prefer vetted libraries.\n"
        )
        self.reco_box.configure(state="disabled")

    def _fill_placeholder_hints(self):
        self.hints.insert(
            "1.0",
            "• Prefer AES-GCM over AES-CBC for authenticated encryption.\n"
            "• Use HKDF for key derivation; avoid ad-hoc constructions.\n"
            "• If signatures needed, consider Ed25519 or ECDSA (P-256).\n"
            "• Ensure secure randoms via OS RNG / libsodium / cryptography.io\n"
        )
        self.hints.configure(state="disabled")

    def _refresh_from_last_analysis(self):
        """
        Optional: pull from app-level state if available.
        This function safely checks for 'current_scan_meta' / last payload
        on the Toplevel app and updates the boxes.
        """
        app = self.winfo_toplevel()
        meta = getattr(app, "current_scan_meta", None)
        payload = getattr(app, "last_export_payload", None)

        # Basic UX message:
        self.reco_box.configure(state="normal")
        self.reco_box.delete("1.0", "end")
        self.reco_box.insert(
            "1.0",
            "Refreshed from last analysis context.\n\n"
            f"Meta: {meta}\n\n"
            f"Payload keys: {list(payload.keys()) if isinstance(payload, dict) else '—'}\n\n"
            "Use this hook to generate live, tailored recommendations.",
        )
        self.reco_box.configure(state="disabled")

        self.hints.configure(state="normal")
        self.hints.insert("end", "\n\n• (Live) Review KDF parameters and nonce sizes.")
        self.hints.configure(state="disabled")
