from __future__ import annotations

import tkinter as tk
import customtkinter as ctk
from typing import Callable


class AccountsMenu(ctk.CTkFrame):
    """Top-right circular accounts button with a dropdown menu.

    This replaces the previous inline 'Profiles' controls with a compact
    circular avatar-like button. Clicking the button opens a simple
    dropdown menu with placeholder entries (Account, Settings). Backend
    wiring will be added later.
    """

    def __init__(self, parent, on_profile_change: Callable[[str], None] | None = None):
        super().__init__(parent, fg_color="transparent")
        self.on_profile_change = on_profile_change

        # Create a circular-looking button (width==height, large corner_radius)
        size = 36
        try:
            self._btn = ctk.CTkButton(self, text="", width=size, height=size, corner_radius=int(size / 2), fg_color="#2b8ad6", hover_color="#3b9be8", command=self._on_click, border_width=0)
        except Exception:
            # Fallback if CTkButton doesn't accept height/width/corner_radius
            self._btn = ctk.CTkButton(self, text="A", width=36, command=self._on_click)

        # Use a simple label on the button (initials) if available
        try:
            # If CTk supports setting text and font consistently, show an initial
            self._btn.configure(text="A")
        except Exception:
            pass

        self._btn.pack(side="right", padx=(8, 0))

        # Build the popup menu (tk.Menu) to appear under the button
        self._menu = tk.Menu(self, tearoff=0)
        self._menu.add_command(label="Account", command=self._open_account)
        self._menu.add_command(label="Settings", command=self._open_settings)

    def _on_click(self):
        # Position the menu directly under the button
        try:
            bx = self._btn.winfo_rootx()
            by = self._btn.winfo_rooty()
            bh = self._btn.winfo_height()
            # post the menu at the left edge of the button, below it
            self._menu.tk_popup(bx, by + bh)
        except Exception:
            try:
                # fallback: post at pointer
                self._menu.post(self.winfo_pointerx(), self.winfo_pointery())
            except Exception:
                pass

    def _open_account(self):
        # placeholder: show a tiny popup window
        try:
            t = ctk.CTkToplevel(self.winfo_toplevel())
            t.title("Account")
            frm = ctk.CTkFrame(t, fg_color="transparent")
            frm.pack(padx=12, pady=12)
            ctk.CTkLabel(frm, text="Account (placeholder)").pack()
            ctk.CTkButton(frm, text="Close", command=lambda: (t.destroy())).pack(pady=(8, 0))
        except Exception:
            pass

    def _open_settings(self):
        # placeholder: display settings window (to house profiles later)
        try:
            t = ctk.CTkToplevel(self.winfo_toplevel())
            t.title("Settings")
            frm = ctk.CTkFrame(t, fg_color="transparent")
            frm.pack(padx=12, pady=12)
            ctk.CTkLabel(frm, text="Settings (placeholder)").pack()
            ctk.CTkButton(frm, text="Close", command=lambda: (t.destroy())).pack(pady=(8, 0))
        except Exception:
            pass
