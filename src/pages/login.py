# src/pages/login.py
"""
CryptoScope Login Page
- No autofocus on fields when page is shown (no caret blink)
- Password field same width as others
- 'Show password' below the password field
- Uses shared theme (ui.theme)
"""

import customtkinter as ctk
from PIL import Image, ImageDraw 

from api_client_supabase import (
    login as sb_login,
    ensure_role_row as sb_ensure_role_row,
    get_my_role as sb_get_role,
)
from api_client_google import login_with_google
from api_client_github import login_with_github

from ui.theme import (
    BG,
    BODY_FONT,
    BORDER,
    CARD_BG,
    MUTED,
    OUTLINE_BR,
    OUTLINE_H,
    PRIMARY,
    PRIMARY_H,
    SUB_FONT,
    TEXT,
    TITLE_FONT,
)

ENTRY_WIDTH = 420  # unify widths


class LoginPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page

        # -------- state --------
        self._show_password = ctk.BooleanVar(value=False)
        self._busy = False

        # -------- layout wrappers --------
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.pack(fill="both", expand=True)

        # Center container (card)
        self.card = ctk.CTkFrame(
            wrapper,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        self.card.place(relx=0.5, rely=0.5, anchor="center")
        self.card.grid_columnconfigure(0, weight=1)

        # ---------- Header ----------
        title = ctk.CTkLabel(self.card, text="Welcome back", font=TITLE_FONT, text_color=TEXT)
        subtitle = ctk.CTkLabel(
            self.card,
            text="Sign in to continue to CryptoScope",
            font=SUB_FONT,
            text_color=MUTED,
        )
        title.grid(row=0, column=0, sticky="w", padx=26, pady=(22, 2))
        subtitle.grid(row=1, column=0, sticky="w", padx=26, pady=(0, 10))

        # ---------- Form ----------
        form = ctk.CTkFrame(self.card, fg_color="transparent")
        form.grid(row=2, column=0, sticky="ew", padx=26)
        form.grid_columnconfigure(0, weight=1)

        self.email_entry = ctk.CTkEntry(
            form,
            placeholder_text="Email address",
            placeholder_text_color=MUTED,   # 👈 add
            height=38, width=ENTRY_WIDTH, corner_radius=8,
            fg_color=BG, border_color=BORDER, border_width=1, text_color=TEXT,
        )
        self.email_entry.grid(row=0, column=0, sticky="ew", pady=(2, 8))

        self.password_entry = ctk.CTkEntry(
            form,
            placeholder_text="Password",
            placeholder_text_color=MUTED,   # 👈 add
            height=38, width=ENTRY_WIDTH, corner_radius=8,
            fg_color=BG, border_color=BORDER, border_width=1, text_color=TEXT,
            show="*",
        )
        self.password_entry.grid(row=1, column=0, sticky="ew")

        # show password BELOW password field
        show_pw = ctk.CTkCheckBox(
            form,
            text="Show password",
            variable=self._show_password,
            command=self._toggle_password,
            text_color=MUTED,
            border_color=OUTLINE_BR,
            fg_color=PRIMARY,   # must be a real color
            hover_color=OUTLINE_H,
            checkbox_height=16,
            checkbox_width=16,
            corner_radius=4,
        )
        show_pw.grid(row=2, column=0, sticky="w", pady=(6, 8), padx=(6,0))

        # Status label
        self.status = ctk.CTkLabel(self.card, text="", font=BODY_FONT, text_color=MUTED)
        self.status.grid(row=3, column=0, sticky="w", padx=26, pady=(0, 8))

        # ---------- Actions ----------
        actions = ctk.CTkFrame(self.card, fg_color="transparent")
        actions.grid(row=4, column=0, sticky="ew", padx=26, pady=(4, 22))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=0)

        self.login_btn = ctk.CTkButton(
            actions,
            text="Sign in",
            width=120,
            height=38,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color=BG,
            command=self._do_login,
        )
        self.login_btn.grid(row=0, column=0, sticky="w")

        register_btn = ctk.CTkButton(
            actions,
            text="Create account",
            width=140,
            height=38,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: self.switch_page("register"),
        )
        register_btn.grid(row=0, column=1, sticky="e", padx=(10, 0))

        # Card default size
        self.card.configure(width=560, height=400)

        # Ensure no widget is focused initially
        self.after(10, self._defocus)

    # ---------- Refresh placeholders -----------
    def _refresh_placeholders(self):
    # Re-apply placeholder text so CTk renders it if the field is empty
        try:
            if (self.email_entry.get() or "").strip() == "":
                self.email_entry.configure(placeholder_text="Email address")
            if (self.password_entry.get() or "").strip() == "":
                self.password_entry.configure(placeholder_text="Password")
        except Exception:
            pass

    # -------- lifecycle --------
    def on_enter(self):
        # Clear fields and remove focus to avoid blinking caret
        self._reset_fields()
        self._set_status("")
        self._defocus()
        self.after(30, self._refresh_placeholders)   # 👈 ensure placeholders show


    def on_resize(self, w: int, h: int):
        pass

    # -------- helpers --------
    def _defocus(self):
        # move focus to the frame itself so no Entry shows the caret
        try:
            self.focus_set()
        except Exception:
            pass

    def _toggle_password(self):
        self.password_entry.configure(show="" if self._show_password.get() else "*")

    def _set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, text_color=(TEXT if error else MUTED))

    def _set_busy(self, busy: bool):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for b in (self.login_btn, getattr(self, "google_btn", None), getattr(self, "github_btn", None)):
            try:
                if b:
                    b.configure(state=state)
            except Exception:
                pass

    def _reset_fields(self):
        try:
            self.email_entry.delete(0, "end")
            self.password_entry.delete(0, "end")
            self._show_password.set(False)
            self.password_entry.configure(show="*")
        except Exception:
            pass
        self._refresh_placeholders()                 # 👈 refresh

    # -------- login flows --------
    def _do_login(self):
        if self._busy:
            return
        email = (self.email_entry.get() or "").strip()
        password = self.password_entry.get() or ""
        if not email or not password:
            self._set_status("Enter email and password.", error=True)
            return

        self._set_busy(True)
        self._set_status("Signing in…")
        try:
            ok, token_or_err, user = sb_login(email, password)
        except Exception as e:
            self._set_busy(False)
            self._set_status(f"Login error: {e}", error=True)
            return

        if not ok or not user:
            self._set_busy(False)
            self._set_status(f"{token_or_err}", error=True)
            return

        uid = user.get("id")
        token = token_or_err

        # ensure role exists and fetch role
        try:
            sb_ensure_role_row(token, uid)
        except Exception:
            pass

        try:
            role = sb_get_role(token, uid) or "free"
        except Exception:
            role = "free"

        # attach to the app
        app = self.winfo_toplevel()
        try:
            app.auth_token = token
            app.current_user = user
            app.current_user_role = role
        except Exception:
            pass

        # clear, defocus, go landing
        self._reset_fields()
        self._set_status("")
        self._set_busy(False)
        self._defocus()
        self.switch_page("landing")
