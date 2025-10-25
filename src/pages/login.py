# src/pages/login.py
"""
CryptoScope Login Page
- Uses shared theme (ui.theme) — no inline hex colors
- Supabase auth via api_client_supabase.py
- Clears fields after successful login
"""

from typing import Optional, Dict, Any
import customtkinter as ctk
from ui.theme import (
    BG, CARD_BG, BORDER, TEXT, MUTED,
    PRIMARY, PRIMARY_H, OUTLINE_BR, OUTLINE_H,
    TITLE_FONT, SUB_FONT, HEADING_FONT, BODY_FONT
)

# Supabase bridge (desktop app backend)
from api_client_supabase import (
    login as sb_login,
    get_my_role as sb_get_role,
    ensure_role_row as sb_ensure_role_row,
)


class LoginPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page

        # ---------- State ----------
        self._show_password = ctk.BooleanVar(value=False)
        self._busy = False

        # ---------- Wrapper ----------
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.pack(fill="both", expand=True)

        # Center container
        center = ctk.CTkFrame(
            wrapper,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        center.place(relx=0.5, rely=0.5, anchor="center")
        center.grid_columnconfigure(0, weight=1)

        # ---------- Header ----------
        title = ctk.CTkLabel(center, text="Welcome back", font=TITLE_FONT, text_color=TEXT)
        subtitle = ctk.CTkLabel(
            center,
            text="Sign in to continue to CryptoScope",
            font=SUB_FONT,
            text_color=MUTED,
        )
        title.grid(row=0, column=0, sticky="w", padx=26, pady=(22, 2))
        subtitle.grid(row=1, column=0, sticky="w", padx=26, pady=(0, 10))

        # ---------- Form ----------
        form = ctk.CTkFrame(center, fg_color="transparent")
        form.grid(row=2, column=0, sticky="ew", padx=26)
        form.grid_columnconfigure(0, weight=1)

        self.email_entry = ctk.CTkEntry(
            form,
            placeholder_text="Email address",
            height=38,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
        )
        self.email_entry.grid(row=0, column=0, sticky="ew", pady=(2, 8))

        pw_row = ctk.CTkFrame(form, fg_color="transparent")
        pw_row.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        pw_row.grid_columnconfigure(0, weight=1)

        self.password_entry = ctk.CTkEntry(
            pw_row,
            placeholder_text="Password",
            height=38,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            show="*",
        )
        self.password_entry.grid(row=0, column=0, sticky="ew")

        show_pw = ctk.CTkCheckBox(
            pw_row,
            text="Show password",
            variable=self._show_password,
            command=self._toggle_password,
            text_color=MUTED,
            border_color=OUTLINE_BR,
            fg_color=PRIMARY,        # ✅ must be a real color (no "transparent")
            hover_color=OUTLINE_H,
            checkbox_height=16,
            checkbox_width=16,
            corner_radius=4,
        )

        show_pw.grid(row=0, column=1, padx=(10, 0))

        # Status label
        self.status = ctk.CTkLabel(center, text="", font=BODY_FONT, text_color=MUTED)
        self.status.grid(row=3, column=0, sticky="w", padx=26, pady=(0, 8))

        # ---------- Actions ----------
        actions = ctk.CTkFrame(center, fg_color="transparent")
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
            text_color=BG,  # dark text on green for contrast (from theme)
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

        # Make the center card a good default size
        center.configure(width=540, height=360)

    # ---------- Lifecycle ----------
    def on_enter(self):
        """Optional: called by the app when page is shown."""
        self._reset_fields()
        self._set_status("")

    def on_resize(self, w: int, h: int):
        """Optional: respond to window resize if your app calls this."""
        pass

    # ---------- UI helpers ----------
    def _toggle_password(self):
        self.password_entry.configure(show="" if self._show_password.get() else "*")

    def _set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, text_color=(TEXT if error else MUTED))

    def _set_busy(self, busy: bool):
        self._busy = busy
        state = "disabled" if busy else "normal"
        try:
            self.login_btn.configure(state=state)
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

    # ---------- Login flow ----------
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

        # Success
        uid = user.get("id")
        token = token_or_err

        # ensure role row exists and retrieve role
        try:
            sb_ensure_role_row(token, uid)
        except Exception:
            pass  # not fatal

        try:
            role = sb_get_role(token, uid) or "free"
        except Exception:
            role = "free"

        # attach to the app (top-level window)
        app = self.winfo_toplevel()
        try:
            app.auth_token = token
            app.current_user = user
            app.current_user_role = role
        except Exception:
            # Soft-fail if the app doesn't have these attrs yet
            pass

        # clear fields to avoid lingering credentials
        self._reset_fields()
        self._set_status("")

        # go to landing
        self._set_busy(False)
        self.switch_page("landing")
