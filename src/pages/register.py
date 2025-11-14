# src/pages/register.py
"""
CryptoScope Registration Page
- Uniform vertical spacing for all 5 inputs
- Confirm Password sits ABOVE 'Show password'
- 'Show password' toggles BOTH password fields
- Solid placeholder behavior on all inputs
- No autofocus on page load
- Uses shared theme (ui.theme)
"""

import customtkinter as ctk

from api_client_supabase import register_user as sb_register
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

ENTRY_WIDTH = 420
Y = 4                     # uniform vertical spacing between inputs
PADX = 26

class RegisterPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page
        self._busy = False
        self._show_pw = ctk.BooleanVar(value=False)

        # ---------- Wrapper ----------
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.pack(fill="both", expand=True)

        # Center card
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
        title = ctk.CTkLabel(self.card, text="Create your account", font=TITLE_FONT, text_color=TEXT)
        subtitle = ctk.CTkLabel(
            self.card,
            text="Sign up to start using CryptoScope.",
            font=SUB_FONT,
            text_color=MUTED,
        )
        title.grid(row=0, column=0, sticky="w", padx=PADX, pady=(22, 2))
        subtitle.grid(row=1, column=0, sticky="w", padx=PADX, pady=(0, 10))

        # ---------- Form ----------
        form = ctk.CTkFrame(self.card, fg_color="transparent")
        form.grid(row=2, column=0, sticky="ew", padx=PADX)
        form.grid_columnconfigure(0, weight=1)

        self.fullname_entry = ctk.CTkEntry(
            form,
            placeholder_text="Full name",
            placeholder_text_color=MUTED,
            height=38, width=ENTRY_WIDTH, corner_radius=8,
            fg_color=BG, border_color=BORDER, border_width=1, text_color=TEXT,
        )
        self.fullname_entry.grid(row=0, column=0, sticky="ew", pady=(Y, Y))

        self.username_entry = ctk.CTkEntry(
            form,
            placeholder_text="Username",
            placeholder_text_color=MUTED,
            height=38, width=ENTRY_WIDTH, corner_radius=8,
            fg_color=BG, border_color=BORDER, border_width=1, text_color=TEXT,
        )
        self.username_entry.grid(row=1, column=0, sticky="ew", pady=(Y, Y))

        self.email_entry = ctk.CTkEntry(
            form,
            placeholder_text="Email address",
            placeholder_text_color=MUTED,
            height=38, width=ENTRY_WIDTH, corner_radius=8,
            fg_color=BG, border_color=BORDER, border_width=1, text_color=TEXT,
        )
        self.email_entry.grid(row=2, column=0, sticky="ew", pady=(Y, Y))

        self.password_entry = ctk.CTkEntry(
            form,
            placeholder_text="Password",
            placeholder_text_color=MUTED,
            height=38, width=ENTRY_WIDTH, corner_radius=8,
            fg_color=BG, border_color=BORDER, border_width=1, text_color=TEXT,
            show="*",
        )
        self.password_entry.grid(row=3, column=0, sticky="ew", pady=(Y, Y))

        self.confirm_password_entry = ctk.CTkEntry(
            form,
            placeholder_text="Confirm password",
            placeholder_text_color=MUTED,
            height=38, width=ENTRY_WIDTH, corner_radius=8,
            fg_color=BG, border_color=BORDER, border_width=1, text_color=TEXT,
            show="*",
        )
        # Confirm ABOVE the checkbox, same spacing
        self.confirm_password_entry.grid(row=4, column=0, sticky="ew", pady=(Y, Y))

        # Keep placeholders consistent when leaving fields
        for inp in (
            self.fullname_entry,
            self.username_entry,
            self.email_entry,
            self.password_entry,
            self.confirm_password_entry,
        ):
            inp.bind("<FocusOut>", lambda _e: self._refresh_placeholders())

        # 'Show password' BELOW both password fields, small top space
        show_pw = ctk.CTkCheckBox(
            form,
            text="Show password",
            variable=self._show_pw,
            command=self._toggle_password,
            text_color=MUTED,
            border_color=OUTLINE_BR,
            fg_color=PRIMARY,     # must be a solid color
            hover_color=OUTLINE_H,
            checkbox_height=16, checkbox_width=16, corner_radius=4,
        )
        show_pw.grid(row=5, column=0, sticky="w", pady=(Y, Y), padx=(6,0))

        # ---------- Status ----------
        self.status = ctk.CTkLabel(self.card, text="", font=BODY_FONT, text_color=MUTED)
        self.status.grid(row=3, column=0, sticky="w", padx=PADX, pady=(2, 8))

        # ---------- Actions ----------
        actions = ctk.CTkFrame(self.card, fg_color="transparent")
        actions.grid(row=4, column=0, sticky="ew", padx=PADX, pady=(4, 22))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=0)

        register_btn = ctk.CTkButton(
            actions,
            text="Register",
            width=120, height=38, corner_radius=8,
            fg_color=PRIMARY, hover_color=PRIMARY_H, text_color=BG,
            command=self._do_register,
        )
        register_btn.grid(row=0, column=0, sticky="w")

        login_btn = ctk.CTkButton(
            actions,
            text="Back to Login",
            width=140, height=38, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=OUTLINE_BR,
            hover_color=OUTLINE_H, text_color=TEXT,
            command=lambda: self.switch_page("login"),
        )
        login_btn.grid(row=0, column=1, sticky="e", padx=(10, 0))

        # Card size
        self.card.configure(width=560, height=560)

        # No autofocus + ensure placeholders visible
        self.after(10, self._defocus)
        self.after(30, self._refresh_placeholders)

    # ---------- Lifecycle ----------
    def on_enter(self):
        self._reset_fields()
        self._set_status("")
        self._defocus()
        self.after(30, self._refresh_placeholders)

    # ---------- UI helpers ----------
    def _defocus(self):
        try:
            self.focus_set()
        except Exception:
            pass

    def _toggle_password(self):
        show = "" if self._show_pw.get() else "*"
        self.password_entry.configure(show=show)
        self.confirm_password_entry.configure(show=show)

    def _set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, text_color=(TEXT if error else MUTED))

    def _refresh_placeholders(self):
        try:
            if (self.fullname_entry.get() or "").strip() == "":
                self.fullname_entry.configure(placeholder_text="Full name")
            if (self.username_entry.get() or "").strip() == "":
                self.username_entry.configure(placeholder_text="Username")
            if (self.email_entry.get() or "").strip() == "":
                self.email_entry.configure(placeholder_text="Email address")
            if (self.password_entry.get() or "").strip() == "":
                self.password_entry.configure(placeholder_text="Password")
            if (self.confirm_password_entry.get() or "").strip() == "":
                self.confirm_password_entry.configure(placeholder_text="Confirm password")
        except Exception:
            pass

    def _reset_fields(self):
        for w in (
            self.fullname_entry,
            self.username_entry,
            self.email_entry,
            self.password_entry,
            self.confirm_password_entry,
        ):
            try:
                w.delete(0, "end")
            except Exception:
                pass
        self._show_pw.set(False)
        self.password_entry.configure(show="*")
        self.confirm_password_entry.configure(show="*")
        self._set_status("")
        self._refresh_placeholders()

    # ---------- Registration Logic ----------
    def _do_register(self):
        if self._busy:
            return

        fullname = (self.fullname_entry.get() or "").strip()
        username = (self.username_entry.get() or "").strip()
        email = (self.email_entry.get() or "").strip()
        password = self.password_entry.get() or ""
        confirm  = self.confirm_password_entry.get() or ""

        if not all([fullname, username, email, password, confirm]):
            self._set_status("Fill in all fields.", error=True)
            return

        if password != confirm:
            self._set_status("Passwords do not match.", error=True)
            return

        self._busy = True
        self._set_status("Registering…")

        try:
            ok, result = sb_register(email, password, fullname, username)
        except Exception as e:
            self._busy = False
            self._set_status(f"Error: {e}", error=True)
            return

        if not ok:
            self._busy = False
            self._set_status(str(result), error=True)
            return

        self._set_status("Registration successful! Check your email to verify.")
        self.after(1000, lambda: self.switch_page("verify_email"))
        self._reset_fields()
        self._busy = False
