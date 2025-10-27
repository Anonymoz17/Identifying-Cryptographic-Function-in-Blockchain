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
        card = ctk.CTkFrame(
            wrapper,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD_BG,
        )
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.grid_columnconfigure(0, weight=1)

        # ---------- Header ----------
        title = ctk.CTkLabel(
            card, text="Create your account", font=TITLE_FONT, text_color=TEXT
        )
        subtitle = ctk.CTkLabel(
            card,
            text="Sign up to start using CryptoScope.",
            font=SUB_FONT,
            text_color=MUTED,
        )
        title.grid(row=0, column=0, sticky="w", padx=26, pady=(22, 2))
        subtitle.grid(row=1, column=0, sticky="w", padx=26, pady=(0, 10))

        # ---------- Form ----------
        form = ctk.CTkFrame(card, fg_color="transparent")
        form.grid(row=2, column=0, sticky="ew", padx=26)
        form.grid_columnconfigure(0, weight=1)

        self.fullname_entry = ctk.CTkEntry(
            form,
            placeholder_text="Full name",
            height=38,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
        )
        self.fullname_entry.grid(row=0, column=0, sticky="ew", pady=(4, 6))

        self.username_entry = ctk.CTkEntry(
            form,
            placeholder_text="Username",
            height=38,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
        )
        self.username_entry.grid(row=1, column=0, sticky="ew", pady=(4, 6))

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
        self.email_entry.grid(row=2, column=0, sticky="ew", pady=(4, 6))

        pw_row = ctk.CTkFrame(form, fg_color="transparent")
        pw_row.grid(row=3, column=0, sticky="ew", pady=(2, 6))
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

        self.confirm_password_entry = ctk.CTkEntry(
            pw_row,
            placeholder_text="Confirm Password",
            height=38,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            show="*",
        )
        self.confirm_password_entry.grid(row=1, column=0, sticky="ew")

        show_pw = ctk.CTkCheckBox(
            pw_row,
            text="Show password",
            variable=self._show_pw,
            command=self._toggle_password,
            text_color=MUTED,
            border_color=OUTLINE_BR,
            fg_color=PRIMARY,  # ✅ real color
            hover_color=OUTLINE_H,
            checkbox_height=16,
            checkbox_width=16,
            corner_radius=4,
        )

        show_pw.grid(row=1, column=1, padx=(10, 0))

        # Status label
        self.status = ctk.CTkLabel(card, text="", font=BODY_FONT, text_color=MUTED)
        self.status.grid(row=3, column=0, sticky="w", padx=26, pady=(2, 8))

        # ---------- Actions ----------
        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=4, column=0, sticky="ew", padx=26, pady=(4, 22))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=0)

        register_btn = ctk.CTkButton(
            actions,
            text="Register",
            width=120,
            height=38,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color=BG,
            command=self._do_register,
        )
        register_btn.grid(row=0, column=0, sticky="w")

        login_btn = ctk.CTkButton(
            actions,
            text="Back to Login",
            width=140,
            height=38,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=OUTLINE_BR,
            hover_color=OUTLINE_H,
            text_color=TEXT,
            command=lambda: self.switch_page("login"),
        )
        login_btn.grid(row=0, column=1, sticky="e", padx=(10, 0))

        # Default size
        card.configure(width=540, height=430)

    # ---------- UI helpers ----------
    def _toggle_password(self):
        self.password_entry.configure(show="" if self._show_pw.get() else "*")
        self.confirm_password_entry.configure(show="" if self._show_pw.get() else "*")

    def _set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, text_color=(TEXT if error else MUTED))

    def _reset_fields(self):
        for field in (
            self.fullname_entry,
            self.username_entry,
            self.email_entry,
            self.password_entry,
            self.confirm_password_entry,
        ):
            try:
                field.delete(0, "end")
            except Exception:
                pass
        self._show_pw.set(False)
        self.password_entry.configure(show="*")
        self.confirm_password_entry.configure(show="*")
        self._set_status("")

    # ---------- Registration Logic ----------
    def _do_register(self):
        if self._busy:
            return

        fullname = (self.fullname_entry.get() or "").strip()
        username = (self.username_entry.get() or "").strip()
        email = (self.email_entry.get() or "").strip()
        password = self.password_entry.get() or ""
        confirm_password = self.confirm_password_entry.get() or ""

        if not all([fullname, username, email, password, confirm_password]):
            self._set_status("Fill in all fields.", error=True)
            return

        if password != confirm_password:
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

        # Success — go back to login
        self._set_status("Registration successful! Please log in.")
        self.after(1000, lambda: self.switch_page("login"))
        self._reset_fields()
        self._busy = False
