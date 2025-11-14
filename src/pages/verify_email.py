"""Email Verification Page for desktop app.

After user registers, they receive a confirmation email.
This page allows them to paste the access_token from the email link.
"""

import customtkinter as ctk
import logging

from api_client_supabase import _sb, _require_client
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

logger = logging.getLogger(__name__)

ENTRY_WIDTH = 420
PADX = 26


class VerifyEmailPage(ctk.CTkFrame):
    """Email verification page for confirming email via token from link."""

    def __init__(self, master, switch_page):
        super().__init__(master, fg_color=BG)
        self.switch_page = switch_page
        self._busy = False
        self.email = None

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
        title = ctk.CTkLabel(
            self.card,
            text="Verify Your Email",
            font=TITLE_FONT,
            text_color=TEXT,
        )
        subtitle = ctk.CTkLabel(
            self.card,
            text="Check your email for a confirmation link.\nCopy the access token from the URL and paste it below.",
            font=SUB_FONT,
            text_color=MUTED,
        )
        title.grid(row=0, column=0, sticky="w", padx=PADX, pady=(22, 2))
        subtitle.grid(row=1, column=0, sticky="w", padx=PADX, pady=(0, 14))

        # ---------- Instructions ----------
        instructions = ctk.CTkLabel(
            self.card,
            text=(
                "📧 Steps:\n"
                "1. Open the confirmation email\n"
                "2. Click the confirmation link\n"
                "3. Copy the 'access_token' value from the URL\n"
                "4. Paste it below and click 'Verify'"
            ),
            font=BODY_FONT,
            text_color=MUTED,
            justify="left",
        )
        instructions.grid(row=2, column=0, sticky="w", padx=PADX, pady=(0, 14))

        # ---------- Form ----------
        form = ctk.CTkFrame(self.card, fg_color="transparent")
        form.grid(row=3, column=0, sticky="ew", padx=PADX)
        form.grid_columnconfigure(0, weight=1)

        token_label = ctk.CTkLabel(
            form,
            text="Access Token:",
            font=BODY_FONT,
            text_color=TEXT,
        )
        token_label.grid(row=0, column=0, sticky="w", pady=(0, 6))

        self.token_entry = ctk.CTkEntry(
            form,
            placeholder_text="Paste access_token here...",
            placeholder_text_color=MUTED,
            height=100,
            width=ENTRY_WIDTH,
            corner_radius=8,
            fg_color=BG,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
        )
        self.token_entry.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        # ---------- Status ----------
        self.status = ctk.CTkLabel(
            self.card, text="", font=BODY_FONT, text_color=MUTED
        )
        self.status.grid(row=4, column=0, sticky="w", padx=PADX, pady=(2, 8))

        # ---------- Actions ----------
        actions = ctk.CTkFrame(self.card, fg_color="transparent")
        actions.grid(row=5, column=0, sticky="ew", padx=PADX, pady=(4, 22))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=0)

        verify_btn = ctk.CTkButton(
            actions,
            text="Verify Email",
            width=120,
            height=38,
            corner_radius=8,
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color=BG,
            command=self._do_verify,
        )
        verify_btn.grid(row=0, column=0, sticky="w")

        back_btn = ctk.CTkButton(
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
        back_btn.grid(row=0, column=1, sticky="e", padx=(10, 0))

        # Card size
        self.card.configure(width=560, height=520)

    def on_enter(self):
        """Called when page is displayed."""
        self._reset_fields()
        self._set_status("")
        try:
            self.token_entry.focus()
        except Exception:
            pass

    def _reset_fields(self):
        """Clear input fields."""
        try:
            self.token_entry.delete(0, "end")
        except Exception:
            pass
        self._set_status("")

    def _set_status(self, msg: str, error: bool = False):
        """Display status message."""
        color = TEXT if error else MUTED
        self.status.configure(text=msg, text_color=color)

    def _do_verify(self):
        """Handle email verification."""
        if self._busy:
            return

        token = (self.token_entry.get() or "").strip()

        if not token:
            self._set_status("Please paste the access token from the email link.", error=True)
            return

        # Clean up token if it's very long (paste error)
        if len(token) > 2000:
            self._set_status("Token too long. Make sure you only pasted the token, not the entire URL.", error=True)
            return

        self._busy = True
        self._set_status("Verifying email...")

        try:
            # The token from the email link can be used to set the session
            # This essentially confirms the email
            ok, result = self._verify_email_with_token(token)

            if ok:
                self._set_status("✅ Email verified! Logging you in...")
                self.after(1000, lambda: self.switch_page("login"))
            else:
                self._set_status(f"❌ Verification failed: {result}", error=True)

        except Exception as e:
            self._set_status(f"Error: {e}", error=True)
            logger.exception(f"Email verification error: {e}")

        finally:
            self._busy = False

    def _verify_email_with_token(self, token: str) -> tuple:
        """
        Verify email using the access token from confirmation link.

        Returns:
            (success: bool, message: str)
        """
        try:
            _require_client()

            # Set the session using the token from the email link
            # This confirms the email
            session = _sb.auth.set_session(access_token=token, refresh_token="")

            if session:
                user = session.user
                logger.info(f"Email verified for user {user.id}")
                return True, "Email verified successfully"
            else:
                return False, "Invalid token or session"

        except Exception as e:
            logger.error(f"Error verifying email: {e}")
            return False, str(e)
