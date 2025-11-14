# src/pages/login.py
import os
import customtkinter as ctk
from PIL import Image, ImageDraw

from api_client_supabase import ensure_role_row as sb_ensure_role_row
from api_client_supabase import get_my_role as sb_get_role
from api_client_supabase import login as sb_login
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

# =========================================
# Choose where to go after successful login
# =========================================
NEXT_PAGE = "landing"

# ------------ icon helpers (assets/) ------------
HERE = os.path.dirname(os.path.abspath(__file__))
ASSET_DIRS = [
    os.path.normpath(os.path.join(HERE, "..", "assets")),              # <repo>/src/assets
    os.path.normpath(os.path.join(HERE, "assets")),                    # <repo>/src/pages/assets (fallback)
    os.path.normpath(os.path.join(HERE, "..", "..", "assets")),        # <repo>/assets
]

def _find_asset(name: str) -> str | None:
    for d in ASSET_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return None

def _load_icon(name: str, size=(28, 28), circle_bg="#0E1624"):
    """
    Round 'chip' icon (kept for optional reuse elsewhere).
    """
    path = _find_asset(name)
    if not path:
        return None

    W, H = size
    bg = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(mask).ellipse([(0, 0), (W - 1, H - 1)], fill=255)
    circle = Image.new("RGBA", (W, H), circle_bg)
    bg = Image.composite(circle, bg, mask)

    fg = Image.open(path).convert("RGBA")
    fg.thumbnail((int(W * 0.7), int(H * 0.7)), Image.LANCZOS)
    bg.alpha_composite(fg, ((W - fg.width) // 2, (H - fg.height) // 2))

    return ctk.CTkImage(light_image=bg, dark_image=bg, size=(W, H))

def _ctk_logo(name: str, size=(18, 18)):
    """
    Crisp logo (no circle) for the full-width SocialButton.
    """
    path = _find_asset(name)
    if not path:
        return None
    img = Image.open(path).convert("RGBA")
    img.thumbnail(size, Image.LANCZOS)
    return ctk.CTkImage(light_image=img, dark_image=img, size=size)

# --- polished social button (no unsupported kwargs) ---
class SocialButton(ctk.CTkButton):
    """
    Full-width, left-aligned icon + label with subtle border & hover.
    Uses your theme constants. No 'padx' kwarg (CTkButton doesn't support it).
    """
    def __init__(self, master, text, icon=None, command=None, **kwargs):
        super().__init__(
            master,
            text=text,
            image=icon,
            compound="left",
            anchor="w",
            height=44,
            corner_radius=10,
            font=BODY_FONT,
            text_color=TEXT,
            fg_color=CARD_BG,
            hover_color=OUTLINE_H,
            border_width=1,
            border_color=OUTLINE_BR,
            command=command,
            **kwargs
        )
        self._default_border = OUTLINE_BR
        self.bind("<FocusIn>",  lambda e: self.configure(border_color=PRIMARY))
        self.bind("<FocusOut>", lambda e: self.configure(border_color=self._default_border))
        self.bind("<Return>",   lambda e: self.invoke())


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
            fg_color=PRIMARY,
            hover_color=OUTLINE_H,
            checkbox_height=16,
            checkbox_width=16,
            corner_radius=4,
        )
        show_pw.grid(row=0, column=1, padx=(10, 0))

        # ---------- Social sign-in (full-width buttons) ----------
        social = ctk.CTkFrame(center, fg_color="transparent")
        social.grid(row=3, column=0, sticky="ew", padx=26, pady=(6, 8))
        social.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(social, text="Continue with", font=BODY_FONT, text_color=MUTED)\
            .grid(row=0, column=0, sticky="w", pady=(0, 6))

        # Logos; if missing, buttons still render with text
        google_logo = _ctk_logo("google.png", size=(18, 18))
        github_logo = _ctk_logo("github.png", size=(18, 18))

        # small visual gap between icon and text
        ICON_GAP = "  "  # two spaces (could use "\u2007" for figure-space)

        self.google_btn = SocialButton(
            social,
            text=ICON_GAP + "Continue with Google",
            icon=google_logo,
            command=self._do_google_signin,
        )
        self.google_btn.grid(row=1, column=0, sticky="ew")

        self.github_btn = SocialButton(
            social,
            text=ICON_GAP + "Continue with GitHub",
            icon=github_logo,
            command=self._do_github_signin,
        )
        self.github_btn.grid(row=2, column=0, sticky="ew", pady=(6, 0))

        # Status label
        self.status = ctk.CTkLabel(center, text="", font=BODY_FONT, text_color=MUTED)
        self.status.grid(row=4, column=0, sticky="w", padx=26, pady=(0, 8))

        # ---------- Actions ----------
        actions = ctk.CTkFrame(center, fg_color="transparent")
        actions.grid(row=5, column=0, sticky="ew", padx=26, pady=(4, 22))
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

        # size hint
        center.configure(width=560, height=420)

    # ---------- Lifecycle ----------
    def on_enter(self):
        self._reset_fields()
        self._set_status("")

    def on_resize(self, w: int, h: int):
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
            self.google_btn.configure(state=state)
            self.github_btn.configure(state=state)
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

    # ---------- Email/password login ----------
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

        self._finish_login(token_or_err, user)

    # ---------- Google ----------
    def _do_google_signin(self):
        if self._busy:
            return
        self._set_busy(True)
        self._set_status("Opening Google…")
        try:
            ok, token_or_err, user = login_with_google()
        except Exception as e:
            self._set_busy(False)
            self._set_status(f"Google sign-in error: {e}", error=True)
            return
        if not ok:
            self._set_busy(False)
            self._set_status(f"Google sign-in failed: {token_or_err}", error=True)
            return
        self._finish_login(token_or_err, user or {})

    # ---------- GitHub ----------
    def _do_github_signin(self):
        if self._busy:
            return
        self._set_busy(True)
        self._set_status("Opening GitHub…")
        try:
            ok, token_or_err, user = login_with_github()
        except Exception as e:
            self._set_busy(False)
            self._set_status(f"GitHub sign-in error: {e}", error=True)
            return
        if not ok:
            self._set_busy(False)
            self._set_status(f"GitHub sign-in failed: {token_or_err}", error=True)
            return
        self._finish_login(token_or_err, user or {})

    # ---------- Finalize shared ----------
    def _finish_login(self, token: str, user: dict):
        uid = user.get("id")
        try:
            if uid:
                try:
                    sb_ensure_role_row(token, uid)
                except Exception:
                    pass
                role = sb_get_role(token, uid) or "free"
            else:
                role = "free"
        except Exception:
            role = "free"

        app = self.winfo_toplevel()
        try:
            app.auth_token = token
            app.current_user = user
            app.current_user_role = role
        except Exception:
            pass

        self._reset_fields()
        self._set_status("")
        self._set_busy(False)
        self.switch_page(NEXT_PAGE)
