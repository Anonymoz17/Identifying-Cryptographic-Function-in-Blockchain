# pages/login.py
import os
import customtkinter as ctk
from PIL import Image, ImageDraw

from api_client_supabase import (
    login as sb_login,
    get_my_role as sb_get_role,
    ensure_role_row,
)
from api_client_google import login_with_google
from api_client_github import login_with_github

# ---------------------------------------------
# Icon loader (looks in assets/ and assests/)
# ---------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
ASSET_DIRS = [
    os.path.normpath(os.path.join(HERE, "..", "assets")),
    os.path.normpath(os.path.join(HERE, "..", "assests")),  # fallback if old folder name
]

def _find_asset(name: str):
    for d in ASSET_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return None

def _load_icon(name: str, size=(28, 28), circle_bg="#F3F4F6"):
    """
    Load an icon (PNG), resize it, and place it on a circular light background so
    white-on-transparent logos remain visible. Returns a CTkImage or None.
    """
    path = _find_asset(name)
    if not path:
        return None
    try:
        W, H = size

        # circular background
        bg = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        mask = Image.new("L", (W, H), 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse([(0, 0), (W - 1, H - 1)], fill=255)
        circle = Image.new("RGBA", (W, H), circle_bg)
        bg = Image.composite(circle, bg, mask)

        # foreground logo
        fg = Image.open(path).convert("RGBA")
        fg.thumbnail((int(W * 0.7), int(H * 0.7)), Image.LANCZOS)
        x = (W - fg.width) // 2
        y = (H - fg.height) // 2
        bg.alpha_composite(fg, (x, y))

        return ctk.CTkImage(light_image=bg, dark_image=bg, size=size)
    except Exception:
        return None


# ---------------------------------------------
# Login Page
# ---------------------------------------------
class LoginPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        # Center container
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center")

        # Card
        card = ctk.CTkFrame(container, corner_radius=16, border_width=1, border_color="#374151")
        card.grid(row=0, column=0, padx=16, pady=16, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(card, text="Welcome to CryptoScope", font=("Segoe UI", 24, "bold"))
        subtitle = ctk.CTkLabel(card, text="Sign in to continue", font=("Segoe UI", 12))
        title.grid(row=0, column=0, padx=20, pady=(20, 6), sticky="w")
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # Email / Password
        self.email = ctk.CTkEntry(card, placeholder_text="Email", height=40, width=420, corner_radius=10)
        self.pw    = ctk.CTkEntry(card, placeholder_text="Password", show="•", height=40, width=420, corner_radius=10)
        self.email.grid(row=2, column=0, padx=20, pady=(8, 6))
        self.pw.grid(row=3, column=0, padx=20, pady=(0, 8))

        ctk.CTkButton(card, text="Sign in", height=40, corner_radius=10, command=self._do_login)\
            .grid(row=4, column=0, padx=20, pady=(4, 10), sticky="ew")

        # Divider
        ctk.CTkFrame(card, height=1, fg_color="#1F2937")\
            .grid(row=5, column=0, padx=20, pady=(6, 6), sticky="ew")
        ctk.CTkLabel(card, text="Or continue with", font=("Segoe UI", 11))\
            .grid(row=6, column=0, padx=20, pady=(0, 6), sticky="w")

        # Icon buttons row
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.grid(row=7, column=0, padx=20, pady=(0, 10), sticky="w")

        g_icon  = _load_icon("google.png")
        gh_icon = _load_icon("github.png")

        self.google_btn = ctk.CTkButton(
            row, width=44, height=44, corner_radius=22, text="", image=g_icon,
            command=self._do_google_signin, fg_color="#ffffff", hover_color="#f3f4f6",
            border_width=1, border_color="#E5E7EB"
        )
        self.google_btn.pack(side="left", padx=(0, 8))

        self.github_btn = ctk.CTkButton(
            row, width=44, height=44, corner_radius=22, text="", image=gh_icon,
            command=self._do_github_signin, fg_color="#ffffff", hover_color="#f3f4f6",
            border_width=1, border_color="#E5E7EB"
        )
        self.github_btn.pack(side="left", padx=(0, 8))

        # Register link (brighter text for dark mode)
        reg_row = ctk.CTkFrame(card, fg_color="transparent")
        reg_row.grid(row=8, column=0, padx=20, pady=(4, 16), sticky="ew")
        ctk.CTkLabel(reg_row, text="No account?", font=("Segoe UI", 11)).pack(side="left")
        ctk.CTkButton(
            reg_row,
            text="Create account",
            height=28,
            corner_radius=8,
            fg_color="transparent",
            hover_color="#1F2937",
            border_width=1,
            border_color="#374151",
            text_color="#E5E7EB",  # brighter
            command=lambda: self.switch_page("register"),
        ).pack(side="left", padx=(8, 0))

        self.status = ctk.CTkLabel(card, text="", font=("Segoe UI", 11))
        self.status.grid(row=9, column=0, padx=20, pady=(0, 16), sticky="w")

    # ---------- handlers ----------
    def _do_login(self):
        email = (self.email.get() or "").strip()
        pw = self.pw.get() or ""
        if not email or not pw:
            return self._set_status("Please enter email and password.", True)
        try:
            ok, token_or_err, user = sb_login(email, pw)
        except Exception as e:
            return self._set_status(f"Login error: {e}", True)
        if not ok or not token_or_err or not user:
            return self._set_status("Invalid credentials.", True)

        app = self.winfo_toplevel()
        app.auth_token = token_or_err
        app.current_user_email = user.get("email") or email
        uid = user.get("id")
        if uid:
            try:
                ensure_role_row(app.auth_token, uid)
            except Exception:
                pass
            app.current_user_role = sb_get_role(app.auth_token, uid) or "free"
        else:
            app.current_user_role = "free"
        self.switch_page("dashboard")

    def _do_google_signin(self):
        self.google_btn.configure(state="disabled")
        try:
            ok, token_or_err, user = login_with_google()
            if not ok:
                return self._set_status(f"Google sign-in failed: {token_or_err}", True)

            app = self.winfo_toplevel()
            app.auth_token = token_or_err
            app.current_user_email = (user or {}).get("email") or "(google user)"
            uid = (user or {}).get("id") or ""

            try:
                if uid:
                    try:
                        ensure_role_row(app.auth_token, uid)
                    except Exception:
                        pass
                    app.current_user_role = sb_get_role(app.auth_token, uid) or "free"
                else:
                    app.current_user_role = "free"
            except Exception:
                app.current_user_role = "free"

            self.switch_page("dashboard")
        finally:
            self.google_btn.configure(state="normal")

    def _do_github_signin(self):
        self.github_btn.configure(state="disabled")
        try:
            ok, token_or_err, user = login_with_github()
            if not ok:
                return self._set_status(f"GitHub sign-in failed: {token_or_err}", True)

            app = self.winfo_toplevel()
            app.auth_token = token_or_err
            app.current_user_email = (user or {}).get("email") or "(github user)"
            uid = (user or {}).get("id") or ""

            try:
                if uid:
                    try:
                        ensure_role_row(app.auth_token, uid)
                    except Exception:
                        pass
                    app.current_user_role = sb_get_role(app.auth_token, uid) or "free"
                else:
                    app.current_user_role = "free"
            except Exception:
                app.current_user_role = "free"

            self.switch_page("dashboard")
        finally:
            self.github_btn.configure(state="normal")

    def _set_status(self, text, error=False):
        self.status.configure(text=text, text_color=("red" if error else "#4B5563"))

    # Optional hooks used by App.logout()
    def reset_ui(self):
        try:
            self.email.delete(0, "end")
        except Exception:
            pass
        try:
            self.pw.delete(0, "end")
        except Exception:
            pass
        self._set_status("")

    def blur_inputs(self):
        try:
            self.focus_force()
        except Exception:
            pass
