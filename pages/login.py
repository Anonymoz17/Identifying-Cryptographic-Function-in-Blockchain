# pages/login.py
import customtkinter as ctk
from api_client_supabase import (
    login as sb_login,
    get_my_role as sb_get_role,
    ensure_role_row,
)

class LoginPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        self.title = ctk.CTkLabel(self, text="Login", font=("Roboto", 72))
        self.title.pack(pady=(40, 12))

        form = ctk.CTkFrame(self, corner_radius=12)
        form.pack(padx=32, pady=8)

        self.email = ctk.CTkEntry(form, placeholder_text="Email", width=420, height=44)
        self.email.pack(pady=6)

        # Password row with eye toggle
        pw_row = ctk.CTkFrame(form, fg_color="transparent")
        pw_row.pack(fill="x", pady=(6, 0))
        self.pw = ctk.CTkEntry(pw_row, placeholder_text="Password", show="*", width=370, height=44)
        self.pw.pack(side="left")

        self._pw_visible = False
        self.pw_toggle = ctk.CTkButton(
            pw_row, text="👁", width=44, height=44, corner_radius=8,
            command=self._toggle_pw
        )
        self.pw_toggle.pack(side="left", padx=(8, 0))

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=8)
        ctk.CTkButton(actions, text="Login", command=self._do_login, width=160, height=40)\
            .pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="Register", command=lambda: self.switch_page("register"),
                      width=160, height=40).pack(side="left")

        self.status = ctk.CTkLabel(self, text="")
        self.status.pack(pady=(6, 0))

        # --- Hidden focus sink (invisible, used to remove focus from inputs) ---
        self._focus_sink = ctk.CTkButton(self, text="", width=1, height=1, corner_radius=0)
        # Keep it off-layout; .place() off-screen so it can still take focus
        self._focus_sink.place(x=-1000, y=-1000)

    def _toggle_pw(self):
        self._pw_visible = not self._pw_visible
        self.pw.configure(show="" if self._pw_visible else "*")
        self.pw_toggle.configure(text=("🙈" if self._pw_visible else "👁"))

    def _do_login(self):
        email = (self.email.get() or "").strip()
        pw = self.pw.get() or ""
        if not email or not pw:
            self._set_status("Please enter email and password.", True); return

        try:
            ok, token_or_err, user = sb_login(email, pw)
        except Exception as e:
            self._set_status(f"Login error: {e}", True); return

        if not ok or not token_or_err or not user:
            self._set_status("Invalid credentials.", True); return

        app = self.winfo_toplevel()
        app.auth_token = token_or_err
        app.current_user_email = user.get("email") or email

        # Ensure role row, then fetch role
        try:
            uid = user.get("id")
            if uid:
                try:
                    ensure_role_row(app.auth_token, uid)
                except Exception:
                    pass
                role = sb_get_role(app.auth_token, uid) or "free"
            else:
                role = "free"
        except Exception:
            role = "free"
        app.current_user_role = role

        self._set_status(f"Welcome {app.current_user_email} ({role.upper()}).")
        self.switch_page("dashboard")

    def _set_status(self, text, error=False):
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    def reset_ui(self):
        # called by App.logout()
        try: self.email.delete(0, "end")
        except Exception: pass
        try: self.pw.delete(0, "end")
        except Exception: pass
        self._pw_visible = False
        self.pw.configure(show="*")
        self.pw_toggle.configure(text="👁")
        self._set_status("")

    def blur_inputs(self):
        """Sink keyboard focus so entries don't show a caret after logout."""
        try:
            self._focus_sink.focus_set()
        except Exception:
            # fallback: try to focus the toplevel window
            try:
                self.winfo_toplevel().focus_force()
            except Exception:
                pass

    def on_resize(self, w, h):
        if not self.winfo_exists():
            return
        # bucket sizes to reduce churn (font changes are expensive)
        new_size = max(28, min(84, int(72 * (h / 900.0))))
        if getattr(self, "_last_title_size", None) == new_size:
            return
        self._last_title_size = new_size
        try:
            self.title.configure(font=("Roboto", new_size))
        except Exception:
            pass  # ignore if tearing down
