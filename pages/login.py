# pages/login.py
import customtkinter as ctk
print("Loaded pages/login.py (Google button version)")

from api_client_supabase import (
    login as sb_login,
    get_my_role as sb_get_role,
    ensure_role_row,
)
from api_client_google import login_with_google  # required


class LoginPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        self.title = ctk.CTkLabel(self, text="Login", font=("Roboto", 72))
        self.title.pack(pady=(40, 12))

        # --- form ---
        form = ctk.CTkFrame(self, corner_radius=12)
        form.pack(padx=32, pady=8)

        self.email = ctk.CTkEntry(form, placeholder_text="Email", width=420, height=44)
        self.email.pack(pady=6)

        pw_row = ctk.CTkFrame(form, fg_color="transparent")
        pw_row.pack(fill="x", pady=(6, 0))
        self.pw = ctk.CTkEntry(pw_row, placeholder_text="Password", show="*", width=370, height=44)
        self.pw.pack(side="left")

        self._pw_visible = False
        self.pw_toggle = ctk.CTkButton(
            pw_row, text="👁", width=44, height=44, corner_radius=8, command=self._toggle_pw
        )
        self.pw_toggle.pack(side="left", padx=(8, 0))

        # --- actions ---
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=8)
        ctk.CTkButton(actions, text="Login", command=self._do_login, width=160, height=40)\
            .pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="Register", command=lambda: self.switch_page("register"),
                      width=160, height=40).pack(side="left")

        # --- divider + Google button ---
        ctk.CTkLabel(self, text="or").pack(pady=(4, 0))
        self.google_btn = ctk.CTkButton(
            self, text="Continue with Google", width=330, height=40,
            command=self._do_google_signin  # <- this method is defined **inside** the class below
        )
        self.google_btn.pack(pady=(8, 6))

        self.status = ctk.CTkLabel(self, text="")
        self.status.pack(pady=(6, 0))

        # focus sink
        self._focus_sink = ctk.CTkButton(self, text="", width=1, height=1, corner_radius=0)
        self._focus_sink.place(x=-1000, y=-1000)

    # ---------------- Handlers ----------------
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
        self.after(10, lambda: self.switch_page("dashboard"))

    def _do_google_signin(self):
        """Google OAuth flow; on success go to Dashboard."""
        print("Google button clicked")  # DEBUG
        self.google_btn.configure(state="disabled")
        try:
            ok, token_or_err, user = login_with_google()
            print("google: exchange result =", ok, token_or_err, user)  # DEBUG

            if not ok:
                self._set_status(f"Google sign-in failed: {token_or_err}", True)
                return

            app = self.winfo_toplevel()
            app.auth_token = token_or_err
            app.current_user_email = (user or {}).get("email")

            # role lookups should never block navigation
            try:
                uid = (user or {}).get("id")
                if uid:
                    try:
                        ensure_role_row(app.auth_token, uid)
                    except Exception as e:
                        print("google: ensure_role_row error:", e)
                    role = sb_get_role(app.auth_token, uid) or "free"
                else:
                    role = "free"
            except Exception as e:
                print("google: get role error:", e)
                role = "free"
            app.current_user_role = role

            self._set_status(f"Welcome {app.current_user_email} ({role.upper()}).")
            print("google: switching to dashboard...")  # DEBUG
            self.after(10, lambda: self.switch_page("dashboard"))
        finally:
            self.google_btn.configure(state="normal")

    # ---------------- Utilities ----------------
    def _set_status(self, text, error=False):
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    def reset_ui(self):
        try:
            self.email.delete(0, "end"); self.pw.delete(0, "end")
        except Exception:
            pass
        self._pw_visible = False
        self.pw.configure(show="*"); self.pw_toggle.configure(text="👁")
        self._set_status("")

    def blur_inputs(self):
        try:
            self._focus_sink.focus_set()
        except Exception:
            try:
                self.winfo_toplevel().focus_force()
            except Exception:
                pass

    def on_resize(self, w, h):
        new_size = max(28, min(84, int(72 * (h / 900.0))))
        if getattr(self, "_last_title_size", None) == new_size:
            return
        self._last_title_size = new_size
        try:
            self.title.configure(font=("Roboto", new_size))
        except Exception:
            pass


# sanity check: this must print True
print("Sanity: class has _do_google_signin ->", hasattr(LoginPage, "_do_google_signin"))
