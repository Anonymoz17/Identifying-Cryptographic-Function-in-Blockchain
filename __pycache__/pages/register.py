# pages/register.py
import customtkinter as ctk
from api_client_supabase import register_user as sb_register

class RegisterPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        self.title = ctk.CTkLabel(self, text="Register", font=("Roboto", 72))
        self.title.pack(pady=(40, 12))

        form = ctk.CTkFrame(self, corner_radius=12)
        form.pack(padx=32, pady=8)

        self.full_name = ctk.CTkEntry(form, placeholder_text="Full name", width=420, height=44)
        self.full_name.pack(pady=6)

        self.username = ctk.CTkEntry(form, placeholder_text="Username", width=420, height=44)
        self.username.pack(pady=6)

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
        ctk.CTkButton(actions, text="Create account", command=self._do_register,
                      width=180, height=40).pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="Back to Login",
                      command=lambda: self.switch_page("login"),
                      width=160, height=40).pack(side="left")

        self.status = ctk.CTkLabel(self, text="")
        self.status.pack(pady=(6, 0))

    def _toggle_pw(self):
        self._pw_visible = not self._pw_visible
        self.pw.configure(show="" if self._pw_visible else "*")
        self.pw_toggle.configure(text=("🙈" if self._pw_visible else "👁"))

    def _do_register(self):
        full_name = (self.full_name.get() or "").strip()
        username  = (self.username.get()  or "").strip()
        email     = (self.email.get()     or "").strip()
        password  = self.pw.get() or ""

        if not full_name or not username or not email or not password:
            self._set_status("Please fill in full name, username, email, and password.", True); return

        try:
            ok, data = sb_register(email=email, password=password,
                                   full_name=full_name, username=username)
        except Exception as e:
            self._set_status(f"Registration error: {e}", True); return

        if ok:
            self._set_status("Account created. Please log in.")
            self.switch_page("login")
        else:
            msg = data if isinstance(data, str) else "Registration failed."
            self._set_status(msg, True)

    def _set_status(self, text, error=False):
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    def on_resize(self, w, h):
        title_size = max(28, min(84, int(72 * (h / 900.0))))
        self.title.configure(font=("Roboto", title_size))
