# loginTest.py (Supabase-wired, responsive)
import os
import customtkinter as ctk

from file_handler import (
    FileHandler,
    FileDropController,
    open_file_picker,
)

from api_client_supabase import (
    register_user as sb_register,
    login as sb_login,
    get_my_role as sb_get_role,
    admin_set_tier as sb_admin_set_tier,  # optional (for future admin page)
)

# Theme
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("green")

# ---------------------- Helpers ---------------------------------------------

def clamp(v, lo, hi):
    return max(lo, min(hi, v))

def scaled_font(px, h, lo=12, hi=80):
    return clamp(int(px * (h / 900.0)), lo, hi)

# ---------------------- Pages -----------------------------------------------

class LoginPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        self.title = ctk.CTkLabel(self, text="Login", font=("Roboto", 72))
        self.title.pack(pady=(40, 12))

        form = ctk.CTkFrame(self, corner_radius=12)
        form.pack(fill="x", expand=False, padx=32, pady=8)
        form.grid_columnconfigure(0, weight=1)

        # Email-based login (Supabase Auth)
        self.email = ctk.CTkEntry(form, placeholder_text="Email", height=46)
        self.email.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))

        self.pw = ctk.CTkEntry(form, placeholder_text="Password", height=46, show="*")
        self.pw.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=10)
        self.login_btn = ctk.CTkButton(row, text="Login", command=self._do_login)
        self.login_btn.pack(side="left", padx=(0, 12))
        self.create_btn = ctk.CTkButton(row, text="Create an account",
                                        fg_color="transparent",
                                        text_color=("black", "white"),
                                        hover=False,
                                        command=lambda: self.switch_page("register"))
        self.create_btn.pack(side="left")

        # feedback
        self.feedback = ctk.CTkLabel(self, text="", text_color="red")
        self.feedback.pack(pady=(4, 0))

    def _do_login(self):
        email = (self.email.get() or "").strip()
        pw = self.pw.get()

        if "@" not in email:
            self.feedback.configure(text="Please log in with your EMAIL (not username)."); return
        if not email or not pw:
            self.feedback.configure(text="Please enter email and password."); return

        # progress hint
        self.login_btn.configure(state="disabled", text="Logging in…")
        self.update_idletasks()

        ok, token_or_err, user = sb_login(email, pw)
        if not ok:
            self.feedback.configure(text=f"Login failed: {token_or_err}")
            print("Login error:", token_or_err)
            self.login_btn.configure(state="normal", text="Login")
            return

        # success
        app = self.winfo_toplevel()
        app.auth_token = token_or_err
        app.current_user = user

        # ensure role row exists, then read it (tolerant)
        try:
            from api_client_supabase import ensure_role_row
            ensure_role_row(app.auth_token, user["id"])
        except Exception as e:
            print("ensure_role_row error:", e)
        try:
            app.current_user_role = sb_get_role(app.auth_token, user["id"])
        except Exception as e:
            print("get_my_role error:", e)
            app.current_user_role = "free"

        self.login_btn.configure(state="normal", text="Login")
        self.switch_page("dashboard")

    def on_resize(self, w, h):
        self.title.configure(font=("Roboto", scaled_font(72, h, 28, 84)))
        ent_h = clamp(int(h * 0.05), 36, 56)
        btn_h = clamp(int(h * 0.05), 36, 56)
        for e in (self.email, self.pw):
            e.configure(height=ent_h)
        self.login_btn.configure(height=btn_h, width=clamp(int(w * 0.12), 120, 200))
        self.create_btn.configure(height=btn_h, width=clamp(int(w * 0.18), 150, 260))

    def clear_fields(self):
        try:
            self.email.delete(0, "end")
            self.pw.delete(0, "end")
        except Exception:
            pass
        self.feedback.configure(text="")
        # ensure button text/state is normal next time
        self.login_btn.configure(state="normal", text="Login")
        # optional: focus the email box when returning
        self.after(50, lambda: self.email.focus_set())



class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, switch_page, file_handler: FileHandler):
        super().__init__(master)
        self.switch_page = switch_page
        self.file_handler = file_handler
        self.uploaded = []

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        self.title = ctk.CTkLabel(content, text="Dashboard", font=("Roboto", 72))
        self.title.pack(pady=(12, 4))

        # Role/Status
        self.status = ctk.CTkLabel(content, text="")
        self.status.pack(pady=(0, 6))

        # Drop zone
        self.dnd = ctk.CTkFrame(
            content,
            corner_radius=16,
            border_width=2,
            border_color="#9aa0a6",
            fg_color=("white", "#000000"),
        )
        self.dnd.pack(padx=24, pady=6, fill="x")
        self.dnd.pack_propagate(False)

        self.dz_label = ctk.CTkLabel(
            self.dnd,
            text=("Drag & Drop files here\n"
                  "• Local file paths (e.g., .exe, .so, .zip, .py)\n"
                  "• GitHub repo URLs (not implemented in this sample)"),
            font=("Roboto", 24),
            justify="center",
        )
        self.dz_label.place(relx=0.5, rely=0.5, anchor="center")

        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(pady=(6, 0))
        self.analyze_btn = ctk.CTkButton(actions, text="Analyze", width=160, height=40, command=self._analyze)
        self.analyze_btn.pack()

        self.results = ctk.CTkScrollableFrame(content, corner_radius=12)
        self.results.pack(padx=24, pady=(8, 6), fill="both", expand=True)
        self._add_results_header()

        below_results = ctk.CTkFrame(content, fg_color="transparent")
        below_results.pack(pady=(0, 8))
        self.browse_btn = ctk.CTkButton(
            below_results, text="Browse files…", width=160, height=40,
            command=lambda: open_file_picker(
                self, self.file_handler, self._add_result_row, self._set_status
            )
        )
        self.browse_btn.pack()

        # Try DnD
        try:
            self.ctrl_zone = FileDropController(
                target_widget=self.dnd,
                file_handler=self.file_handler,
                on_processed=self._add_result_row,
                on_status=self._set_status,
                on_border=self._set_border,
            )
            try:
                self.ctrl_label = FileDropController(
                    target_widget=self.dz_label,
                    file_handler=self.file_handler,
                    on_processed=self._add_result_row,
                    on_status=self._set_status,
                    on_border=self._set_border,
                )
            except Exception:
                pass
        except Exception as e:
            self._add_browse_fallback(str(e))

        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=1, column=0, sticky="ew", padx=24, pady=(4, 10))
        bottom.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(bottom, text="").grid(row=0, column=0, sticky="w")
        self.logout_btn = ctk.CTkButton(
            bottom, text="Logout", width=160, height=40,
            command=self._logout
        )
        self.logout_btn.grid(row=0, column=1, sticky="e")

        self._results_min_h = 120
        self._results_max_h = 480

    def _logout(self):
        app = self.winfo_toplevel()
        app.logout()

    def reset_ui(self):
        """Clear transient state when a user logs out."""
        self.uploaded.clear()
        # reset status + border color
        self._set_status("")
        self._set_border("#9aa0a6")
        # clear results list (remove rows + header then re-add header)
        try:
            for w in self.results.winfo_children():
                w.destroy()
        except Exception:
            pass
        self._add_results_header()


    def _add_browse_fallback(self, reason: str):
        self._set_status(f"Drag & drop unavailable: {reason}", error=True)

    def _set_border(self, color: str):
        self.dnd.configure(border_color=color)

    def _set_status(self, text: str, error: bool = False):
        low = (text or "").lower()
        if low.startswith("tkdnd") or "dnd ready" in low:
            return
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    def _add_results_header(self):
        header = ctk.CTkFrame(self.results, fg_color="transparent")
        header.pack(fill="x", padx=8, pady=(6, 4))
        for i, col in enumerate(("Name", "Category", "MIME/Type", "Size (bytes)", "Stored Path / Note")):
            ctk.CTkLabel(header, text=col, font=("Roboto", 14, "bold")).grid(
                row=0, column=i, sticky="w", padx=(8, 12))
        for i in range(5):
            header.grid_columnconfigure(i, weight=(2 if i == 4 else 1))

    def _add_result_row(self, meta: dict):
        app = self.winfo_toplevel()
        tier = getattr(app, "current_user_role", "free")
        self.uploaded.append(meta)
        row = ctk.CTkFrame(self.results, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=2)

        name = meta.get("filename") or os.path.basename(meta.get("stored_path", "")) or "-"
        category = meta.get("category", "-")
        mime = meta.get("filetype", "-")
        size = str(meta.get("size", "-"))
        stored = meta.get("stored_path") or "-"

        for i, val in enumerate((name, category, mime, size, stored)):
            ctk.CTkLabel(row, text=str(val)).grid(row=0, column=i, sticky="w", padx=(8, 12), pady=2)
            row.grid_columnconfigure(i, weight=(2 if i == 4 else 1))

        self.update_idletasks()
        # Example: nudge status based on tier
        self._set_status(f"Logged in as {tier.upper()}")

    def _analyze(self):
        app = self.winfo_toplevel()
        if not getattr(app, "auth_token", None):
            self._set_status("Please log in first.", error=True); return
        # Example of gating: only premium/admin may analyze when > 1 uploaded, etc.
        tier = getattr(app, "current_user_role", "free")
        if tier == "free" and len(self.uploaded) > 1:
            self._set_status("Free tier: analyze 1 file at a time. Upgrade to analyze multiple.", error=True)
            return
        self.switch_page("analysis")

    def on_resize(self, w, h):
        title_size = max(28, min(84, int(72 * (h / 900.0))))
        self.title.configure(font=("Roboto", title_size))

        dz_w = max(520, min(1400, int(w * 0.72)))
        dz_h = max(180, min(380, int(h * 0.28)))
        self.dnd.configure(width=dz_w, height=dz_h)

        dz_label_size = max(16, min(28, int(24 * (h / 900.0))))
        self.dz_label.configure(font=("Roboto", dz_label_size))

        btn_w = max(120, min(220, int(w * 0.12)))
        btn_h = max(36, min(56, int(h * 0.05)))
        self.analyze_btn.configure(width=btn_w, height=btn_h)
        self.browse_btn.configure(width=btn_w, height=btn_h)
        self.logout_btn.configure(width=btn_w, height=btn_h)

        target_h = max(self._results_min_h, min(self._results_max_h, int(h * 0.30)))
        self.results.configure(height=target_h)


class RegisterPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        self.title = ctk.CTkLabel(self, text="Create Account", font=("Roboto", 64))
        self.title.pack(pady=(24, 8))

        form = ctk.CTkFrame(self, corner_radius=16)
        form.pack(pady=12, padx=24, fill="x")
        for i in range(2):
            form.grid_columnconfigure(i, weight=1, pad=8)

        self.fullname_lbl = ctk.CTkLabel(form, text="Full name")
        self.fullname_lbl.grid(row=0, column=0, sticky="w", padx=18, pady=(12, 4))
        self.fullname = ctk.CTkEntry(form, placeholder_text="e.g. Alice Tan")
        self.fullname.grid(row=1, column=0, columnspan=2, padx=18, pady=(0, 8), sticky="ew")

        self.email_lbl = ctk.CTkLabel(form, text="Email")
        self.email_lbl.grid(row=2, column=0, sticky="w", padx=18, pady=(8, 4))
        self.email = ctk.CTkEntry(form, placeholder_text="e.g. alice@example.com")
        self.email.grid(row=3, column=0, columnspan=2, padx=18, pady=(0, 8), sticky="ew")

        self.username_lbl = ctk.CTkLabel(form, text="Username")
        self.username_lbl.grid(row=4, column=0, sticky="w", padx=18, pady=(8, 4))
        self.username = ctk.CTkEntry(form, placeholder_text="Choose a username")
        self.username.grid(row=5, column=0, columnspan=2, padx=18, pady=(0, 8), sticky="ew")

        self.pw_lbl = ctk.CTkLabel(form, text="Password")
        self.pw_lbl.grid(row=6, column=0, sticky="w", padx=18, pady=(8, 4))
        self.pw2_lbl = ctk.CTkLabel(form, text="Confirm password")
        self.pw2_lbl.grid(row=6, column=1, sticky="w", padx=18, pady=(8, 4))

        self.password = ctk.CTkEntry(form, placeholder_text="At least 8 characters", show="*")
        self.password.grid(row=7, column=0, padx=(18, 9), pady=(0, 8), sticky="ew")
        self.password2 = ctk.CTkEntry(form, placeholder_text="Re-enter password", show="*")
        self.password2.grid(row=7, column=1, padx=(9, 18), pady=(0, 8), sticky="ew")

        self.show_pw_var = ctk.BooleanVar(value=False)
        self.show_pw = ctk.CTkCheckBox(form, text="Show passwords",
                                       variable=self.show_pw_var, command=self._toggle_pw)
        self.show_pw.grid(row=8, column=0, columnspan=2, padx=18, pady=(0, 8), sticky="w")

        self.feedback = ctk.CTkLabel(form, text="", text_color="red")
        self.feedback.grid(row=9, column=0, columnspan=2, padx=18, pady=(0, 6), sticky="w")

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=8)
        self.create_btn = ctk.CTkButton(actions, text="Create account", width=240, command=self._submit)
        self.create_btn.pack(side="left", padx=(0, 12))
        self.back_btn = ctk.CTkButton(actions, text="Back to Login",
                                      fg_color="transparent",
                                      text_color=("black", "white"), hover=False,
                                      command=lambda: switch_page("login"))
        self.back_btn.pack(side="left")

    def _toggle_pw(self):
        show = "" if self.show_pw_var.get() else "*"
        self.password.configure(show=show)
        self.password2.configure(show=show)

    def _submit(self):
        name, email, uname = self.fullname.get().strip(), self.email.get().strip(), self.username.get().strip()
        pwd, pwd2 = self.password.get(), self.password2.get()
        if not all([name, email, uname, pwd, pwd2]):
            self.feedback.configure(text="Please fill in all fields."); return
        if "@" not in email or "." not in email.split("@")[-1]:
            self.feedback.configure(text="Please enter a valid email address."); return
        if len(pwd) < 8:
            self.feedback.configure(text="Password must be at least 8 characters."); return
        if pwd != pwd2:
            self.feedback.configure(text="Passwords do not match."); return

        ok, data = sb_register(email=email, password=pwd, full_name=name, username=uname)
        if ok:
            self.feedback.configure(text="Account created! Redirecting to Login…", text_color="green")
            self.password.delete(0, "end"); self.password2.delete(0, "end")
            self.after(600, lambda: self.switch_page("login"))
        else:
            self.feedback.configure(text=str(data), text_color="red")


    def on_resize(self, w, h):
        self.title.configure(font=("Roboto", scaled_font(64, h, 26, 76)))
        ent_h = clamp(int(h * 0.05), 36, 56)
        for e in (self.fullname, self.email, self.username, self.password, self.password2):
            e.configure(height=ent_h)
        btn_h = clamp(int(h * 0.05), 36, 56)
        self.create_btn.configure(height=btn_h, width=clamp(int(w * 0.16), 180, 280))
        self.back_btn.configure(height=btn_h, width=clamp(int(w * 0.14), 150, 240))


class AnalysisPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=24, pady=(8, 8))
        content.grid_columnconfigure(0, weight=1)
        for r in (0, 4):
            content.grid_rowconfigure(r, weight=1)
        content.grid_rowconfigure(1, weight=0)
        content.grid_rowconfigure(2, weight=0)
        content.grid_rowconfigure(3, weight=0)

        self.title = ctk.CTkLabel(content, text="Analysis", font=("Roboto", 72))
        self.title.grid(row=1, column=0, sticky="n", pady=(0, 6))

        ctk.CTkFrame(content, height=6, fg_color="transparent").grid(row=2, column=0)

        self.analysis_box = ctk.CTkFrame(
            content,
            corner_radius=16,
            border_width=2,
            border_color="#9aa0a6",
            fg_color=("white", "#000000"),
        )
        self.analysis_box.grid(row=3, column=0)
        self.analysis_box.pack_propagate(False)

        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=1, column=0, sticky="ew", padx=24, pady=(4, 12))
        bottom.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(bottom, text="").grid(row=0, column=0, sticky="w")
        self.logout_btn = ctk.CTkButton(
            bottom, text="Logout", width=160, height=40,
            command=self._logout
        )
        self.logout_btn.grid(row=0, column=1, sticky="e")

    def _logout(self):
        app = self.winfo_toplevel()
        app.logout()

    def on_resize(self, w, h):
        title_px = max(28, min(84, int(72 * (h / 900.0))))
        self.title.configure(font=("Roboto", title_px))
        box_w = max(520, min(1400, int(w * 0.72)))
        box_h = max(260, min(700, int(h * 0.55)))
        self.analysis_box.configure(width=box_w, height=box_h)
        btn_w = max(120, min(220, int(w * 0.12)))
        btn_h = max(36, min(56, int(h * 0.05)))
        self.logout_btn.configure(width=btn_w, height=btn_h)


# ---------------------- App root ---------------------------------------------

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1500x900")
        self.title("CryptoScope")

        self.file_handler = FileHandler(upload_dir="uploads")

        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.pages = {
            "login":     LoginPage(self.container, self.show_page),
            "dashboard": DashboardPage(self.container, self.show_page, self.file_handler),
            "register":  RegisterPage(self.container, self.show_page),
            "analysis":  AnalysisPage(self.container, self.show_page),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")
        self.show_page("login")

        # Auth state
        self.auth_token = None
        self.current_user = None
        self.current_user_role = "free"

        self.bind("<Configure>", self._on_resize)
        self._last_wh = (0, 0)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def show_page(self, name):
        self.pages[name].tkraise()
        self.after_idle(self._force_resize_pass)

    def _on_resize(self, event):
        try:
            w = self.winfo_width()
            h = self.winfo_height()
            if (w, h) == self._last_wh:
                return
            self._last_wh = (w, h)
            for p in self.pages.values():
                if hasattr(p, "on_resize"):
                    p.on_resize(w, h)
        except Exception:
            pass

    def _force_resize_pass(self):
        w = self.winfo_width()
        h = self.winfo_height()
        for p in self.pages.values():
            if hasattr(p, "on_resize"):
                p.on_resize(w, h)

    def _on_close(self):
        try:
            self.withdraw()
        except Exception:
            pass
        self.after(120, self.destroy)

    def logout(self):
        try:
            from api_client_supabase import logout as sb_logout
            sb_logout()
        except Exception:
            pass
        # wipe in-memory auth
        self.auth_token = None
        self.current_user = None
        self.current_user_role = "free"

        # reset per-page UI
        if "dashboard" in self.pages and hasattr(self.pages["dashboard"], "reset_ui"):
            self.pages["dashboard"].reset_ui()
        if "login" in self.pages and hasattr(self.pages["login"], "clear_fields"):
            self.pages["login"].clear_fields()

        # navigate back to Login
        self.show_page("login")



if __name__ == "__main__":
    app = App()
    app.mainloop()
