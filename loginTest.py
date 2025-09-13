# loginTest.py (responsive layout)
import os
import customtkinter as ctk

from file_handler import (
    FileHandler,
    FileDropController,
    open_file_picker,
)

# Theme
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("green")


# ---------------------- Helpers ---------------------------------------------

def clamp(v, lo, hi):
    return max(lo, min(hi, v))

def scaled_font(px, h, lo=12, hi=80):
    # scale "px" proportionally to window height with clamp
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

        self.user = ctk.CTkEntry(form, placeholder_text="Username", height=46)
        self.user.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))

        self.pw = ctk.CTkEntry(form, placeholder_text="Password", height=46, show="*")
        self.pw.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=10)
        self.login_btn = ctk.CTkButton(row, text="Login",
                                       command=lambda: self.switch_page("dashboard"))
        self.login_btn.pack(side="left", padx=(0, 12))
        self.create_btn = ctk.CTkButton(row, text="Create an account",
                                        fg_color="transparent",
                                        text_color=("black", "white"),
                                        hover=False,
                                        command=lambda: self.switch_page("register"))
        self.create_btn.pack(side="left")

    def on_resize(self, w, h):
        # Scale title and entry/button sizes
        self.title.configure(font=("Roboto", scaled_font(72, h, 28, 84)))
        ent_h = clamp(int(h * 0.05), 36, 56)
        btn_h = clamp(int(h * 0.05), 36, 56)
        self.user.configure(height=ent_h)
        self.pw.configure(height=ent_h)
        self.login_btn.configure(height=btn_h, width=clamp(int(w * 0.12), 120, 200))
        self.create_btn.configure(height=btn_h, width=clamp(int(w * 0.18), 150, 260))


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, switch_page, file_handler: FileHandler):
        super().__init__(master)
        self.switch_page = switch_page
        self.file_handler = file_handler
        self.uploaded = []

        # ===== GRID LAYOUT =====
        # Row 0 -> main content (expands)
        # Row 1 -> fixed bottom bar (Logout stays visible)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        # ===== CONTENT WRAPPER =====
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        # Title + status
        self.title = ctk.CTkLabel(content, text="Dashboard", font=("Roboto", 72))
        self.title.pack(pady=(12, 4))

        self.status = ctk.CTkLabel(content, text="")
        self.status.pack(pady=(0, 6))

        # Drop zone (DnD)
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

        # Actions row
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(pady=(6, 0))
        self.analyze_btn = ctk.CTkButton(actions, text="Analyze", width=160, height=40, command=self._analyze)
        self.analyze_btn.pack()

        # Results area (scrollable)
        self.results = ctk.CTkScrollableFrame(content, corner_radius=12)
        self.results.pack(padx=24, pady=(8, 6), fill="both", expand=True)
        self._add_results_header()

        # Browse button below results
        below_results = ctk.CTkFrame(content, fg_color="transparent")
        below_results.pack(pady=(0, 8))
        self.browse_btn = ctk.CTkButton(
            below_results, text="Browse files…", width=160, height=40,
            command=lambda: open_file_picker(
                self, self.file_handler, self._add_result_row, self._set_status
            )
        )
        self.browse_btn.pack()

        # Try to enable Drag & Drop
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

        # ===== FIXED BOTTOM BAR =====
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=1, column=0, sticky="ew", padx=24, pady=(4, 10))
        bottom.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(bottom, text="").grid(row=0, column=0, sticky="w")
        self.logout_btn = ctk.CTkButton(
            bottom, text="Logout", width=160, height=40,
            command=lambda: switch_page("login")
        )
        self.logout_btn.grid(row=0, column=1, sticky="e")

        # ===== Responsive parameters =====
        self._results_min_h = 120
        self._results_max_h = 480

    # ---------- helpers ----------
    def _add_browse_fallback(self, reason: str):
        self._set_status(f"Drag & drop unavailable: {reason}", error=True)

    def _set_border(self, color: str):
        self.dnd.configure(border_color=color)

    def _set_status(self, text: str, error: bool = False):
        # Hide noisy tkdnd banners; show real messages
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

    def _analyze(self):
        if not self.uploaded:
            self._set_status("Nothing to analyze yet — add a file first.", error=True)
            return
        self.switch_page("analysis")

    # ---------- responsiveness ----------
    def on_resize(self, w, h):
        # Title scaling
        title_size = max(28, min(84, int(72 * (h / 900.0))))
        self.title.configure(font=("Roboto", title_size))

        # Drop zone sizing (~72% width, ~26–30% height for laptops)
        dz_w = max(520, min(1400, int(w * 0.72)))
        dz_h = max(180, min(380, int(h * 0.28)))
        self.dnd.configure(width=dz_w, height=dz_h)

        # Label size
        dz_label_size = max(16, min(28, int(24 * (h / 900.0))))
        self.dz_label.configure(font=("Roboto", dz_label_size))

        # Buttons
        btn_w = max(120, min(220, int(w * 0.12)))
        btn_h = max(36, min(56, int(h * 0.05)))
        self.analyze_btn.configure(width=btn_w, height=btn_h)
        self.browse_btn.configure(width=btn_w, height=btn_h)
        self.logout_btn.configure(width=btn_w, height=btn_h)

        # Results height ~30% of window height (clamped)
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

        # Entries
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

        # Actions
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

        self.feedback.configure(text="Account created! You can log in now.", text_color="green")
        self.password.delete(0, "end"); self.password2.delete(0, "end")

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

        # ===== GRID LAYOUT =====
        # Row 0 -> main content (expands)
        # Row 1 -> fixed bottom bar (Logout always visible)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        # ===== CONTENT WRAPPER =====
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew", padx=24, pady=(8, 8))
        content.grid_columnconfigure(0, weight=1)
        for r in (0, 4):
            content.grid_rowconfigure(r, weight=1)  # top/bottom spacers
        content.grid_rowconfigure(1, weight=0)      # title
        content.grid_rowconfigure(2, weight=0)      # gap
        content.grid_rowconfigure(3, weight=0)      # analysis box

        # Title
        self.title = ctk.CTkLabel(content, text="Analysis", font=("Roboto", 72))
        self.title.grid(row=1, column=0, sticky="n", pady=(0, 6))

        # Small vertical gap
        ctk.CTkFrame(content, height=6, fg_color="transparent").grid(row=2, column=0)

        # Centered analysis box (responsive size set in on_resize)
        self.analysis_box = ctk.CTkFrame(
            content,
            corner_radius=16,
            border_width=2,
            border_color="#9aa0a6",
            fg_color=("white", "#000000"),
        )
        self.analysis_box.grid(row=3, column=0)
        self.analysis_box.pack_propagate(False)

        # ===== FIXED BOTTOM BAR =====
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=1, column=0, sticky="ew", padx=24, pady=(4, 12))
        bottom.grid_columnconfigure(0, weight=1)  # spacer
        ctk.CTkLabel(bottom, text="").grid(row=0, column=0, sticky="w")
        self.logout_btn = ctk.CTkButton(
            bottom, text="Logout", width=160, height=40,
            command=lambda: switch_page("login")
        )
        self.logout_btn.grid(row=0, column=1, sticky="e")

    # ---------- responsiveness ----------
    def on_resize(self, w, h):
        # Scale title with window height
        title_px = max(28, min(84, int(72 * (h / 900.0))))
        self.title.configure(font=("Roboto", title_px))

        # Analysis box ~72% of width and ~55% of height (clamped for laptops)
        box_w = max(520, min(1400, int(w * 0.72)))
        box_h = max(260, min(700, int(h * 0.55)))
        self.analysis_box.configure(width=box_w, height=box_h)

        # Logout button sizing
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

        # Global resize binding
        self.bind("<Configure>", self._on_resize)
        self._last_wh = (0, 0)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def show_page(self, name):
        self.pages[name].tkraise()
        # Trigger a resize pass so new page snaps to current size
        self.after_idle(self._force_resize_pass)

    def _on_resize(self, event):
        # Reduce noisy calls by checking if size actually changed
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


if __name__ == "__main__":
    app = App()
    app.mainloop()
