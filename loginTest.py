# loginTest.py
import os
import customtkinter as ctk

from file_handler import (
    FileHandler,
    FileDropController,
    HAS_DND,           # whether tkinterdnd2 module is importable
    open_file_picker,  # file dialog that does NOT require tkdnd
)

# Try to import your Analyse page; fall back to an inline page if missing.
try:
    from Analyse import Analyse as AnalysisPage
except ModuleNotFoundError:
    try:
        from analyse import Analyse as AnalysisPage
    except ModuleNotFoundError:
        class AnalysisPage(ctk.CTkFrame):
            def __init__(self, master, switch_page_callback):
                super().__init__(master)
                content = ctk.CTkFrame(self, fg_color="transparent")
                content.pack(fill="both", expand=True, padx=32, pady=24)
                box = ctk.CTkFrame(
                    content, width=420, height=240,
                    corner_radius=16, border_width=2,
                    border_color="#9aa0a6", fg_color=("white", "#000000")
                )
                box.place(relx=0.5, rely=0.5, anchor="center")
                box.pack_propagate(False)
                ctk.CTkLabel(box, text="Analyzing…", font=("Roboto", 28))\
                    .place(relx=0.5, rely=0.5, anchor="center")
                back = ctk.CTkButton(self, text="Back to Dashboard", width=180,
                                     command=lambda: switch_page_callback("dashboard"))
                back.pack(anchor="w", padx=32, pady=(0, 24))

# Theming
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("green")


class LoginPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)

        ctk.CTkLabel(self, text="Login", font=("Roboto", 80)).pack(pady=100, padx=10)
        self.user = ctk.CTkEntry(self, placeholder_text="Username", width=500, height=50); self.user.pack(pady=20, padx=10)
        self.pw   = ctk.CTkEntry(self, placeholder_text="Password", width=500, height=50, show="*"); self.pw.pack(pady=20, padx=12)

        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(pady=10)
        ctk.CTkButton(row, text="Login", font=("Roboto", 16),
                      command=lambda: switch_page_callback("dashboard")).pack(side="left", padx=(0, 16))
        ctk.CTkButton(row, text="Create an account", fg_color="transparent",
                      text_color=("black", "white"), hover=False,
                      command=lambda: switch_page_callback("register")).pack(side="left")


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback, file_handler: FileHandler):
        super().__init__(master)
        self.switch_page_callback = switch_page_callback
        self.file_handler = file_handler
        self.uploaded: list[dict] = []
        self.browse_btn = None   # <- guard so we never create it twice

        # Title + status
        ctk.CTkLabel(self, text="Dashboard", font=("Roboto", 80)).pack(pady=(20, 6))
        self.status = ctk.CTkLabel(self, text="Drop files or GitHub URLs into the zone below.")
        self.status.pack(pady=(0, 10))

        # Drop zone
        self.dnd = ctk.CTkFrame(self, width=900, height=300, corner_radius=16,
                                border_width=2, border_color="#9aa0a6",
                                fg_color=("white", "#000000"))
        self.dnd.pack(padx=40, pady=12)
        self.dnd.pack_propagate(False)

        dz_label = ctk.CTkLabel(
            self.dnd,
            text=("Drag & Drop files here\n"
                  "• Local file paths (e.g., .exe, .so, .zip, .py)\n"
                  "• GitHub repo URLs (we’ll fetch main/master)"),
            font=("Roboto", 24), justify="center"
        )
        dz_label.place(relx=0.5, rely=0.5, anchor="center")

        # Analyze
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(padx=40, pady=(6, 6), fill="x")
        ctk.CTkButton(actions, text="Analyze", width=160, height=40, command=self._analyze)\
            .pack(pady=2)

        # Results (shorter)
        self.results = ctk.CTkScrollableFrame(self, width=900, height=210, corner_radius=12)
        self.results.pack(padx=40, pady=(8, 10), fill="x")
        self._add_results_header()

        # DnD + fallback (only one Browse button ever)
        dnd_ok = False
        if HAS_DND:
            try:
                self.drop_controller = FileDropController(
                    target_widget=self.dnd,
                    file_handler=self.file_handler,
                    on_processed=self._add_result_row,
                    on_status=self._set_status,
                    on_border=self._set_border,
                )
                try:
                    # also allow drops on the overlay label
                    self.drop_controller_label = FileDropController(
                        target_widget=dz_label,
                        file_handler=self.file_handler,
                        on_processed=self._add_result_row,
                        on_status=self._set_status,
                        on_border=self._set_border,
                    )
                except Exception:
                    pass
                dnd_ok = True
            except Exception as e:
                self._add_browse_fallback(f"Drag & drop unavailable: {e}")

        if not dnd_ok:
            self._add_browse_fallback("Drag & drop package (tkinterdnd2) not installed.")

        # Bottom bar with larger Logout (bottom-right)
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=40, pady=(6, 16))
        ctk.CTkLabel(bottom, text="").pack(side="left", expand=True)
        ctk.CTkButton(
            bottom, text="Logout", width=160, height=40, font=("Roboto", 16),
            command=lambda: switch_page_callback("login")
        ).pack(side="right")

    # ------- helpers -------
    def _add_browse_fallback(self, reason: str):
        """Create a single Browse button if not already present."""
        if self.browse_btn is None:
            self.browse_btn = ctk.CTkButton(
                self, text="Browse files…", width=160, height=40,
                command=lambda: open_file_picker(
                    self, self.file_handler, self._add_result_row, self._set_status
                ),
            )
            self.browse_btn.pack(pady=(6, 0))
        # always show the reason once
        self._set_status(reason, error=True)

    def _set_border(self, color: str):
        self.dnd.configure(border_color=color)

    def _set_status(self, text: str, error: bool = False):
        self.status.configure(text=text, text_color=("red" if error else "#202124"))

    def _add_results_header(self):
        header = ctk.CTkFrame(self.results, fg_color="transparent")
        header.pack(fill="x", padx=8, pady=(6, 4))
        for i, col in enumerate(("Name", "Category", "MIME/Type", "Size (bytes)", "Stored Path / Note")):
            ctk.CTkLabel(header, text=col, font=("Roboto", 14, "bold")).grid(
                row=0, column=i, sticky="w", padx=(8, 12)
            )
        for i in range(5):
            header.grid_columnconfigure(i, weight=(2 if i == 4 else 1))

    def _add_result_row(self, meta: dict):
        self.uploaded.append(meta)
        row = ctk.CTkFrame(self.results, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=2)

        name = meta.get("filename") or meta.get("repo_name") or os.path.basename(meta.get("stored_path", "")) or "-"
        category = meta.get("category", "-")
        mime = meta.get("filetype") or ("zip (repo)" if category == "github-repo" else "-")
        size = str(meta.get("size", "-"))
        stored = meta.get("stored_path") or meta.get("repo_url") or "-"

        for i, val in enumerate((name, category, mime, size, stored)):
            ctk.CTkLabel(row, text=str(val)).grid(row=0, column=i, sticky="w", padx=(8, 12), pady=2)
            row.grid_columnconfigure(i, weight=(2 if i == 4 else 1))

    def _analyze(self):
        if not self.uploaded:
            self._set_status("Nothing to analyze yet — add a file first.", error=True)
            return
        self.switch_page_callback("analysis")



class RegisterPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)

        ctk.CTkLabel(self, text="Create Account", font=("Roboto", 64)).pack(pady=(60, 10))
        form = ctk.CTkFrame(self, corner_radius=16); form.pack(pady=20)
        for i in range(2): form.grid_columnconfigure(i, weight=1, pad=8)

        entry_width, pad_y = 420, 10
        ctk.CTkLabel(form, text="Full name").grid(row=0, column=0, sticky="w", padx=18, pady=(18, 6))
        self.fullname = ctk.CTkEntry(form, placeholder_text="e.g. Alice Tan", width=entry_width)
        self.fullname.grid(row=1, column=0, columnspan=2, padx=18, pady=(0, pad_y))

        ctk.CTkLabel(form, text="Email").grid(row=2, column=0, sticky="w", padx=18, pady=(6, 6))
        self.email = ctk.CTkEntry(form, placeholder_text="e.g. alice@example.com", width=entry_width)
        self.email.grid(row=3, column=0, columnspan=2, padx=18, pady=(0, pad_y))

        ctk.CTkLabel(form, text="Username").grid(row=4, column=0, sticky="w", padx=18, pady=(6, 6))
        self.username = ctk.CTkEntry(form, placeholder_text="Choose a username", width=entry_width)
        self.username.grid(row=5, column=0, columnspan=2, padx=18, pady=(0, pad_y))

        ctk.CTkLabel(form, text="Password").grid(row=6, column=0, sticky="w", padx=18, pady=(6, 6))
        ctk.CTkLabel(form, text="Confirm password").grid(row=6, column=1, sticky="w", padx=18, pady=(6, 6))

        self.password = ctk.CTkEntry(form, placeholder_text="At least 8 characters",
                                     width=entry_width // 2 - 10, show="*")
        self.password.grid(row=7, column=0, padx=(18, 9), pady=(0, pad_y), sticky="ew")
        self.password2 = ctk.CTkEntry(form, placeholder_text="Re-enter password",
                                      width=entry_width // 2 - 10, show="*")
        self.password2.grid(row=7, column=1, padx=(9, 18), pady=(0, pad_y), sticky="ew")

        self.show_pw_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(form, text="Show passwords",
                        variable=self.show_pw_var, command=self._toggle_password_visibility)\
            .grid(row=8, column=0, columnspan=2, padx=18, pady=(0, 10), sticky="w")

        self.feedback = ctk.CTkLabel(form, text="", text_color="red")
        self.feedback.grid(row=9, column=0, columnspan=2, padx=18, pady=(0, 6), sticky="w")

        actions = ctk.CTkFrame(self, fg_color="transparent"); actions.pack(pady=10)
        ctk.CTkButton(actions, text="Create account", width=240, command=self._submit)\
            .pack(side="left", padx=(0, 12))
        ctk.CTkButton(actions, text="Back to Login", fg_color="transparent",
                      text_color=("black", "white"), hover=False,
                      command=lambda: switch_page_callback("login")).pack(side="left")

    def _toggle_password_visibility(self):
        show_char = "" if self.show_pw_var.get() else "*"
        self.password.configure(show=show_char); self.password2.configure(show=show_char)

    def _submit(self):
        name, email, uname = self.fullname.get().strip(), self.email.get().strip(), self.username.get().strip()
        pwd, pwd2 = self.password.get(), self.password2.get()
        if not all([name, email, uname, pwd, pwd2]): self.feedback.configure(text="Please fill in all fields."); return
        if "@" not in email or "." not in email.split("@")[-1]: self.feedback.configure(text="Please enter a valid email address."); return
        if len(pwd) < 8: self.feedback.configure(text="Password must be at least 8 characters."); return
        if pwd != pwd2: self.feedback.configure(text="Passwords do not match."); return
        self.feedback.configure(text="Account created! You can log in now.", text_color="green")
        self.password.delete(0, "end"); self.password2.delete(0, "end")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1500x900"); self.title("CryptoScope")
        self.file_handler = FileHandler(upload_dir="uploads")

        self.container = ctk.CTkFrame(self); self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1); self.container.grid_columnconfigure(0, weight=1)

        self.pages = {
            "login":     LoginPage(self.container, self.show_page),
            "dashboard": DashboardPage(self.container, self.show_page, self.file_handler),
            "register":  RegisterPage(self.container, self.show_page),
            "analysis":  AnalysisPage(self.container, self.show_page),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")
        self.show_page("login")

        # Smooth close (optional)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def show_page(self, name): self.pages[name].tkraise()
    def _on_close(self): self.after(50, self.destroy)  # let pending callbacks finish


if __name__ == "__main__":
    app = App()
    app.mainloop()
