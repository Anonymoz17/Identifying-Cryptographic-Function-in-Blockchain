import customtkinter as ctk

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("green")


class LoginPage(ctk.CTkFrame):
    def __init__ (self, master, switch_page_callback):
        super().__init__(master)

        self.label = ctk.CTkLabel(self, text='Login', font=("Roboto", 80))
        self.label.pack(pady=100, padx=10)

        self.user = ctk.CTkEntry(self, placeholder_text="Username", width=500, height=50)
        self.user.pack(pady=20, padx=10)

        self.pw = ctk.CTkEntry(self, placeholder_text="Password", width=500, height=50, show="*")
        self.pw.pack(pady=20, padx=12)

        # Login row
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=10)
        self.login = ctk.CTkButton(row, text="Login", font=('Roboto', 16),
                                   command=lambda: switch_page_callback("dashboard"))
        self.login.pack(side="left", padx=(0, 16))

        # Link-style button to register
        self.register_link = ctk.CTkButton(
            row, text="Create an account", fg_color="transparent",
            text_color=("black", "white"), hover=False,
            command=lambda: switch_page_callback("register")
        )
        self.register_link.pack(side="left")


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)

        # page title
        self.label = ctk.CTkLabel(self, text="Dashboard", font=("Roboto", 80))
        self.label.pack(pady=20)

        self.dnd = ctk.CTkFrame(
            self,
            width=900, height=600,
            corner_radius=16,
            border_width=2,
            border_color="#9aa0a6",
            fg_color=("white", "#000000")
        )
        self.dnd.pack(padx=40, pady=20)
        self.dnd.pack_propagate(False)  # keep the fixed size above

        dz_label = ctk.CTkLabel(
            self.dnd,
            text="Drag & Drop files here",
            font=("Roboto", 28),
            justify="center"
        )
        dz_label.place(relx=0.5, rely=0.5, anchor="center")

        self.logout_button = ctk.CTkButton(self, text="Logout",
                                           command=lambda: switch_page_callback("login"))
        self.logout_button.pack(pady=10)


class RegisterPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)

        self.title = ctk.CTkLabel(self, text="Create Account", font=("Roboto", 64))
        self.title.pack(pady=(60, 10))

        form = ctk.CTkFrame(self, corner_radius=16)
        form.pack(pady=20)

        # Use a grid inside the form for neat alignment
        for i in range(2):
            form.grid_columnconfigure(i, weight=1, pad=8)

        entry_width = 420
        pad_y = 10

        # Full Name
        ctk.CTkLabel(form, text="Full name").grid(row=0, column=0, sticky="w", padx=18, pady=(18, 6))
        self.fullname = ctk.CTkEntry(form, placeholder_text="e.g. Alice Tan", width=entry_width)
        self.fullname.grid(row=1, column=0, columnspan=2, padx=18, pady=(0, pad_y))

        # Email
        ctk.CTkLabel(form, text="Email").grid(row=2, column=0, sticky="w", padx=18, pady=(6, 6))
        self.email = ctk.CTkEntry(form, placeholder_text="e.g. alice@example.com", width=entry_width)
        self.email.grid(row=3, column=0, columnspan=2, padx=18, pady=(0, pad_y))

        # Username
        ctk.CTkLabel(form, text="Username").grid(row=4, column=0, sticky="w", padx=18, pady=(6, 6))
        self.username = ctk.CTkEntry(form, placeholder_text="Choose a username", width=entry_width)
        self.username.grid(row=5, column=0, columnspan=2, padx=18, pady=(0, pad_y))

        # Password + Confirm Password
        ctk.CTkLabel(form, text="Password").grid(row=6, column=0, sticky="w", padx=18, pady=(6, 6))
        ctk.CTkLabel(form, text="Confirm password").grid(row=6, column=1, sticky="w", padx=18, pady=(6, 6))

        self.password = ctk.CTkEntry(form, placeholder_text="At least 8 characters", width=entry_width//2-10, show="*")
        self.password.grid(row=7, column=0, padx=(18, 9), pady=(0, pad_y), sticky="ew")

        self.password2 = ctk.CTkEntry(form, placeholder_text="Re-enter password", width=entry_width//2-10, show="*")
        self.password2.grid(row=7, column=1, padx=(9, 18), pady=(0, pad_y), sticky="ew")

        # Show password toggle
        self.show_pw_var = ctk.BooleanVar(value=False)
        self.show_pw = ctk.CTkCheckBox(
            form, text="Show passwords", variable=self.show_pw_var, command=self._toggle_password_visibility
        )
        self.show_pw.grid(row=8, column=0, columnspan=2, padx=18, pady=(0, 10), sticky="w")

        # Feedback label (for validation messages)
        self.feedback = ctk.CTkLabel(form, text="", text_color="red")
        self.feedback.grid(row=9, column=0, columnspan=2, padx=18, pady=(0, 6), sticky="w")

        # Actions
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=10)

        self.create_btn = ctk.CTkButton(actions, text="Create account", width=240, command=self._submit)
        self.create_btn.pack(side="left", padx=(0, 12))

        self.back_btn = ctk.CTkButton(
            actions, text="Back to Login", fg_color="transparent",
            text_color=("black", "white"), hover=False,
            command=lambda: switch_page_callback("login")
        )
        self.back_btn.pack(side="left")

    def _toggle_password_visibility(self):
        show_char = "" if self.show_pw_var.get() else "*"
        self.password.configure(show=show_char)
        self.password2.configure(show=show_char)

    def _submit(self):
        # Minimal inline validation (extend as needed)
        name = self.fullname.get().strip()
        email = self.email.get().strip()
        uname = self.username.get().strip()
        pwd = self.password.get()
        pwd2 = self.password2.get()

        if not all([name, email, uname, pwd, pwd2]):
            self.feedback.configure(text="Please fill in all fields.")
            return
        if "@" not in email or "." not in email.split("@")[-1]:
            self.feedback.configure(text="Please enter a valid email address.")
            return
        if len(pwd) < 8:
            self.feedback.configure(text="Password must be at least 8 characters.")
            return
        if pwd != pwd2:
            self.feedback.configure(text="Passwords do not match.")
            return

        # TODO: replace this with your persistence (DB / API)
        # For now, just show a success message and clear fields
        self.feedback.configure(text="Account created! You can log in now.", text_color="green")
        self.password.delete(0, "end")
        self.password2.delete(0, "end")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.geometry("1500x900")
        self.title("CryptoScope")

        # Single container for pages
        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        # Build & stack pages once
        self.pages = {
            "login": LoginPage(self.container, self.show_page),
            "dashboard": DashboardPage(self.container, self.show_page),
            "register": RegisterPage(self.container, self.show_page),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")  # stacked

        self.show_page("login")

    def show_page(self, name):
        # Raise target frame; no layout thrash, minimal repaint
        self.pages[name].tkraise()
        # Optional: delay until idle to avoid mid-layout flicker
        # self.after_idle(self.pages[name].tkraise)


if __name__=="__main__":
    app = App()
    app.mainloop()
