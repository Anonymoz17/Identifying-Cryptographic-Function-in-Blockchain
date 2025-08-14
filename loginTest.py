# app.py
import customtkinter as ctk
from auth import store
from account_pages import AccountViewPage, AccountEditPage, AccountDeletePage

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("green")

class LoginPage(ctk.CTkFrame):
    def __init__ (self, master, switch_page_callback):
        super().__init__(master)
        self.switch = switch_page_callback

        self.label = ctk.CTkLabel(self, text='Login', font=("Roboto", 80))
        self.label.pack(pady=100, padx=10)

        self.user = ctk.CTkEntry(self, placeholder_text="Username", width=500, height=50)
        self.user.pack(pady=20, padx=10)

        self.pw = ctk.CTkEntry(self, placeholder_text="Password", width=500, height=50, show="*")
        self.pw.pack(pady=20, padx=12)

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=10)
        self.login = ctk.CTkButton(row, text="Login", font=('Roboto', 16), command=self._do_login)
        self.login.pack(side="left", padx=(0, 16))

        self.register_link = ctk.CTkButton(
            row, text="Create an account", fg_color="transparent",
            text_color=("black", "white"), hover=False,
            command=lambda: self.switch("register")
        )
        self.register_link.pack(side="left")

        self.feedback = ctk.CTkLabel(self, text="", text_color="red")
        self.feedback.pack(pady=(6,0))

    def _do_login(self):
        ok, msg = store.login(self.user.get().strip(), self.pw.get())
        if ok:
            self.feedback.configure(text="")
            self.switch("dashboard")
        else:
            self.feedback.configure(text=msg)


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch = switch_page_callback

        self.label = ctk.CTkLabel(self, text="Dashboard", font=("Roboto", 80))
        self.label.pack(pady=20)

        # Drag & Drop target (placeholder)
        self.dnd = ctk.CTkFrame(
            self,
            width=900, height=600,
            corner_radius=16,
            border_width=2,
            border_color="#9aa0a6",
            fg_color=("white", "#000000")
        )
        self.dnd.pack(padx=40, pady=20)
        self.dnd.pack_propagate(False)

        dz_label = ctk.CTkLabel(
            self.dnd, text="Drag & Drop files here", font=("Roboto", 28), justify="center"
        )
        dz_label.place(relx=0.5, rely=0.5, anchor="center")

        # Account actions row
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=8)

        ctk.CTkButton(actions, text="My Account", width=160,
                      command=lambda: self.switch("account_view")).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Edit Account", width=160,
                      command=lambda: self.switch("account_edit")).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Delete Account", width=160,
                      fg_color="#d32f2f", hover_color="#b71c1c",
                      command=lambda: self.switch("account_delete")).pack(side="left", padx=8)

        self.logout_button = ctk.CTkButton(self, text="Logout", command=self._logout)
        self.logout_button.pack(pady=10)

        self.who = ctk.CTkLabel(self, text="", font=("Roboto", 16))
        self.who.pack(pady=(0, 10))

    def tkraise(self, aboveThis=None):
        # Show who is logged in
        u = store.current_user()
        self.who.configure(text=f"Logged in as: {u.username}" if u else "Not logged in")
        super().tkraise(aboveThis)

    def _logout(self):
        store.logout()
        self.switch("login")


class RegisterPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch = switch_page_callback

        self.title = ctk.CTkLabel(self, text="Create Account", font=("Roboto", 64))
        self.title.pack(pady=(60, 10))

        form = ctk.CTkFrame(self, corner_radius=16)
        form.pack(pady=20)

        for i in range(2):
            form.grid_columnconfigure(i, weight=1, pad=8)

        entry_width = 420
        pad_y = 10

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

        self.password = ctk.CTkEntry(form, placeholder_text="At least 8 characters", width=entry_width//2-10, show="*")
        self.password.grid(row=7, column=0, padx=(18, 9), pady=(0, pad_y), sticky="ew")

        self.password2 = ctk.CTkEntry(form, placeholder_text="Re-enter password", width=entry_width//2-10, show="*")
        self.password2.grid(row=7, column=1, padx=(9, 18), pady=(0, pad_y), sticky="ew")

        self.show_pw_var = ctk.BooleanVar(value=False)
        self.show_pw = ctk.CTkCheckBox(
            form, text="Show passwords", variable=self.show_pw_var, command=self._toggle_password_visibility
        )
        self.show_pw.grid(row=8, column=0, columnspan=2, padx=18, pady=(0, 10), sticky="w")

        self.feedback = ctk.CTkLabel(form, text="", text_color="red")
        self.feedback.grid(row=9, column=0, columnspan=2, padx=18, pady=(0, 6), sticky="w")

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=10)

        self.create_btn = ctk.CTkButton(actions, text="Create account", width=240, command=self._submit)
        self.create_btn.pack(side="left", padx=(0, 12))

        self.back_btn = ctk.CTkButton(
            actions, text="Back to Login", fg_color="transparent",
            text_color=("black", "white"), hover=False,
            command=lambda: self.switch("login")
        )
        self.back_btn.pack(side="left")

    def _toggle_password_visibility(self):
        show_char = "" if self.show_pw_var.get() else "*"
        self.password.configure(show=show_char)
        self.password2.configure(show=show_char)

    def _submit(self):
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

        ok, msg = store.create_user(name, email, uname, pwd)
        if ok:
            self.feedback.configure(text="Account created! You can log in now.", text_color="green")
            self.password.delete(0, "end"); self.password2.delete(0, "end")
        else:
            self.feedback.configure(text=msg, text_color="red")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("1500x900")
        self.title("CryptoScope")

        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.pages = {
            "login": LoginPage(self.container, self.show_page),
            "dashboard": DashboardPage(self.container, self.show_page),
            "register": RegisterPage(self.container, self.show_page),

            # NEW account pages
            "account_view": AccountViewPage(self.container, self.show_page),
            "account_edit": AccountEditPage(self.container, self.show_page),
            "account_delete": AccountDeletePage(self.container, self.show_page),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

        self.show_page("login")

    def show_page(self, name):
        self.pages[name].tkraise()

if __name__=="__main__":
    app = App()
    app.mainloop()
