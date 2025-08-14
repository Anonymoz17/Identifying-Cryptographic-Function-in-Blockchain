# account_pages.py
import customtkinter as ctk
from auth import store

class AccountViewPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch = switch_page_callback

        ctk.CTkLabel(self, text="My Account", font=("Roboto", 64)).pack(pady=(40, 10))

        self.card = ctk.CTkFrame(self, corner_radius=16)
        self.card.pack(padx=40, pady=20, fill="x")

        self.name_lbl = ctk.CTkLabel(self.card, text="", font=("Roboto", 20))
        self.email_lbl = ctk.CTkLabel(self.card, text="", font=("Roboto", 20))
        self.user_lbl = ctk.CTkLabel(self.card, text="", font=("Roboto", 20))

        self.name_lbl.pack(anchor="w", padx=18, pady=(18, 4))
        self.email_lbl.pack(anchor="w", padx=18, pady=4)
        self.user_lbl.pack(anchor="w", padx=18, pady=(4, 18))

        # Actions
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=10)

        ctk.CTkButton(actions, text="Edit details", width=180,
                      command=lambda: self.switch("account_edit")).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions, text="Delete account", width=180,
                      fg_color="#d32f2f", hover_color="#b71c1c",
                      command=lambda: self.switch("account_delete")).pack(side="left", padx=10)
        ctk.CTkButton(actions, text="Back to Dashboard", width=180,
                      command=lambda: self.switch("dashboard")).pack(side="left", padx=(10, 0))

    def tkraise(self, aboveThis=None):
        # Refresh data each time the page is shown
        u = store.current_user()
        if u:
            self.name_lbl.configure(text=f"Full name: {u.full_name}")
            self.email_lbl.configure(text=f"Email: {u.email}")
            self.user_lbl.configure(text=f"Username: {u.username}")
        else:
            self.name_lbl.configure(text="Not logged in.")
            self.email_lbl.configure(text="")
            self.user_lbl.configure(text="")
        super().tkraise(aboveThis)


class AccountEditPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch = switch_page_callback

        ctk.CTkLabel(self, text="Edit Account", font=("Roboto", 64)).pack(pady=(40, 10))

        form = ctk.CTkFrame(self, corner_radius=16)
        form.pack(pady=20)

        for i in range(2):
            form.grid_columnconfigure(i, weight=1, pad=8)

        entry_width = 420
        pad_y = 10

        ctk.CTkLabel(form, text="Full name").grid(row=0, column=0, sticky="w", padx=18, pady=(18, 6))
        self.fullname = ctk.CTkEntry(form, width=entry_width)
        self.fullname.grid(row=1, column=0, columnspan=2, padx=18, pady=(0, pad_y))

        ctk.CTkLabel(form, text="Email").grid(row=2, column=0, sticky="w", padx=18, pady=(6, 6))
        self.email = ctk.CTkEntry(form, width=entry_width)
        self.email.grid(row=3, column=0, columnspan=2, padx=18, pady=(0, pad_y))

        ctk.CTkLabel(form, text="New password (optional)").grid(row=4, column=0, sticky="w", padx=18, pady=(6, 6))
        ctk.CTkLabel(form, text="Confirm new password").grid(row=4, column=1, sticky="w", padx=18, pady=(6, 6))

        self.password = ctk.CTkEntry(form, width=entry_width//2-10, show="*")
        self.password.grid(row=5, column=0, padx=(18, 9), pady=(0, pad_y), sticky="ew")

        self.password2 = ctk.CTkEntry(form, width=entry_width//2-10, show="*")
        self.password2.grid(row=5, column=1, padx=(9, 18), pady=(0, pad_y), sticky="ew")

        self.feedback = ctk.CTkLabel(form, text="", text_color="red")
        self.feedback.grid(row=6, column=0, columnspan=2, padx=18, pady=(0, 10), sticky="w")

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=10)

        ctk.CTkButton(actions, text="Save changes", width=200, command=self._save).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions, text="Cancel", width=200,
                      command=lambda: self.switch("account_view")).pack(side="left", padx=(10, 0))

    def tkraise(self, aboveThis=None):
        # Prefill with current user data
        u = store.current_user()
        if u:
            self.fullname.delete(0, "end"); self.fullname.insert(0, u.full_name)
            self.email.delete(0, "end"); self.email.insert(0, u.email)
            self.password.delete(0, "end")
            self.password2.delete(0, "end")
            self.feedback.configure(text="", text_color="red")
        else:
            self.fullname.delete(0, "end")
            self.email.delete(0, "end")
            self.feedback.configure(text="Not logged in.", text_color="red")
        super().tkraise(aboveThis)

    def _save(self):
        u = store.current_user()
        if not u:
            self.feedback.configure(text="Not logged in.")
            return

        name = self.fullname.get().strip()
        email = self.email.get().strip()
        pwd = self.password.get()
        pwd2 = self.password2.get()

        if not name or not email:
            self.feedback.configure(text="Name and Email are required.")
            return
        if "@" not in email or "." not in email.split("@")[-1]:
            self.feedback.configure(text="Please enter a valid email.")
            return
        if pwd or pwd2:
            if len(pwd) < 8:
                self.feedback.configure(text="New password must be at least 8 characters.")
                return
            if pwd != pwd2:
                self.feedback.configure(text="Passwords do not match.")
                return
            ok, msg = store.update_user(u.username, full_name=name, email=email, password=pwd)
        else:
            ok, msg = store.update_user(u.username, full_name=name, email=email)

        if ok:
            self.feedback.configure(text="Saved!", text_color="green")
        else:
            self.feedback.configure(text=msg, text_color="red")


class AccountDeletePage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch = switch_page_callback

        ctk.CTkLabel(self, text="Delete Account", font=("Roboto", 64)).pack(pady=(40, 10))

        warn = ctk.CTkLabel(
            self,
            text="This action is permanent. Type your username to confirm.",
            text_color="#d32f2f",
            font=("Roboto", 18),
            wraplength=900,
            justify="center"
        )
        warn.pack(pady=(10, 20))

        box = ctk.CTkFrame(self, corner_radius=16)
        box.pack(pady=10)

        ctk.CTkLabel(box, text="Username").grid(row=0, column=0, padx=18, pady=(18, 6), sticky="w")
        self.confirm_entry = ctk.CTkEntry(box, width=420)
        self.confirm_entry.grid(row=1, column=0, padx=18, pady=(0, 18))

        self.feedback = ctk.CTkLabel(self, text="", text_color="red")
        self.feedback.pack(pady=(8, 2))

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=10)

        ctk.CTkButton(actions, text="Delete my account", width=220,
                      fg_color="#d32f2f", hover_color="#b71c1c",
                      command=self._delete).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions, text="Cancel", width=180,
                      command=lambda: self.switch("account_view")).pack(side="left", padx=(10, 0))

    def tkraise(self, aboveThis=None):
        self.confirm_entry.delete(0, "end")
        self.feedback.configure(text="", text_color="red")
        super().tkraise(aboveThis)

    def _delete(self):
        u = store.current_user()
        if not u:
            self.feedback.configure(text="Not logged in.")
            return

        if self.confirm_entry.get().strip() != u.username:
            self.feedback.configure(text="Username does not match.")
            return

        ok, msg = store.delete_user(u.username)
        if ok:
            self.feedback.configure(text="Account deleted.", text_color="green")
            # Return to login page
            self.switch("login")
        else:
            self.feedback.configure(text=msg, text_color="red")
