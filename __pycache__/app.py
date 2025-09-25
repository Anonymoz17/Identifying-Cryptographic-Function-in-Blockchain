# app.py  (only the logout() changed from your current file)
import customtkinter as ctk
from file_handler import FileHandler
from pages import LoginPage, RegisterPage, DashboardPage, AnalysisPage

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CryptoScope")
        self.geometry("1200x800")
        self.minsize(900, 600)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.auth_token = None
        self.current_user_role = "free"
        self.current_user_email = None

        self.file_handler = FileHandler(upload_dir="./uploads")

        self._pages = {
            "login":      LoginPage(self, self.switch_page),
            "register":   RegisterPage(self, self.switch_page),
            "dashboard":  DashboardPage(self, self.switch_page, self.file_handler),
            "analysis":   AnalysisPage(self, self.switch_page),
        }
        for p in self._pages.values():
            p.grid(row=0, column=0, sticky="nsew")
            p.grid_remove()

        self.switch_page("login")
        self.bind("<Configure>", self._on_configure)

    def switch_page(self, name: str):
        for n, page in self._pages.items():
            if n == name:
                page.grid()
                if hasattr(page, "on_enter"):
                    page.on_enter()
            else:
                page.grid_remove()

    def logout(self):
        # Clear auth
        self.auth_token = None
        self.current_user_role = "free"
        self.current_user_email = None

        # Reset per-page UI
        if hasattr(self._pages["dashboard"], "reset_ui"):
            self._pages["dashboard"].reset_ui()
        if hasattr(self._pages["analysis"], "reset_ui"):
            self._pages["analysis"].reset_ui()
        if hasattr(self._pages["login"], "reset_ui"):
            self._pages["login"].reset_ui()

        # Show login page, then explicitly remove focus from inputs
        self.switch_page("login")
        # Defer a tick so the page is visible, then sink focus
        self.after(10, lambda: getattr(self._pages["login"], "blur_inputs", lambda: None)())

    def _on_configure(self, event):
        w, h = self.winfo_width(), self.winfo_height()
        for p in self._pages.values():
            if hasattr(p, "on_resize"):
                p.on_resize(w, h)

if __name__ == "__main__":
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("green")
    App().mainloop()
