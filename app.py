# app.py
import customtkinter as ctk
from file_handler import FileHandler
from pages import LoginPage, RegisterPage, DashboardPage, AnalysisPage, AdvisorPage

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CryptoScope")
        self.geometry("1200x800")
        self.minsize(900, 600)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.auth_token = None
        self.current_user_role = "premium"
        self.current_user_email = None

        self.file_handler = FileHandler(upload_dir="./uploads")

        # Instantiate all pages as frames (no lambdas/factories)
        self._pages = {
            "login":     LoginPage(self, self.switch_page),
            "register":  RegisterPage(self, self.switch_page),
            "dashboard": DashboardPage(self, self.switch_page, self.file_handler),
            "analysis":  AnalysisPage(self, self.switch_page),
            "advisor":   AdvisorPage(self, self.switch_page),  # <-- fixed: real frame instance
        }

        for p in self._pages.values():
            p.grid(row=0, column=0, sticky="nsew")
            p.grid_remove()

        # track which page is visible (for targeted resize)
        self._current_page_name = "dashboard"
        self.switch_page(self._current_page_name)

        # ---- Debounced resize handling ----
        self._resize_job = None
        self.bind("<Configure>", self._on_configure)

        # ---- Clean shutdown: stop timers before widgets die ----
        self._closing = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def get_role(self):
        return self.current_user_role
    
    def set_role(self, role: str):
        self.current_user_role = role
        # Update current page if it supports role application
        cur = getattr(self, "_current_page_name", None)
        if cur:
            page = self._pages.get(cur)
            if page and hasattr(page, "apply_role"):
                page.apply_role(role)


    def switch_page(self, name: str):
        self._current_page_name = name
        for n, page in self._pages.items():
            if n == name:
                page.grid()
                if hasattr(page, "on_enter"):
                    page.on_enter()
            else:
                page.grid_remove()

    def logout(self):
        self.auth_token = None
        self.current_user_role = "free"
        self.current_user_email = None

        if hasattr(self._pages["dashboard"], "reset_ui"):
            self._pages["dashboard"].reset_ui()
        if hasattr(self._pages["analysis"], "reset_ui"):
            self._pages["analysis"].reset_ui()
        if hasattr(self._pages["login"], "reset_ui"):
            self._pages["login"].reset_ui()

        self.switch_page("login")
        # blur inputs so caret doesn't appear automatically
        self.after(10, lambda: getattr(self._pages["login"], "blur_inputs", lambda: None)())

    # ---------- Resize (debounced) ----------
    def _on_configure(self, event):
        # Ignore noisy events triggered during closing
        if self._closing:
            return
        # Debounce: schedule a single resize after 30ms
        if self._resize_job is not None:
            try:
                self.after_cancel(self._resize_job)
            except Exception:
                pass
        self._resize_job = self.after(30, self._do_resize)

    def _do_resize(self):
        self._resize_job = None
        if self._closing:
            return
        page = self._pages.get(self._current_page_name)
        # page may already be destroyed during shutdown
        try:
            if page is not None and page.winfo_exists() and hasattr(page, "on_resize"):
                w, h = self.winfo_width(), self.winfo_height()
                page.on_resize(w, h)
        except Exception:
            # swallow resize errors during teardown
            pass

    def _on_close(self):
        # prevent any further scheduled work
        self._closing = True
        if self._resize_job is not None:
            try:
                self.after_cancel(self._resize_job)
            except Exception:
                pass
            self._resize_job = None
        self.destroy()

if __name__ == "__main__":
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("green")
    App().mainloop()
