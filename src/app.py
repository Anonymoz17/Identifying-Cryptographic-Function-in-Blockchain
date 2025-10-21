"""Top-level app runner moved under src for packaging."""

from pathlib import Path

import customtkinter as ctk

from file_handler import FileHandler
from pages import (
    AdvisorPage,
    AnalysisPage,
    AuditorPage,
    DashboardPage,
    LoginPage,
    RegisterPage,
    LandingPage
)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CryptoScope")
        self.geometry("1200x800")
        self.minsize(900, 600)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- Session + scan state ---
        self.auth_token = None
        # safer default for local usage
        self.current_user_role = "free"
        self.current_user_email = None
        self.current_scan_meta = None

        # Use pathlib.Path for cross-platform paths
        uploads_dir = Path(".") / "uploads"
        self.file_handler = FileHandler(upload_dir=uploads_dir)

        # --- Instantiate pages ---
        self._pages = {
            "login": LoginPage(self, self.switch_page),
            "register": RegisterPage(self, self.switch_page),
            "dashboard": DashboardPage(self, self.switch_page, self.file_handler),
            "analysis": AnalysisPage(self, self.switch_page),
            "landing":    LandingPage(self, self.switch_page),   # ← NEW
            "advisor": AdvisorPage(
                self, self.switch_page
            ),  # <-- fixed: real frame instance
            "auditor": AuditorPage(self, self.switch_page),
        }

        for p in self._pages.values():
            p.grid(row=0, column=0, sticky="nsew")
            p.grid_remove()

        # --- Start on Login (not dashboard) ---
        self._current_page_name = "landing"
        self.switch_page(self._current_page_name)

        # Debounced resize handling
        self._resize_job = None
        self.bind("<Configure>", self._on_configure)

        # Clean shutdown
        self._closing = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -------- Navigation --------
    def switch_page(self, name: str):
        self._current_page_name = name
        for n, page in self._pages.items():
            if n == name:
                page.grid()
                if hasattr(page, "on_enter"):
                    try:
                        page.on_enter()
                    except Exception:
                        pass
            else:
                page.grid_remove()

    # -------- Logout (clear state, reset pages, go to login) --------
    def logout(self):
        self.auth_token = None
        self.current_user_role = "free"
        self.current_user_email = None
        self.current_scan_meta = None

        # Let pages clear their UI if they implement reset_ui()
        for key in ("dashboard", "analysis", "login"):
            page = self._pages.get(key)
            if page and hasattr(page, "reset_ui"):
                try:
                    page.reset_ui()
                except Exception:
                    pass

        self.switch_page("login")
        # blur inputs so caret doesn't appear automatically; pass callable to after
        blur_cb = getattr(self._pages["login"], "blur_inputs", lambda: None)
        # pass the callable directly to tkinter.after (no args)
        self.after(10, blur_cb)

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
        # schedule resize using a callable reference
        self._resize_job = self.after(30, self._do_resize)

    def _do_resize(self):
        self._resize_job = None
        if self._closing:
            return
        page = self._pages.get(self._current_page_name)
        try:
            if page is not None and page.winfo_exists() and hasattr(page, "on_resize"):
                w, h = self.winfo_width(), self.winfo_height()
                page.on_resize(w, h)
        except Exception:
            pass

    def _on_close(self):
        self._closing = True
        if self._resize_job is not None:
            try:
                self.after_cancel(self._resize_job)
            except Exception:
                pass
            self._resize_job = None
        self.destroy()


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    App().mainloop()
