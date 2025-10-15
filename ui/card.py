# ui/card.py  (replace your current Card with this)
import customtkinter as ctk


class Card(ctk.CTkFrame):
    def __init__(
        self, master, title, subtitle="", locked=False, command=None, min_h=140
    ):
        super().__init__(master, corner_radius=16, border_width=1)
        self._command = command
        self._locked = bool(locked)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        body = ctk.CTkFrame(self, fg_color="transparent", height=min_h)
        body.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        body.grid_propagate(False)

        # Title
        self.title_lbl = ctk.CTkLabel(body, text=title, font=("Roboto", 18, "bold"))
        self.title_lbl.pack(anchor="w")
        self._default_title_color = self.title_lbl.cget("text_color") or (
            "#000000",
            "#FFFFFF",
        )

        # Subtitle (optional)
        self.sub_lbl = None
        self._default_sub_color = None
        if subtitle:
            self.sub_lbl = ctk.CTkLabel(body, text=subtitle, font=("Roboto", 13))
            self.sub_lbl.pack(anchor="w", pady=(6, 0))
            self._default_sub_color = self.sub_lbl.cget("text_color") or (
                "#333333",
                "#CCCCCC",
            )

        # Action button
        self.btn = ctk.CTkButton(body, text="Open", command=self._on_click, height=32)
        self.btn.pack(anchor="w", pady=(10, 0))

        # Lock overlay
        self.overlay = ctk.CTkFrame(
            self, corner_radius=16, fg_color=("gray92", "gray20")
        )
        self.lock_lbl = ctk.CTkLabel(
            self.overlay, text="🔒 Premium feature", font=("Roboto", 14, "bold")
        )

        self.set_locked(self._locked)

    def _on_click(self):
        if not self._locked and callable(self._command):
            self._command()

    def set_locked(self, locked: bool, message: str = "🔒 Premium feature"):
        self._locked = bool(locked)
        if self._locked:
            self.overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.lock_lbl.configure(text=message)
            self.lock_lbl.place(relx=0.5, rely=0.5, anchor="center")
            self.btn.configure(state="disabled")
            self.title_lbl.configure(text_color=("gray40", "gray60"))
            if self.sub_lbl:
                self.sub_lbl.configure(text_color=("gray45", "gray55"))
        else:
            self.overlay.place_forget()
            self.btn.configure(state="normal")
            self.title_lbl.configure(text_color=self._default_title_color)
            if self.sub_lbl:
                self.sub_lbl.configure(text_color=self._default_sub_color)
