# pages/analysis.py
import customtkinter as ctk

class AnalysisPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        ctk.CTkLabel(self, text="Analysis", font=("Roboto", 80)).pack(pady=(24, 8))

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=32, pady=(0, 0))

        self.box = ctk.CTkFrame(
            content, width=1100, height=520, corner_radius=16,
            border_width=2, border_color="#9aa0a6", fg_color=("white", "#000000")
        )
        self.box.place(relx=0.5, rely=0.5, anchor="center")
        self.box.pack_propagate(False)

        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=24, pady=(6, 10))
        bottom.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(bottom, text="Back to Dashboard", width=160, height=40,
                      command=lambda: self.switch_page("dashboard")).grid(row=0, column=1, sticky="e")

    def reset_ui(self):
        pass

    def on_resize(self, w, h):
        # keep the big box centered and reasonable size if you want dynamic sizing later
        pass
