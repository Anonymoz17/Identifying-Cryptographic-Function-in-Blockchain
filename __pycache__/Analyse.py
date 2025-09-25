import customtkinter as ctk

class Analyse(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)

        # (Optional) page title – comment out if you truly want "empty"
        # title = ctk.CTkLabel(self, text="Analyse", font=("Roboto", 64))
        # title.pack(anchor="w", padx=32, pady=(24, 0))

        # A transparent filler that lets us right-align the box nicely
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=32, pady=24)

        # Right-side box
        box = ctk.CTkFrame(
            content,
            width=420, height=240,
            corner_radius=16,
            border_width=2,
            border_color="#9aa0a6",
            fg_color=("white", "#000000")
        )
        box.place(relx=0.5, rely=0.5, anchor="center")
        box.pack_propagate(False)

        ctk.CTkLabel(box, text="Analyzing…", font=("Roboto", 28)).place(relx=0.5, rely=0.5, anchor="center")

        # Tiny back button so you can return
        back = ctk.CTkButton(self, text="Back to Dashboard", width=180,
                             command=lambda: switch_page_callback("dashboard"))
        back.pack(anchor="w", padx=32, pady=(0, 24))
