# pages/advisor.py
import customtkinter as ctk

ALGORITHMS = ["SHA-256", "SHA3/Keccak", "BLAKE3", "RIPEMD-160", "MD5 (deprecated)"]

class AdvisorPage(ctk.CTkFrame):
    """
    Minimal 'Advisor (beta)' page.
    - No backend yet; just a placeholder UI so you can demo the pivot.
    - Uses hardcoded options; safe to keep alongside existing flows.
    """
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        # Title
        ctk.CTkLabel(self, text="Advisor (beta)", font=("Roboto", 36)).pack(pady=(24, 8))

        # Subtitle
        ctk.CTkLabel(
            self,
            text="Compare algorithms without uploading code.\n(Temporary demo UI)",
            justify="center"
        ).pack(pady=(0, 16))

        # Top-3 placeholder
        box = ctk.CTkFrame(self, corner_radius=12)
        box.pack(fill="x", padx=24, pady=(0, 16))
        ctk.CTkLabel(box, text="Suggested Top 3 (static demo)", font=("Roboto", 16)).pack(pady=(12, 4))
        ctk.CTkLabel(
            box,
            text="1) SHA-256\n2) SHA3/Keccak\n3) BLAKE3",
            justify="left"
        ).pack(padx=16, pady=(0, 12), anchor="w")

        # Simple compare controls
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=8)

        ctk.CTkLabel(row, text="Compare:").grid(row=0, column=0, padx=(0, 8), pady=6, sticky="e")
        self.a = ctk.CTkOptionMenu(row, values=ALGORITHMS)
        self.a.set("SHA-256")
        self.a.grid(row=0, column=1, padx=4, pady=6)
        ctk.CTkLabel(row, text="vs").grid(row=0, column=2, padx=8, pady=6)
        self.b = ctk.CTkOptionMenu(row, values=ALGORITHMS)
        self.b.set("BLAKE3")
        self.b.grid(row=0, column=3, padx=4, pady=6)

        self.result = ctk.CTkLabel(self, text="")
        self.result.pack(pady=(8, 0))

        ctk.CTkButton(
            self,
            text="Compare (demo)",
            command=self._compare_demo
        ).pack(pady=12)

        # Back button
        ctk.CTkButton(
            self,
            text="Back to Dashboard",
            fg_color="#444444",
            hover_color="#333333",
            command=lambda: self.switch_page("dashboard")
        ).pack(pady=(4, 24))

    def _compare_demo(self):
        a = self.a.get()
        b = self.b.get()
        msg = f"Demo comparison:\n- {a}: strong, widely adopted\n- {b}: fast, modern\n(Scoring engine coming next)"
        self.result.configure(text=msg)
