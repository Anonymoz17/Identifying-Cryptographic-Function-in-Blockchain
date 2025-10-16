import customtkinter as ctk

# same colors as your login/register/dashboard
BG = "#0B0F1A"
CARD_BG = "#111827"
BORDER = "#1F2937"
TEXT = "#E5E7EB"
MUTED = "#9CA3AF"
PRIMARY = "#22C55E"
PRIMARY_H = "#16A34A"


def _build_scroll_column(parent, *, width=960, bg=BG):
    parent.configure(fg_color=bg)
    viewport = ctk.CTkScrollableFrame(parent, fg_color="transparent")
    viewport.pack(fill="both", expand=True)
    column = ctk.CTkFrame(viewport, fg_color="transparent", width=width)
    column.pack(padx=24, pady=16)
    column.pack_propagate(False)
    return viewport, column


class ReportsPage(ctk.CTkFrame):
    def __init__(self, master, switch_page, get_role, export_json_cb, export_pdf_cb):
        super().__init__(master)
        self.switch_page = switch_page
        self.get_role = get_role
        self.export_json_cb = export_json_cb
        self.export_pdf_cb = export_pdf_cb

        _, root = _build_scroll_column(self, width=960)

        # Header
        head = ctk.CTkFrame(root, fg_color="transparent")
        head.pack(fill="x", padx=22, pady=(16, 6))
        ctk.CTkLabel(
            head, text="Reports", font=("Segoe UI", 28, "bold"), text_color=TEXT
        ).pack(anchor="w")
        ctk.CTkLabel(
            head,
            text="Export machine-readable or presentation-ready files.",
            font=("Segoe UI", 12),
            text_color=MUTED,
        ).pack(anchor="w", pady=(2, 0))

        # Cards row
        row = ctk.CTkFrame(root, fg_color="transparent")
        row.pack(fill="x", padx=22, pady=(8, 16))

        card_json = ctk.CTkFrame(
            row, corner_radius=16, border_width=1, border_color=BORDER, fg_color=CARD_BG
        )
        card_pdf = ctk.CTkFrame(
            row, corner_radius=16, border_width=1, border_color=BORDER, fg_color=CARD_BG
        )
        card_json.pack(side="left", fill="both", expand=True, padx=(0, 8))
        card_pdf.pack(side="left", fill="both", expand=True, padx=(8, 0))

        # JSON card
        ctk.CTkLabel(
            card_json,
            text="Export JSON",
            font=("Segoe UI", 16, "bold"),
            text_color=TEXT,
        ).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            card_json, text="For pipelines and integrations.", text_color=MUTED
        ).pack(anchor="w", padx=16)
        ctk.CTkButton(
            card_json,
            text="Export",
            fg_color=PRIMARY,
            hover_color=PRIMARY_H,
            text_color="#041007",
            command=self.export_json_cb,
        ).pack(anchor="w", padx=16, pady=(10, 14))

        # PDF card
        ctk.CTkLabel(
            card_pdf, text="Export PDF", font=("Segoe UI", 16, "bold"), text_color=TEXT
        ).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(card_pdf, text="Polished, ready to share.", text_color=MUTED).pack(
            anchor="w", padx=16
        )
        ctk.CTkButton(card_pdf, text="Export", command=self.export_pdf_cb).pack(
            anchor="w", padx=16, pady=(10, 14)
        )

        # Status + Back
        self.status = ctk.CTkLabel(
            root, text="", font=("Segoe UI", 11), text_color=TEXT
        )
        self.status.pack(anchor="w", padx=22, pady=(0, 10))

        ctk.CTkButton(
            root,
            text="Back to Dashboard",
            command=lambda: self.switch_page("dashboard"),
        ).pack(anchor="w", padx=22, pady=(0, 20))

    # keep compatibility if other code calls this
    def set_status(self, msg: str, error: bool = False):
        self.status.configure(text=msg, text_color=("red" if error else TEXT))

    def on_resize(self, w, h):
        pass
