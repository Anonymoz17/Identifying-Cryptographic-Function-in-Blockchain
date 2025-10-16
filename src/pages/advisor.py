import customtkinter as ctk

from core.kb import list_algorithms
from core.recommender import compare, top_n
from roles import is_premium
from ui.card import Card
from ui.grid import grid_evenly


class AdvisorPage(ctk.CTkFrame):
    """
    Advisor (beta)
    - Top-3 recommendations (from in-memory KB)
    - A vs B compare (disabled until distinct selections)
    - Tiny legend: "risk: lower is better"
    - Responsive: title/subtitle/button buckets only (no forced heights to avoid flicker)
    """

    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        # ---- Layout base ----
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        # ---- Title + subtitle ----
        self.title = ctk.CTkLabel(content, text="Advisor (beta)", font=("Roboto", 36))
        self.title.pack(pady=(20, 4))

        self.subtitle = ctk.CTkLabel(
            content,
            text="Compare cryptographic algorithms without uploading code.",
            justify="center",
        )
        self.subtitle.pack(pady=(0, 12))

        # ---- Top-3 card ----
        self.top_card = ctk.CTkFrame(
            content,
            corner_radius=14,
            border_width=1,
            border_color="#cdd5e0",
            fg_color=("#f7f9fc", "#121212"),
        )
        self.top_card.pack(fill="x", padx=24, pady=(0, 14))
        # let pack decide; don't force heights
        self.top_card.pack_propagate(True)

        ctk.CTkLabel(
            self.top_card, text="Top recommendations", font=("Roboto", 16, "bold")
        ).pack(anchor="w", padx=14, pady=(12, 6))
        self.top_label = ctk.CTkLabel(self.top_card, text="", justify="left")
        self.top_label.pack(anchor="w", padx=14, pady=(0, 12))

        # ---- Compare controls card ----
        self.compare_card = ctk.CTkFrame(
            content,
            corner_radius=14,
            border_width=1,
            border_color="#cdd5e0",
            fg_color=("#f5f7fb", "#1a1a1a"),
        )
        self.compare_card.pack(fill="x", padx=24, pady=(0, 12))
        self.compare_card.pack_propagate(True)

        row = ctk.CTkFrame(self.compare_card, fg_color="transparent")
        row.pack(padx=14, pady=(14, 8))

        names = {a.id: a.name for a in list_algorithms()}
        self._id_by_name = {v: k for k, v in names.items()}
        values = list(names.values()) or ["(no data)"]

        ctk.CTkLabel(row, text="Compare:").grid(
            row=0, column=0, padx=(0, 8), pady=6, sticky="e"
        )

        self.a_menu = ctk.CTkOptionMenu(
            row, values=values, command=lambda _: self._check_compare_state()
        )
        self.a_menu.set(values[0])
        self.a_menu.grid(row=0, column=1, padx=4, pady=6)

        ctk.CTkLabel(row, text="vs").grid(row=0, column=2, padx=8, pady=6)

        self.b_menu = ctk.CTkOptionMenu(
            row, values=values, command=lambda _: self._check_compare_state()
        )
        self.b_menu.set(values[1 if len(values) > 1 else 0])
        self.b_menu.grid(row=0, column=3, padx=4, pady=6)

        # Compare + legend
        controls = ctk.CTkFrame(self.compare_card, fg_color="transparent")
        controls.pack(fill="x", padx=14, pady=(0, 14))
        controls.grid_columnconfigure(0, weight=0)
        controls.grid_columnconfigure(1, weight=1)

        self.legend = ctk.CTkLabel(
            controls, text="risk: lower is better", text_color="#6b7280"
        )
        self.legend.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self.compare_btn = ctk.CTkButton(
            controls, text="Compare", command=self._do_compare, state="disabled"
        )
        self.compare_btn.grid(row=0, column=1, sticky="e")

        # ---- Result card ----
        self.result_card = ctk.CTkFrame(
            content,
            corner_radius=14,
            border_width=1,
            border_color="#cdd5e0",
            fg_color=("#ffffff", "#0f0f0f"),
        )
        self.result_card.pack(fill="x", padx=24, pady=(0, 16))
        self.result_card.pack_propagate(True)

        ctk.CTkLabel(self.result_card, text="Result", font=("Roboto", 16, "bold")).pack(
            anchor="w", padx=14, pady=(12, 6)
        )
        self.result = ctk.CTkLabel(self.result_card, text="", justify="left")
        self.result.pack(anchor="w", padx=14, pady=(0, 14))

        # ---- Bottom bar ----
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=1, column=0, sticky="ew", padx=24, pady=(4, 12))
        bottom.grid_columnconfigure(0, weight=0)
        bottom.grid_columnconfigure(1, weight=1)
        bottom.grid_columnconfigure(2, weight=0)

        self.back_btn = ctk.CTkButton(
            bottom,
            text="Back to Dashboard",
            command=lambda: self.switch_page("dashboard"),
        )
        self.back_btn.grid(row=0, column=0, sticky="w")

        self.cards_wrap = ctk.CTkFrame(self, fg_color="transparent")

        # append at the next row in the existing grid:
        next_row = self.grid_size()[1]  # number of rows currently used
        self.cards_wrap.grid(row=next_row, column=0, sticky="ew", padx=24, pady=12)
        self.grid_columnconfigure(0, weight=1)  # make page root column stretch
        self.cards_wrap.grid_columnconfigure(0, weight=1)

        self.cards_frame = ctk.CTkFrame(self.cards_wrap, fg_color="transparent")
        self.cards_frame.grid(row=0, column=0, sticky="ew")

        # Cards (always present -> layout never shifts)
        self.card_weights = Card(
            self.cards_frame,
            title="Adjust Weights",
            subtitle="Tune security/performance/adoption/risk/compatibility",
            command=self._open_weights_dialog,
        )

        self.card_top3 = Card(
            self.cards_frame,
            title="Top-3 Recommendations",
            subtitle="Best fits for your selected use case",
            command=self._show_top3,
        )

        self._cards = [self.card_weights, self.card_top3]

        # First layout + apply current role
        self._layout_cards()
        self.apply_role(
            self.master.get_role() if hasattr(self.master, "get_role") else None
        )

        # after you finish creating UI and the Card widgets:
        if hasattr(self.master, "get_role"):
            self.apply_role(self.master.get_role())
        else:
            self.apply_role(getattr(self.master, "current_user_role", None))

        # Make it responsive
        self.bind("<Configure>", lambda e: self._layout_cards())
        # ---- State / sizing guards ----
        self._last_title_px = None
        self._last_sub_px = None
        self._last_btn_w = None
        self._last_btn_h = None

        # initial render
        self._render_top3()
        self._check_compare_state()

    # ---------- Helpers ----------
    def _render_top3(self):
        ranked = top_n(3)
        if not ranked:
            self.top_label.configure(text="No data available.")
            return
        lines = []
        for i, (aid, score) in enumerate(ranked, start=1):
            name = self._name_of(aid)
            lines.append(f"{i}) {name} — {score:.1f}")
        self.top_label.configure(text="\n".join(lines))

    def _check_compare_state(self):
        a_name = self.a_menu.get()
        b_name = self.b_menu.get()
        distinct = a_name != b_name
        enable = (
            distinct and (a_name in self._id_by_name) and (b_name in self._id_by_name)
        )
        self.compare_btn.configure(state=("normal" if enable else "disabled"))

    def _do_compare(self):
        a_name = self.a_menu.get()
        b_name = self.b_menu.get()
        a_id = self._id_by_name.get(a_name)
        b_id = self._id_by_name.get(b_name)
        if not a_id or not b_id or a_id == b_id:
            self.result.configure(text="Pick two different algorithms.")
            return
        table = compare(a_id, b_id)
        lines = [f"{a_name} vs {b_name}"]
        for k in ["security", "performance", "adoption", "compatibility", "risk"]:
            av, bv = table[k]
            metric = "risk (lower better)" if k == "risk" else k
            lines.append(f"• {metric}: {av}  vs  {bv}")
        self.result.configure(text="\n".join(lines))

    def _name_of(self, alg_id: str) -> str:
        for human, _id in self._id_by_name.items():
            if _id == alg_id:
                return human
        return alg_id

    # ---------- Responsive layout (no forced heights) ----------
    def on_resize(self, w, h):
        if not self.winfo_exists():
            return

        # Title font
        title_px = max(28, min(84, int(36 * (h / 900.0))))
        if title_px != self._last_title_px:
            self._last_title_px = title_px
            try:
                self.title.configure(font=("Roboto", title_px))
            except Exception:
                pass

        # Subtitle font
        sub_px = max(12, min(18, int(14 * (h / 900.0))))
        if sub_px != self._last_sub_px:
            self._last_sub_px = sub_px
            try:
                self.subtitle.configure(font=("Roboto", sub_px))
            except Exception:
                pass

        # Button buckets (reuse Dashboard feel)
        btn_w = max(120, min(220, int(w * 0.12)))
        btn_h = max(36, min(56, int(h * 0.05)))
        if (btn_w, btn_h) != (self._last_btn_w, self._last_btn_h):
            self._last_btn_w, self._last_btn_h = btn_w, btn_h
            for b in (self.compare_btn, self.back_btn):
                try:
                    b.configure(width=btn_w, height=btn_h)
                except Exception:
                    pass

    def apply_role(self, role: str | None):
        premium = is_premium(role)
        self.card_weights.set_locked(not premium, "🔒 Premium feature")
        # If you want Top-3 to be Premium-only, lock it too; otherwise leave unlocked.
        # self.card_top3.set_locked(not premium, "🔒 Premium feature")

    def _layout_cards(self):
        w = max(self.winfo_width(), 1)
        cols = 1 if w < 640 else 2
        grid_evenly(self.cards_frame, self._cards, num_cols=cols)

    def _open_weights_dialog(self):
        # TODO: show a small slider dialog to adjust weights (Premium)
        pass

    def _show_top3(self):
        # TODO: call your recommender.top_n() + kb filters; render in a popup or side panel
        pass
