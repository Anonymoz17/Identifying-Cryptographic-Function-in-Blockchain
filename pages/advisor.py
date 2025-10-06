# pages/advisor.py
import customtkinter as ctk
from core.kb import list_algorithms
from core.recommender import top_n, compare

class AdvisorPage(ctk.CTkFrame):
    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        ctk.CTkLabel(self, text="Advisor (beta)", font=("Roboto", 36)).pack(pady=(24, 8))
        ctk.CTkLabel(self, text="Compare algorithms without uploading code.", justify="center").pack(pady=(0, 16))

        # Top-3 recommendations
        self.top_box = ctk.CTkFrame(self, corner_radius=12)
        self.top_box.pack(fill="x", padx=24, pady=(0, 16))
        ctk.CTkLabel(self.top_box, text="Top recommendations", font=("Roboto", 16)).pack(pady=(12, 4))
        self.top_label = ctk.CTkLabel(self.top_box, text="")
        self.top_label.pack(padx=16, pady=(0, 12), anchor="w")

        # Compare controls
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=8)

        names = {a.id: a.name for a in list_algorithms()}
        self._id_by_name = {v: k for k, v in names.items()}
        values = list(names.values())

        ctk.CTkLabel(row, text="Compare:").grid(row=0, column=0, padx=(0, 8), pady=6, sticky="e")
        self.a_menu = ctk.CTkOptionMenu(row, values=values); self.a_menu.set(values[0])
        self.a_menu.grid(row=0, column=1, padx=4, pady=6)
        ctk.CTkLabel(row, text="vs").grid(row=0, column=2, padx=8, pady=6)
        self.b_menu = ctk.CTkOptionMenu(row, values=values); self.b_menu.set(values[1 if len(values)>1 else 0])
        self.b_menu.grid(row=0, column=3, padx=4, pady=6)

        self.compare_btn = ctk.CTkButton(self, text="Compare", command=self._do_compare)
        self.compare_btn.pack(pady=8)

        self.result = ctk.CTkLabel(self, text="", justify="left")
        self.result.pack(pady=(4, 16))

        ctk.CTkButton(self, text="Back to Dashboard",
                      command=lambda: self.switch_page("dashboard")).pack(pady=(4, 24))

        # initial render
        self._render_top3()

    def _render_top3(self):
        ranked = top_n(3)  # [(alg_id, score), ...]
        if not ranked:
            self.top_label.configure(text="No data.")
            return
        lines = []
        for i, (aid, score) in enumerate(ranked, start=1):
            name = self._name_of(aid)
            lines.append(f"{i}) {name} — {score:.1f}")
        self.top_label.configure(text="\n".join(lines))

    def _do_compare(self):
        a_name = self.a_menu.get()
        b_name = self.b_menu.get()
        a_id = self._id_by_name.get(a_name)
        b_id = self._id_by_name.get(b_name)
        if not a_id or not b_id or a_id == b_id:
            self.result.configure(text="Pick two different algorithms.")
            return
        table = compare(a_id, b_id)
        # Pretty print
        lines = [f"{a_name} vs {b_name}"]
        for k in ["security", "performance", "adoption", "compatibility", "risk"]:
            av, bv = table[k]
            metric = "risk (lower better)" if k == "risk" else k
            lines.append(f"• {metric}: {av}  vs  {bv}")
        self.result.configure(text="\n".join(lines))

    def _name_of(self, alg_id: str) -> str:
        # reverse lookup: id -> human name
        for a, b in self._id_by_name.items():
            if b == alg_id:
                return a
        return alg_id
