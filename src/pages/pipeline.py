from __future__ import annotations

import customtkinter as ctk


class PipelinePage(ctk.CTkFrame):
    """Lightweight pipeline overview page.

    Purpose: document the recommended flow and provide quick actions to
    start Engagement (preproc) and run Detectors. This is a non-blocking
    helper page and intentionally small — the Auditor page remains the
    primary interactive surface.
    """

    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page

        header = ctk.CTkLabel(self, text="Pipeline", font=("Roboto", 28))
        header.pack(pady=(16, 8))

        blurb = ctk.CTkLabel(
            self,
            text=(
                "Recommended flow:\n"
                "1) Auditor → Start Engagement (enumerate + preproc)\n"
                "2) Wait for preproc to finish (artifacts/ and preproc/ appear)\n"
                "3) Auditor → Run Detectors (static up to Ghidra)\n"
                "4) Inspect Results and export evidence"
            ),
            justify="left",
        )
        blurb.pack(padx=12, pady=(6, 12))

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(pady=(8, 12))
        ctk.CTkButton(
            actions, text="Go to Auditor", command=lambda: self.switch_page("auditor")
        ).pack()

    def on_enter(self):
        # placeholder for any refresh logic if needed
        pass
