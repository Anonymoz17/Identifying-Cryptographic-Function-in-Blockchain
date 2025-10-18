"""Tiny tooltip helper for tkinter widgets used by the UI.

This is intentionally small and dependency-free. It creates a
borderless Toplevel that follows the mouse while over the widget.
"""

import tkinter as tk


class Tooltip:
    def __init__(self, widget, text: str, delay: int = 500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._id = None
        self._top = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)
        widget.bind("<Motion>", self._motion)

    def _schedule(self, event=None):
        self._cancel()
        self._id = self.widget.after(self.delay, self._show)

    def _cancel(self):
        if self._id:
            try:
                self.widget.after_cancel(self._id)
            except Exception:
                pass
            self._id = None

    def _show(self):
        if self._top:
            return
        try:
            self._top = tk.Toplevel(self.widget)
            self._top.wm_overrideredirect(True)
            self._top.attributes("-topmost", True)
            lbl = tk.Label(
                self._top, text=self.text, bg="#333", fg="white", bd=1, padx=6, pady=3
            )
            lbl.pack()
            # position near cursor
            x, y = self.widget.winfo_pointerxy()
            self._top.geometry(f"+{x + 16}+{y + 16}")
        except Exception:
            self._top = None

    def _hide(self, event=None):
        self._cancel()
        if self._top:
            try:
                self._top.destroy()
            except Exception:
                pass
        self._top = None

    def _motion(self, event=None):
        # keep tooltip following the cursor
        if self._top:
            try:
                x, y = self.widget.winfo_pointerxy()
                self._top.geometry(f"+{x + 16}+{y + 16}")
            except Exception:
                pass
