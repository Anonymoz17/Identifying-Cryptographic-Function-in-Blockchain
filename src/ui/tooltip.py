"""Lightweight Tooltip helper for Tkinter / customtkinter widgets.

Usage:
    from ui.tooltip import add_tooltip
    add_tooltip(widget, "Short help text")

This implements a small delayed hover popup. It's intentionally small and
dependency-free so it works in both the main UI and tests (where messagebox
may be unavailable).
"""

from __future__ import annotations

import tkinter as tk
import typing


class _ToolTip:
    def __init__(self, widget: tk.Widget, text: str, delay: int = 400):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after_id = None
        self._win: typing.Optional[tk.Toplevel] = None

        # Bind events
        try:
            widget.bind("<Enter>", self._on_enter, add=True)
            widget.bind("<Leave>", self._on_leave, add=True)
            widget.bind("<Motion>", self._on_motion, add=True)
        except Exception:
            pass

    def _on_enter(self, event=None):
        try:
            self._schedule()
        except Exception:
            pass

    def _on_leave(self, event=None):
        try:
            self._cancel()
            self._hide()
        except Exception:
            pass

    def _on_motion(self, event=None):
        # reset schedule so tooltip appears after delay at the current pointer
        try:
            self._cancel()
            self._schedule()
        except Exception:
            pass

    def _schedule(self):
        try:
            if self._after_id:
                self.widget.after_cancel(self._after_id)
            self._after_id = self.widget.after(self.delay, self._show)
        except Exception:
            self._show()

    def _cancel(self):
        try:
            if self._after_id:
                self.widget.after_cancel(self._after_id)
                self._after_id = None
        except Exception:
            pass

    def _show(self):
        if self._win:
            return
        try:
            # create a small borderless toplevel for the tooltip
            self._win = tk.Toplevel(self.widget)
            self._win.wm_overrideredirect(True)
            self._win.attributes("-topmost", True)
            lbl = tk.Label(
                self._win,
                text=self.text,
                justify=tk.LEFT,
                background="#ffffe0",
                relief=tk.SOLID,
                borderwidth=1,
                font=("Segoe UI", 9),
            )
            lbl.pack(ipadx=4, ipady=2)
            # position near the widget
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
            self._win.wm_geometry(f"+{x}+{y}")
        except Exception:
            try:
                self._hide()
            except Exception:
                pass

    def _hide(self):
        try:
            if self._win:
                try:
                    self._win.destroy()
                except Exception:
                    pass
                self._win = None
        except Exception:
            pass


def add_tooltip(widget: tk.Widget, text: str, delay: int = 400):
    """Attach a tooltip to the given widget.

    Returns the tooltip object in case the caller wants to keep a reference.
    """
    try:
        tt = _ToolTip(widget, text, delay=delay)
        # keep reference on widget to avoid GC in some environments
        try:
            # store a direct attribute reference to avoid GC in some envs
            widget._tooltip_obj = tt
        except Exception:
            pass
        return tt
    except Exception:
        return None


# Note: there is a single, lightweight tooltip implementation above. The
# older Tooltip class that followed was removed to avoid duplicate imports
# and redefinition of `tk` at module level which caused linter errors.
