from __future__ import annotations

import json
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from typing import Any, List

import customtkinter as ctk

try:
    import matplotlib

    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
except Exception:
    Figure = None
    FigureCanvasTkAgg = None


class ResultsPage(ctk.CTkFrame):
    """Results page: render detector summary JSON as charts.

    Shows top-rule bar chart, engine breakdown, and confidence histogram.
    """

    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(content, text="Results — Summary", font=("Roboto", 24))
        header.pack(pady=(12, 6))

        # Controls
        ctrl = ctk.CTkFrame(content, fg_color="transparent")
        ctrl.pack(fill="x", padx=12)
        self.back_btn = ctk.CTkButton(
            ctrl, text="← Back", command=lambda: self.switch_page("detectors")
        )
        self.back_btn.pack(side="left")
        self.refresh_btn = ctk.CTkButton(ctrl, text="Refresh", command=self.on_enter)
        self.refresh_btn.pack(side="left", padx=(8, 0))

        # Case selector area (always visible). Shows current case if app set it,
        # allows switching to other discovered cases or browsing to a folder.
        case_ctrl = ctk.CTkFrame(ctrl, fg_color="transparent")
        case_ctrl.pack(side="right")
        self._case_values: List[str] = []
        self.case_var = tk.StringVar(value="(none)")
        # OptionMenu used for simple selection of known cases
        try:
            self.case_menu = ctk.CTkOptionMenu(
                case_ctrl, values=["(none)"], variable=self.case_var, width=240
            )
        except Exception:
            # fallback if CTkOptionMenu not available
            self.case_menu = ctk.CTkLabel(case_ctrl, textvariable=self.case_var)
        self.case_menu.pack(side="left", padx=(6, 0))
        (
            self.case_menu.configure(command=self._on_case_selected)
            if hasattr(self.case_menu, "configure")
            else None
        )

        self.browse_btn = ctk.CTkButton(
            case_ctrl, text="Browse…", width=80, command=self._on_browse_case
        )
        self.browse_btn.pack(side="left", padx=(6, 0))
        self.run_btn = ctk.CTkButton(
            case_ctrl, text="Run detectors", width=110, command=self._on_run_detectors
        )
        self.run_btn.pack(side="left", padx=(6, 0))

        # container for charts
        self.visual_frame = ctk.CTkFrame(content, fg_color="transparent")
        self.visual_frame.pack(fill="both", expand=True, padx=12, pady=12)
        self._canvases: list[Any] = []

        self._no_data_label = ctk.CTkLabel(
            self.visual_frame, text="No results available. Run detectors first."
        )
        self._no_data_label.pack()

    def _open_dialog(self, fn, /, **kwargs):
        """Wrapper for file dialogs similar to SetupPage._open_dialog.

        Ensures UI updates before opening, then schedules a small post-dialog
        cleanup to restore focus and redraw. Returns the dialog result.
        """
        try:
            self.update_idletasks()
        except Exception:
            pass
        try:
            res = fn(**kwargs)
        except Exception:
            res = None
        try:
            self.after(50, self._dialog_post_cleanup)
        except Exception:
            try:
                self._dialog_post_cleanup()
            except Exception:
                pass
        return res

    def _dialog_post_cleanup(self):
        try:
            top = self.winfo_toplevel()
            try:
                top.focus_force()
            except Exception:
                pass
            try:
                top.update()
            except Exception:
                pass
        except Exception:
            pass

    # ---- case discovery and selection helpers ----
    def _discover_cases(self) -> List[Path]:
        # Look in a few likely roots for candidate case directories
        roots = [Path("uploads"), Path(".")]
        seen: List[Path] = []
        for r in roots:
            if not r.exists() or not r.is_dir():
                continue
            for child in sorted(
                r.iterdir(),
                key=lambda p: p.stat().st_mtime if p.exists() else 0,
                reverse=True,
            ):
                if not child.is_dir():
                    continue
                # heuristics: presence of manifest or detector_output
                if (child / "inputs.manifest.ndjson").exists() or (
                    child / "detector_output"
                ).exists():
                    seen.append(child)
        # dedupe preserving order
        out: List[Path] = []
        for p in seen:
            if p not in out:
                out.append(p)
        return out

    def _populate_case_menu(self):
        cases = self._discover_cases()
        if not cases:
            vals = ["(none)"]
        else:
            vals = [str(p) for p in cases]
        self._case_values = vals
        try:
            if hasattr(self.case_menu, "configure"):
                self.case_menu.configure(values=vals)
        except Exception:
            pass
        # if app has a current_scan_meta, preselect it
        ctx = getattr(self.master, "current_scan_meta", None)
        if ctx:
            wd = ctx.get("workdir")
            if wd and str(wd) in vals:
                self.case_var.set(str(wd))
            else:
                # try to find by case_id
                cid = ctx.get("case_id")
                if cid:
                    for v in vals:
                        if Path(v).name == cid:
                            self.case_var.set(v)
                            break
        else:
            # default to first candidate if any
            if vals and vals[0] != "(none)":
                self.case_var.set(vals[0])

    def _on_case_selected(self, _=None):
        val = self.case_var.get()
        if not val or val == "(none)":
            self._no_data_label.configure(
                text="No case selected — choose or browse to a case."
            )
            self._clear_visuals()
            self._no_data_label.pack()
            return
        p = Path(val)
        if not p.exists():
            # attach messagebox to the app window
            tk.messagebox.showerror(
                "Not found",
                f"Selected case not found: {p}",
                parent=self.winfo_toplevel(),
            )
            return
        # set app state
        try:
            self.master.current_scan_meta = {"workdir": str(p), "case_id": p.name}
        except Exception:
            pass
        # load summary if present
        # defer heavy load a tick so the UI can redraw after the file dialog
        # returns; this prevents a perceived hang on some platforms.
        try:
            self.after(50, lambda: self.load_case(p))
        except Exception:
            self.load_case(p)

    def _on_browse_case(self):
        d = self._open_dialog(
            tk.filedialog.askdirectory,
            parent=self.winfo_toplevel(),
            title="Select case/workspace directory",
        )
        if not d:
            return
        self.case_var.set(d)
        # defer heavy load to allow UI to refresh
        try:
            self.after(50, self._on_case_selected)
        except Exception:
            self._on_case_selected()

    def _on_run_detectors(self):
        # run the helper script in a detached subprocess so UI stays responsive
        case = self.case_var.get()
        if not case or case == "(none)":
            tk.messagebox.showinfo(
                "Select case",
                "Please select or browse to a case first.",
                parent=self.winfo_toplevel(),
            )
            return
        script = self._locate_open_results_script()
        if script is None:
            # Let user pick the helper script if automatic locate failed
            tk.messagebox.showinfo(
                "Helper not found",
                "Could not locate tools/open_results.py automatically. Please select it on disk.",
                parent=self.winfo_toplevel(),
            )
            chosen = self._open_dialog(
                tk.filedialog.askopenfilename,
                parent=self.winfo_toplevel(),
                title="Select open_results.py",
                filetypes=[("Python files", "*.py"), ("All files", "*")],
            )
            if not chosen:
                return
            script = Path(chosen)
        cmd = [sys.executable, str(script), "--case", case, "--run"]
        try:
            subprocess.Popen(cmd)
            tk.messagebox.showinfo(
                "Running",
                "Detectors started in a background process.",
                parent=self.winfo_toplevel(),
            )
        except Exception as e:
            tk.messagebox.showerror(
                "Failed",
                f"Failed to start detectors: {e}",
                parent=self.winfo_toplevel(),
            )

    def _clear_visuals(self):
        for c in self._canvases:
            try:
                c.get_tk_widget().destroy()
            except Exception:
                pass
        self._canvases = []

    def _render_from_data(self, data: dict | None):
        """Render visuals from already-loaded summary `data` on the main thread.

        If data is None, shows an error message.
        """
        if not data:
            self._no_data_label.configure(text="Failed to read summary JSON")
            self._clear_visuals()
            self._no_data_label.pack()
            return

        # render visuals
        self._clear_visuals()
        try:
            self._no_data_label.pack_forget()
        except Exception:
            pass

        if Figure is None or FigureCanvasTkAgg is None:
            lbl = ctk.CTkLabel(
                self.visual_frame, text="matplotlib not available; cannot render charts"
            )
            lbl.pack(pady=8)
            return

        # Top-rule bar chart
        top_rules = data.get("top_rules", [])
        if top_rules:
            fig = Figure(figsize=(6, 3))
            ax = fig.add_subplot(111)
            names = [r.get("rule") for r in top_rules][:10]
            counts = [r.get("count") for r in top_rules][:10]
            ax.barh(range(len(names))[::-1], counts[::-1], color="#4c78a8")
            ax.set_yticks(range(len(names)))
            ax.set_yticklabels(names[::-1])
            ax.set_xlabel("Occurrences")
            ax.set_title("Top rules")
            canvas = FigureCanvasTkAgg(fig, master=self.visual_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(side="top", fill="x", pady=(6, 6))
            self._canvases.append(canvas)

        # Engine breakdown
        engines = data.get("counts", {}).get("by_engine", {})
        if engines:
            fig = Figure(figsize=(4, 3))
            ax = fig.add_subplot(111)
            labels = list(engines.keys())
            sizes = [engines[k] for k in labels]
            ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
            ax.set_title("Engine breakdown")
            canvas = FigureCanvasTkAgg(fig, master=self.visual_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(
                side="left", fill="both", expand=True, padx=(0, 6)
            )
            self._canvases.append(canvas)

        # Confidence histogram
        buckets = data.get("confidence_buckets", [])
        if buckets:
            fig = Figure(figsize=(4, 3))
            ax = fig.add_subplot(111)
            xs = [i * 0.1 for i in range(len(buckets))]
            ax.bar(xs, buckets, width=0.09, color="#e45756")
            ax.set_xlabel("Confidence (bucket start)")
            ax.set_ylabel("Count")
            ax.set_title("Confidence distribution")
            canvas = FigureCanvasTkAgg(fig, master=self.visual_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(
                side="right", fill="both", expand=True, padx=(6, 0)
            )
            self._canvases.append(canvas)

    def load_case(self, case_dir: Path):
        out_dir = case_dir / "detector_output"
        summary_path = out_dir / "detector_results.summary.json"
        if not summary_path.exists():
            self._no_data_label.configure(
                text=f"No summary found at {summary_path}\nRun detectors first."
            )
            self._clear_visuals()
            self._no_data_label.pack()
            return

        # Show a light-weight loading status while we read the JSON in a thread
        try:
            self._no_data_label.configure(text="Loading summary...")
            self._no_data_label.pack()
        except Exception:
            pass

        def _worker():
            try:
                text = summary_path.read_text(encoding="utf-8")
                data = json.loads(text)
            except Exception:
                data = None
            # schedule UI rendering on main thread
            try:
                self.after(0, lambda: self._render_from_data(data))
            except Exception:
                try:
                    self._render_from_data(data)
                except Exception:
                    pass

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def _locate_open_results_script(self) -> Path | None:
        # Try a few likely locations for tools/open_results.py
        candidates = []
        here = Path(__file__).resolve()
        # repo root (parents[2])
        try:
            repo_root = here.parents[2]
            candidates.append(repo_root / "tools" / "open_results.py")
        except Exception:
            pass
        # cwd-based
        candidates.append(Path.cwd() / "tools" / "open_results.py")
        # sibling positions (in case file layout differs)
        candidates.append(here.parents[1] / "tools" / "open_results.py")
        candidates.append(here.parents[3] / "tools" / "open_results.py")

        for c in candidates:
            if c and c.exists():
                return c
        return None

    def on_enter(self):
        # refresh known cases and preselect if app state exists
        self._populate_case_menu()
        ctx = getattr(self.master, "current_scan_meta", None)
        # if app provided a current case, load it
        if ctx:
            wd = ctx.get("workdir")
            case_id = ctx.get("case_id") or "CASE-000"
            try:
                p = Path(wd)
                if p.exists() and p.name == case_id:
                    case_dir = p
                else:
                    case_dir = Path(wd) / case_id if not p.name == case_id else p
            except Exception:
                case_dir = Path(wd)
            self.case_var.set(str(case_dir))
            self.load_case(case_dir)
            return

        # otherwise, if selector has a candidate, load that
        cur = self.case_var.get()
        if cur and cur != "(none)":
            self.load_case(Path(cur))
            return

        # nothing to show
        self._no_data_label.configure(
            text="No case selected — run Setup first or browse to a case"
        )
