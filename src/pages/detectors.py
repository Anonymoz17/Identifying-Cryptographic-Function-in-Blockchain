from __future__ import annotations

import threading
import tkinter as tk
import tkinter.messagebox as messagebox
from pathlib import Path

from auditor.workspace import Workspace
from detectors.adapter import SimpleSemgrepAdapter, YaraAdapter
from detectors.disasm_adapter import DisasmJsonAdapter
from detectors.ghidra_adapter import GhidraAdapter
from detectors.merge import dedupe_detections
from detectors.runner import generate_summary, run_adapters, write_ndjson_detections
from detectors.tree_sitter_detector import TreeSitterDetector

import customtkinter as ctk  # isort:skip


class DetectorsPage(ctk.CTkFrame):
    """Detectors page: select detectors, run detectors and (optionally) headless Ghidra.

    This page expects the SetupPage to have created preproc artifacts and stored
    a minimal context on the master as `master.current_scan_meta = {workdir, case_id}`.
    """

    def __init__(self, master, switch_page_callback):
        super().__init__(master)
        self.switch_page = switch_page_callback

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            content, text="Detectors — Configure & Run", font=("Roboto", 28)
        )
        header.pack(pady=(12, 6))

        # Mode selector: Static (default) or Dynamic (skeleton)
        mode_frame = ctk.CTkFrame(content, fg_color="transparent")
        mode_frame.pack(padx=12, pady=(0, 6), fill="x")
        ctk.CTkLabel(mode_frame, text="Mode:").pack(side="left", padx=(0, 8))
        self.mode_var = tk.StringVar(value="static")
        try:
            # CTkSegmentedButton provides a compact two-state control
            self.mode_selector = ctk.CTkSegmentedButton(
                mode_frame, values=["static", "dynamic"], command=self._on_mode_change
            )
            self.mode_selector.set("static")
            self.mode_selector.pack(side="left")
        except Exception:
            # fallback to radio buttons if segmented button isn't available
            r1 = ctk.CTkRadioButton(
                mode_frame,
                text="Static",
                variable=self.mode_var,
                value="static",
                command=self._on_mode_change,
            )
            r2 = ctk.CTkRadioButton(
                mode_frame,
                text="Dynamic",
                variable=self.mode_var,
                value="dynamic",
                command=self._on_mode_change,
            )
            r1.pack(side="left", padx=(0, 6))
            r2.pack(side="left")

        # Detector checkboxes
        det_frame = ctk.CTkFrame(content, fg_color="transparent")
        det_frame.pack(padx=12, pady=(6, 6), fill="x")
        det_frame.grid_columnconfigure(1, weight=1)

        self.yara_var = tk.BooleanVar(value=True)
        self.semgrep_var = tk.BooleanVar(value=True)
        self.ts_var = tk.BooleanVar(value=True)
        self.disasm_var = tk.BooleanVar(value=True)
        self.ghidra_var = tk.BooleanVar(value=False)

        ctk.CTkCheckBox(det_frame, text="YARA", variable=self.yara_var).grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkCheckBox(det_frame, text="Semgrep", variable=self.semgrep_var).grid(
            row=0, column=1, sticky="w"
        )
        ctk.CTkCheckBox(det_frame, text="Tree-sitter", variable=self.ts_var).grid(
            row=0, column=2, sticky="w"
        )
        ctk.CTkCheckBox(det_frame, text="Disasm", variable=self.disasm_var).grid(
            row=1, column=0, sticky="w", pady=(6, 0)
        )
        ctk.CTkCheckBox(
            det_frame, text="Ghidra (requires exports)", variable=self.ghidra_var
        ).grid(row=1, column=1, sticky="w", pady=(6, 0))

        # Actions
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(pady=(8, 8))
        self.run_detectors_btn = ctk.CTkButton(
            actions, text="Run Detectors", command=self._on_run_detectors
        )
        self.run_detectors_btn.pack(side="left", padx=(0, 8))
        self.run_ghidra_btn = ctk.CTkButton(
            actions, text="Run Ghidra headless", command=self._on_run_ghidra
        )
        self.run_ghidra_btn.pack(side="left", padx=(0, 8))
        self.open_results_btn = ctk.CTkButton(
            actions,
            text="Open Results Folder",
            command=self._open_results,
            state="disabled",
        )
        self.open_results_btn.pack(side="left", padx=(8, 0))
        self.refresh_btn = ctk.CTkButton(
            actions, text="Refresh", width=80, command=self._check_preproc
        )
        self.refresh_btn.pack(side="left", padx=(8, 0))
        self.back_btn = ctk.CTkButton(
            actions, text="← Back to Setup", command=self._on_back
        )
        self.back_btn.pack(side="left", padx=(8, 0))

        # Ghidra options (exports root and mock toggle)
        gh_frame = ctk.CTkFrame(content, fg_color="transparent")
        gh_frame.pack(fill="x", padx=12, pady=(2, 6))
        ctk.CTkLabel(gh_frame, text="Ghidra exports root:").grid(
            row=0, column=0, sticky="w"
        )
        self.gh_exports_entry = ctk.CTkEntry(
            gh_frame,
            placeholder_text="path to artifacts/ghidra_exports or leave blank for case defaults",
        )
        self.gh_exports_entry.grid(row=0, column=1, sticky="we", padx=(6, 8))
        gh_frame.grid_columnconfigure(1, weight=1)
        self.gh_mock_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            gh_frame,
            text="Use mock Ghidra exports (tools/ghidra/mock_exports)",
            variable=self.gh_mock_var,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))

        # Progress and results
        self.status_label = ctk.CTkLabel(content, text="")
        self.status_label.pack(pady=(6, 2))
        self.results_box = tk.Text(content, height=18, wrap="none")
        self.results_box.pack(fill="both", padx=12, pady=(6, 12), expand=True)

        # internal
        self._runner_thread = None

    def _on_mode_change(self, *args):
        # Called when the mode selector changes. Enable/disable dynamic options.
        try:
            mode = self.mode_var.get() if hasattr(self, "mode_var") else None
        except Exception:
            # CTkSegmentedButton may not update mode_var; try reading selector value
            try:
                mode = (
                    self.mode_selector.get()
                    if hasattr(self, "mode_selector")
                    else "static"
                )
            except Exception:
                mode = "static"

        # Update UI: when in static mode, keep Ghidra options disabled by default
        try:
            if mode == "static":
                # disable exports entry to avoid inviting dynamic runs
                try:
                    self.gh_exports_entry.configure(state="disabled")
                except Exception:
                    pass
                self.status_label.configure(
                    text="Static mode: runs detectors on preprocessed artifacts only"
                )
            else:
                try:
                    self.gh_exports_entry.configure(state="normal")
                except Exception:
                    pass
                self.status_label.configure(
                    text="Dynamic mode: runs dynamic steps first (skeleton) then static detectors"
                )
        except Exception:
            pass

    def on_enter(self):
        # Called when page becomes active: check if we have a case from Setup
        ctx = getattr(self.master, "current_scan_meta", None)
        if not ctx:
            self.status_label.configure(text="No case selected — go to Setup first")
            self.run_detectors_btn.configure(state="disabled")
            self.run_ghidra_btn.configure(state="disabled")
            return

        # Resolve workspace: ctx may store either the base workdir (like './case_demo')
        # plus case_id, or a full case root path produced by Engagement. Handle both.
        wd = ctx.get("workdir")
        case_id = ctx.get("case_id") or "CASE-000"
        try:
            p = Path(wd)
            if p.exists() and p.name == case_id:
                # `wd` already points to the full case root; construct Workspace with parent as base
                ws = Workspace(p.parent, case_id)
            else:
                ws = Workspace(p, case_id)
        except Exception:
            ws = Workspace(Path(wd), case_id)

        case_dir = ws.root
        if not case_dir.exists():
            self.status_label.configure(
                text="Case workdir does not exist — return to Setup"
            )
            self.run_detectors_btn.configure(state="disabled")
            self.run_ghidra_btn.configure(state="disabled")
            return

        # enable run buttons only if preproc artifacts exist; otherwise ask user to run Setup
        self.results_box.delete("1.0", "end")
        self.status_label.configure(
            text=f"Loaded case: {ctx.get('case_id')} @ {case_dir}"
        )
        # Check preproc presence and update the run button states accordingly
        has_preproc = self._check_preproc()
        if has_preproc:
            self.run_ghidra_btn.configure(state="normal")
            self.open_results_btn.configure(state="disabled")
        else:
            self.run_ghidra_btn.configure(state="disabled")

    def _on_back(self):
        self.switch_page("setup")

    def _check_preproc(self):
        """Check for preproc input.bin files for the current case and update UI."""
        ctx = getattr(self.master, "current_scan_meta", None)
        if not ctx:
            self.status_label.configure(text="No case selected — go to Setup first")
            return False
        wd = ctx.get("workdir")
        case_id = ctx.get("case_id") or "CASE-000"
        try:
            p = Path(wd)
            if p.exists() and p.name == case_id:
                ws = Workspace(p.parent, case_id)
            else:
                ws = Workspace(p, case_id)
        except Exception:
            ws = Workspace(Path(wd), case_id)
        # don't create dirs here; just inspect
        case_dir = ws.root
        preproc_dir = case_dir / "preproc"
        count = 0
        if preproc_dir.exists() and preproc_dir.is_dir():
            try:
                for sub in preproc_dir.iterdir():
                    if sub.is_dir() and (sub / "input.bin").exists():
                        count += 1
            except Exception:
                count = 0
        if count:
            self.status_label.configure(
                text=f"Preproc: {count} input(s) found at {preproc_dir}"
            )
            try:
                self.run_detectors_btn.configure(state="normal")
            except Exception:
                pass
            return True
        else:
            self.status_label.configure(
                text="No preprocessed files found for this case. Run Setup first"
            )
            try:
                self.run_detectors_btn.configure(state="disabled")
            except Exception:
                pass
            return False

    def _append(self, text: str):
        try:
            self.results_box.insert("end", text + "\n")
            self.results_box.see("end")
        except Exception:
            pass

    def _on_run_ghidra(self):
        ctx = getattr(self.master, "current_scan_meta", None)
        if not ctx:
            self._append("No case selected; run Setup first")
            return

        # fire off the existing tools runner script in background
        def run_bg():
            try:
                import subprocess

                case_dir = ctx.get("workdir")
                cmd = [
                    "python",
                    "tools/run_ghidra_headless.py",
                    "--case",
                    str(case_dir),
                    "--run",
                ]
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                for line in proc.stdout:
                    self._append(line.rstrip())
                proc.wait()
                self._append(f"Ghidra headless finished: exit {proc.returncode}")
            except Exception as e:
                self._append(f"Ghidra runner failed: {e}")

        t = threading.Thread(target=run_bg, daemon=True)
        t.start()

    def _open_results(self):
        ctx = getattr(self.master, "current_scan_meta", None)
        if not ctx:
            return
        case_dir = Path(ctx.get("workdir"))
        res_dir = case_dir / "detector_output"
        # Prefer to show an in-app Results page if available; fall back to opening
        # the folder in Explorer when running outside the GUI or if Results page
        # isn't registered.
        try:
            # ask the app to switch pages to the results view
            try:
                self.switch_page("results")
                return
            except Exception:
                pass
            if res_dir.exists():
                import subprocess

                subprocess.Popen(["explorer.exe", str(res_dir)])
        except Exception:
            pass

    def _on_run_detectors(self):
        ctx = getattr(self.master, "current_scan_meta", None)
        if not ctx:
            self._append("No case selected; run Setup first")
            return

        wd = ctx.get("workdir")
        case_id = ctx.get("case_id") or "CASE-000"
        try:
            p = Path(wd)
            if p.exists() and p.name == case_id:
                ws = Workspace(p.parent, case_id)
            else:
                ws = Workspace(p, case_id)
        except Exception:
            ws = Workspace(Path(wd), case_id)
        ws.ensure()
        case_dir = ws.root

        # Gather preproc input.bin files (preproc/<sha>/input.bin)
        # Require preprocessed files: look under <case_root>/preproc/<sha>/input.bin
        preproc_dir = case_dir / "preproc"
        files = []
        if preproc_dir.exists() and preproc_dir.is_dir():
            try:
                for sub in preproc_dir.iterdir():
                    if sub.is_dir():
                        cand = sub / "input.bin"
                        if cand.exists():
                            files.append(str(cand))
            except Exception:
                files = []

        if not files:
            self._append("No preprocessed files found for this case. Run Setup first.")
            return

        # Run detectors in background
        def worker():
            try:
                self._append("Starting detectors...")
                adapters = []
                gh_root = None
                if self.semgrep_var.get():
                    sem_rules = {"se:keccak": "keccak", "se:sha3": "sha3"}
                    adapters.append(SimpleSemgrepAdapter(sem_rules))
                if self.yara_var.get():
                    fallback = {
                        "aes_literal": "AES|aes",
                        "sha_literal": "sha256|sha3|keccak",
                    }
                    try:
                        adapters.append(YaraAdapter(rules_map=fallback))
                    except Exception:
                        pass
                if self.ts_var.get():
                    adapters.append(TreeSitterDetector())
                if self.disasm_var.get():
                    adapters.append(DisasmJsonAdapter())
                if self.ghidra_var.get():
                    # choose exports root based on mock toggle or explicit entry
                    try:
                        if bool(self.gh_mock_var.get()):
                            gh_root = Path("tools") / "ghidra" / "mock_exports"
                        else:
                            gh_entry = (
                                self.gh_exports_entry.get().strip()
                                if hasattr(self, "gh_exports_entry")
                                else ""
                            )
                            if gh_entry:
                                cand = Path(gh_entry).resolve()
                                # allowed locations: case_dir/artifacts/ghidra_exports or repo/tools/ghidra/mock_exports
                                repo_root = Path(__file__).resolve().parents[2]
                                allowed = [
                                    (
                                        case_dir / "artifacts" / "ghidra_exports"
                                    ).resolve(),
                                    (
                                        repo_root / "tools" / "ghidra" / "mock_exports"
                                    ).resolve(),
                                ]
                                ok = any(str(cand).startswith(str(a)) for a in allowed)
                                if not ok:
                                    # ask user to confirm using an external path
                                    try:
                                        msg = (
                                            "The Ghidra exports path you provided is outside the case "
                                            "workspace. Using external paths may expose sensitive data or "
                                            "overwrite files. Do you want to continue?"
                                        )
                                        res = messagebox.askyesno(
                                            "Confirm external exports path", msg
                                        )
                                        if res:
                                            gh_root = cand
                                        else:
                                            # fallback to case-local exports
                                            gh_root = (
                                                case_dir
                                                / "artifacts"
                                                / "ghidra_exports"
                                            )
                                    except Exception:
                                        # If messagebox isn't available (headless tests), disallow external
                                        gh_root = (
                                            case_dir / "artifacts" / "ghidra_exports"
                                        )
                                else:
                                    gh_root = cand
                            else:
                                gh_root = case_dir / "artifacts" / "ghidra_exports"
                    except Exception:
                        gh_root = case_dir / "artifacts" / "ghidra_exports"
                    adapters.append(GhidraAdapter(exports_root=str(gh_root)))

                # run adapters and write raw + merged NDJSON into detector_output
                dets = list(run_adapters(adapters, files))
                out_dir = case_dir / "detector_output"
                out_dir.mkdir(parents=True, exist_ok=True)
                raw_path = out_dir / "detector_results.ndjson"
                merged_path = out_dir / "detector_results_merged.ndjson"
                write_ndjson_detections(dets, str(raw_path))
                merged = dedupe_detections(dets)
                write_ndjson_detections(merged, str(merged_path))
                # Generate a summary JSON for the UI (includes aggregates and examples)
                try:
                    generate_summary(dets, out_dir, case_dir, adapters)
                except Exception:
                    # don't fail the whole run for summary write errors
                    pass

                self._append("Detectors finished — results written to detector_output/")
                try:
                    self.open_results_btn.configure(state="normal")
                except Exception:
                    pass
            except Exception as e:
                self._append(f"Detectors failed: {e}")

        t = threading.Thread(target=worker, daemon=True)
        t.start()
