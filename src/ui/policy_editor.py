from __future__ import annotations

import json
import tempfile
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
from typing import Callable, Optional, Tuple

import customtkinter as ctk

from policy_validator import validate_policy_text


class PolicyEditor:
    """Modal policy editor.

    Usage:
        path, attached = PolicyEditor.open(parent, template_callback)

    - parent: parent tkinter widget
    - template_callback: callable(kind: str) -> str which returns a JSON template

    Returns: tuple(path_or_empty_str, attached_bool)
    """

    @staticmethod
    def open(
        parent: tk.Widget, template_callback: Callable[[str], str]
    ) -> Tuple[Optional[str], bool]:
        result_path: Optional[str] = None
        attached_flag = False

        top = tk.Toplevel(parent)
        top.title("Policy baseline editor")
        top.transient(parent)
        top.grab_set()

        frame = ctk.CTkFrame(top, fg_color="transparent")
        frame.pack(padx=12, pady=12, fill="both", expand=True)

        # Template selector + two-pane editor: structured form (left) + raw JSON (right)
        ctk.CTkLabel(frame, text="Template:").grid(row=0, column=0, sticky="w")
        templates = ["Whitelist", "Rule Overrides", "Scoring", "Combined"]
        tmpl_var = tk.StringVar(value=templates[0])
        tmpl_menu = ctk.CTkOptionMenu(frame, values=templates, variable=tmpl_var)
        tmpl_menu.grid(row=0, column=1, sticky="we", padx=(8, 0), columnspan=2)

        split = ctk.CTkFrame(frame, fg_color="transparent")
        split.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=(8, 8))
        split.grid_columnconfigure(0, weight=1)
        split.grid_columnconfigure(1, weight=2)

        # Left: structured fields
        form_frame = ctk.CTkFrame(split, fg_color="transparent")
        form_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        form_frame.grid_columnconfigure(1, weight=1)

        version_entry = ctk.CTkEntry(form_frame)
        version_entry.grid(row=0, column=1, sticky="we", pady=(2, 6))
        author_entry = ctk.CTkEntry(form_frame)
        author_entry.grid(row=1, column=1, sticky="we", pady=(2, 6))
        meta_ver_entry = ctk.CTkEntry(form_frame)
        meta_ver_entry.grid(row=2, column=1, sticky="we", pady=(2, 6))

        ew_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        ew_frame.grid(row=4, column=0, columnspan=2, sticky="we", pady=(2, 6))
        yara_w = ctk.CTkEntry(ew_frame, width=60)
        yara_w.grid(row=0, column=0, padx=(0, 6))
        ts_w = ctk.CTkEntry(ew_frame, width=60)
        ts_w.grid(row=0, column=1, padx=(0, 6))
        disasm_w = ctk.CTkEntry(ew_frame, width=60)
        disasm_w.grid(row=0, column=2)

        whitelist_entry = tk.Text(form_frame, height=6, wrap="none")
        whitelist_entry.grid(row=5, column=1, sticky="we", pady=(2, 6))

        # Right: raw JSON editor
        editor_frame = ctk.CTkFrame(split, fg_color="transparent")
        editor_frame.grid(row=0, column=1, sticky="nsew")
        editor_frame.grid_rowconfigure(0, weight=1)
        editor_frame.grid_columnconfigure(0, weight=1)

        editor = tk.Text(editor_frame, width=80, height=20, wrap="none")
        editor.grid(row=0, column=0, sticky="nsew")

        def _render_template(*_):
            kind = tmpl_var.get()
            editor.delete("1.0", "end")
            try:
                editor.insert("1.0", template_callback(kind))
            except Exception:
                editor.insert("1.0", "{}")
            try:
                obj = json.loads(editor.get("1.0", "end"))
                try:
                    json_to_form(obj)
                except Exception:
                    pass
            except Exception:
                pass

        tmpl_var.trace_add("write", _render_template)
        _render_template()

        # Helper mappers
        def json_to_form(obj: dict):
            try:
                version_entry.delete(0, "end")
                version_entry.insert(0, str(obj.get("version", "")))
            except Exception:
                pass
            try:
                meta = obj.get("metadata", {}) or {}
                author_entry.delete(0, "end")
                author_entry.insert(0, str(meta.get("author", "")))
                meta_ver_entry.delete(0, "end")
                meta_ver_entry.insert(0, str(meta.get("version", "")))
            except Exception:
                pass
            try:
                ew = (obj.get("scoring", {}) or {}).get("engine_weights", {}) or {}
                yara_w.delete(0, "end")
                yara_w.insert(0, str(ew.get("yara", "")))
                ts_w.delete(0, "end")
                ts_w.insert(0, str(ew.get("treesitter", "")))
                disasm_w.delete(0, "end")
                disasm_w.insert(0, str(ew.get("disasm", "")))
            except Exception:
                pass
            try:
                fh = (obj.get("whitelist", {}) or {}).get("file_hashes", []) or []
                whitelist_entry.delete("1.0", "end")
                whitelist_entry.insert("1.0", ",".join(str(x) for x in fh))
            except Exception:
                pass

        def form_to_json():
            out = {}
            try:
                v = version_entry.get().strip()
                if v:
                    out["version"] = v
            except Exception:
                pass
            try:
                meta = {}
                a = author_entry.get().strip()
                if a:
                    meta["author"] = a
                mv = meta_ver_entry.get().strip()
                if mv:
                    meta["version"] = mv
                if meta:
                    out["metadata"] = meta
            except Exception:
                pass
            try:
                ew = {}
                y = yara_w.get().strip()
                t = ts_w.get().strip()
                d = disasm_w.get().strip()
                if y:
                    try:
                        ew["yara"] = float(y)
                    except Exception:
                        ew["yara"] = y
                if t:
                    try:
                        ew["treesitter"] = float(t)
                    except Exception:
                        ew["treesitter"] = t
                if d:
                    try:
                        ew["disasm"] = float(d)
                    except Exception:
                        ew["disasm"] = d
                if ew:
                    out.setdefault("scoring", {})["engine_weights"] = ew
            except Exception:
                pass
            try:
                fh_txt = whitelist_entry.get("1.0", "end").strip()
                if fh_txt:
                    fh = [s.strip() for s in fh_txt.split(",") if s.strip()]
                    out.setdefault("whitelist", {})["file_hashes"] = fh
            except Exception:
                pass
            try:
                editor.delete("1.0", "end")
                editor.insert(
                    "1.0", json.dumps(out, sort_keys=True, ensure_ascii=False, indent=2)
                )
                schedule_validate()
            except Exception:
                pass

        top.form_sync_timer = None

        def schedule_form_sync():
            try:
                if getattr(top, "form_sync_timer", None):
                    top.after_cancel(top.form_sync_timer)
            except Exception:
                pass
            try:
                top.form_sync_timer = top.after(300, form_to_json)
            except Exception:
                form_to_json()

        # Bindings
        try:
            version_entry.bind("<KeyRelease>", lambda e: schedule_form_sync())
            author_entry.bind("<KeyRelease>", lambda e: schedule_form_sync())
            meta_ver_entry.bind("<KeyRelease>", lambda e: schedule_form_sync())
            yara_w.bind("<KeyRelease>", lambda e: schedule_form_sync())
            ts_w.bind("<KeyRelease>", lambda e: schedule_form_sync())
            disasm_w.bind("<KeyRelease>", lambda e: schedule_form_sync())
            whitelist_entry.bind("<KeyRelease>", lambda e: schedule_form_sync())
        except Exception:
            pass

        error_var = tk.StringVar(value="")
        error_label = ctk.CTkLabel(frame, textvariable=error_var, text_color="#d9534f")
        error_label.grid(row=3, column=0, columnspan=3, sticky="we", pady=(0, 6))

        attach_var = tk.BooleanVar(value=False)
        try:
            ctk.CTkCheckBox(frame, text="Attach on Insert", variable=attach_var).grid(
                row=4, column=0, sticky="w", pady=(4, 0)
            )
        except Exception:
            pass

        top.policy_validate_timer = None
        top.last_policy_text = None

        def schedule_validate():
            try:
                if getattr(top, "policy_validate_timer", None):
                    top.after_cancel(top.policy_validate_timer)
            except Exception:
                pass
            try:
                top.policy_validate_timer = top.after(400, run_validate)
            except Exception:
                run_validate()

        def run_validate():
            try:
                top.policy_validate_timer = None
                txt = editor.get("1.0", "end").strip()
                if txt == getattr(top, "last_policy_text", None):
                    return
                top.last_policy_text = txt
                valid, errors = validate_policy_text(txt)
                if not valid:
                    try:
                        error_var.set("\n".join(errors))
                    except Exception:
                        pass
                    try:
                        insert_btn.configure(state="disabled")
                    except Exception:
                        pass
                    try:
                        save_btn.configure(state="disabled")
                    except Exception:
                        pass
                else:
                    try:
                        error_var.set("")
                    except Exception:
                        pass
                    try:
                        obj = json.loads(txt)
                        try:
                            json_to_form(obj)
                        except Exception:
                            pass
                    except Exception:
                        pass
                    try:
                        insert_btn.configure(state="normal")
                    except Exception:
                        pass
                    try:
                        save_btn.configure(state="normal")
                    except Exception:
                        pass
            except Exception:
                try:
                    error_var.set("Validation error")
                except Exception:
                    pass

        editor.bind("<KeyRelease>", lambda e: schedule_validate())
        try:
            schedule_validate()
        except Exception:
            pass

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=2, column=0, columnspan=3, pady=(6, 0))

        def _insert_to_entry():
            nonlocal result_path, attached_flag
            txt = editor.get("1.0", "end").strip()
            valid, errors = validate_policy_text(txt)
            if not valid:
                try:
                    error_var.set("\n".join(errors))
                except Exception:
                    pass
                try:
                    messagebox.showerror(
                        "Invalid policy", "\n".join(errors), parent=top
                    )
                except Exception:
                    pass
                return
            try:
                fd, path = tempfile.mkstemp(prefix="policy_", suffix=".json")
                with open(fd, "w", encoding="utf-8") as f:
                    f.write(txt)
                result_path = path
                attached_flag = bool(attach_var.get())
                top.destroy()
            except Exception:
                try:
                    messagebox.showerror(
                        "Error", "Could not write temp file", parent=top
                    )
                except Exception:
                    pass

        def _save_as():
            nonlocal result_path, attached_flag
            path = filedialog.asksaveasfilename(
                parent=top,
                title="Save policy as...",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*")],
            )
            if not path:
                return
            try:
                txt = editor.get("1.0", "end").strip()
                valid, errors = validate_policy_text(txt)
                if not valid:
                    try:
                        error_var.set("\n".join(errors))
                    except Exception:
                        pass
                    try:
                        messagebox.showerror(
                            "Invalid policy", "\n".join(errors), parent=top
                        )
                    except Exception:
                        pass
                    return
                with open(path, "w", encoding="utf-8") as f:
                    f.write(txt)
                result_path = path
                top.destroy()
            except Exception as e:
                try:
                    messagebox.showerror(
                        "Error", f"Could not save file: {e}", parent=top
                    )
                except Exception:
                    pass

        def _load_file_to_editor():
            p = filedialog.askopenfilename(parent=top, title="Open policy (JSON)")
            if not p:
                return
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = f.read()
                editor.delete("1.0", "end")
                editor.insert("1.0", data)
                try:
                    schedule_validate()
                except Exception:
                    pass
            except Exception:
                try:
                    messagebox.showerror("Error", "Could not read file", parent=top)
                except Exception:
                    pass

        insert_btn = ctk.CTkButton(btn_frame, text="Insert", command=_insert_to_entry)
        insert_btn.pack(side="left", padx=(0, 8))
        save_btn = ctk.CTkButton(btn_frame, text="Save As...", command=_save_as)
        save_btn.pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_frame, text="Load...", command=_load_file_to_editor).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(btn_frame, text="Cancel", command=top.destroy).pack(
            side="left", padx=(0, 8)
        )

        top.wait_window()
        return result_path, attached_flag
