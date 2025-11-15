# src/ui/account_bubble.py
from __future__ import annotations
from typing import Optional, Dict, Any
import os

import customtkinter as ctk

# Theme
try:
    from ui.theme import TEXT, MUTED, CARD_BG, BORDER, BG
except Exception:
    TEXT, MUTED, CARD_BG, BORDER, BG = "#E5E7EB", "#9CA3AF", "#111827", "#1F2937", "#0B0F1A"

# Supabase (optional)
_SUPABASE_READY = True
try:
    from supabase import create_client  # type: ignore
except Exception:
    _SUPABASE_READY = False


class AccountBubble:
    """
    Small top-right bubble button that opens a persistent account window.

    Usage in any page's __init__:
        self._acct = AccountBubble(self)
        self._acct.mount(top_right_of=self)

    Optional overrides from the app/page:
        self._acct.refresh(profile_dict)

    Where profile_dict is:
        {
            "full_name": str,
            "email": str,
            "role": str or list,
            "plan": str,
        }

    If no override is set, the bubble will:
      - Try Supabase 'user_overview' (email, full_name, role)
      - Fall back to app.current_user / app.current_user_role
    """

    def __init__(self, page_frame: ctk.CTkFrame):
        self.page = page_frame
        self.button: Optional[ctk.CTkButton] = None
        self._win: Optional[ctk.CTkToplevel] = None  # keep ref to prevent GC

        # Optional override profile (from app.master.user_overview)
        self._override_profile: Optional[Dict[str, Any]] = None

    # ---------- Public ----------

    def mount(self, top_right_of: ctk.CTkFrame) -> None:
        """Attach the round avatar button to the top-right of the given frame."""
        self.button = ctk.CTkButton(
            top_right_of,
            text="👤",
            width=36,
            height=36,
            corner_radius=18,
            fg_color="#2A3342",     # subtle plate so it pops on dark bg
            hover_color="#374357",
            text_color=TEXT,
            border_width=1,
            border_color=BORDER,
            command=self._toggle_window,
        )
        # place() so layout of the page (grid/pack) doesn't move it
        self.button.place(relx=1.0, x=-16, y=16, anchor="ne")

    def refresh(self, profile: Optional[Dict[str, Any]] = None) -> None:
        """
        Optionally override the profile (from user_overview etc.).

        profile keys:
            full_name, email, role (str or list), plan

        Passing None clears the override and returns to Supabase/fallback mode.
        """
        self._override_profile = profile or None
        # If window is currently open, rebuild with the new data
        if self._win and self._win.winfo_exists():
            self._build_window_contents()

    # ---------- Internals: window + data ----------

    def _toggle_window(self) -> None:
        if self._win and self._win.winfo_exists():
            # Toggle visibility
            if self._win.state() == "normal":
                self._win.withdraw()
            else:
                self._win.deiconify()
                self._win.focus_force()
            return

        # Create window
        self._win = ctk.CTkToplevel(self.page)
        self._win.title("Account")
        self._win.configure(fg_color=BG)
        self._win.geometry("380x280+60+60")
        self._win.resizable(False, False)
        try:
            self._win.attributes("-topmost", True)
            self._win.after(120, lambda: self._win.attributes("-topmost", False))
        except Exception:
            pass

        self._win.bind("<Escape>", lambda e: self._safe_close())

        # Build UI contents based on current profile data
        self._build_window_contents()

    def _build_window_contents(self) -> None:
        if not self._win or not self._win.winfo_exists():
            return

        # Clear old children
        for child in self._win.winfo_children():
            child.destroy()

        profile = self._resolve_profile_data()

        wrap = ctk.CTkFrame(
            self._win,
            fg_color=CARD_BG,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
        )
        wrap.pack(fill="both", expand=True, padx=12, pady=12)

        title = ctk.CTkLabel(
            wrap,
            text="Account",
            font=("Segoe UI", 16, "bold"),
            text_color=TEXT,
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(12, 2))

        # Plan / tier
        self._kv(wrap, row=1, key="Plan", value=profile["plan"])
        # Name
        self._kv(wrap, row=2, key="Name", value=profile["full_name"])
        # Email
        self._kv(wrap, row=3, key="Email", value=profile["email"])

        # Buttons row
        btn_row = ctk.CTkFrame(wrap, fg_color="transparent")
        btn_row.grid(row=99, column=0, columnspan=2, sticky="e", padx=12, pady=(16, 12))
        ctk.CTkButton(
            btn_row,
            text="Close",
            width=86,
            height=30,
            corner_radius=8,
            fg_color="transparent",
            text_color=TEXT,
            border_width=1,
            border_color=BORDER,
            hover_color="#243244",
            command=self._safe_close,
        ).pack(side="right")

    def _kv(self, parent: ctk.CTkFrame, row: int, key: str, value: str) -> None:
        ctk.CTkLabel(
            parent,
            text=key,
            font=("Segoe UI", 12, "bold"),
            text_color=MUTED,
        ).grid(
            row=row,
            column=0,
            sticky="w",
            padx=12,
            pady=(8 if row == 1 else 4, 0),
        )
        ctk.CTkLabel(
            parent,
            text=value or "—",
            font=("Segoe UI", 13),
            text_color=TEXT,
        ).grid(
            row=row,
            column=1,
            sticky="w",
            padx=12,
            pady=(8 if row == 1 else 4, 0),
        )

    def _safe_close(self) -> None:
        try:
            if self._win and self._win.winfo_exists():
                self._win.destroy()
        finally:
            self._win = None

    # ---------- Data resolution ----------

    def _resolve_profile_data(self) -> Dict[str, str]:
        """
        Decide what to show:
          1) Override profile (from refresh())
          2) App.fetch_user_profile()
          3) App current_user/current_user_role
        """
        # 1) Override from page/app
        if self._override_profile is not None:
            p = self._override_profile or {}
            roles_val = p.get("role")
            if isinstance(roles_val, (list, tuple)):
                roles_str = ", ".join(str(r) for r in roles_val)
            else:
                roles_str = roles_val or ""

            plan = p.get("plan") or roles_str or "free"
            return {
                "plan": str(plan).capitalize(),
                "full_name": p.get("full_name") or "—",
                "email": p.get("email") or "—",
            }

        # 2) Ask the app for its current profile snapshot
        app = self.page.winfo_toplevel()
        profile: Dict[str, Any] = {}
        if hasattr(app, "fetch_user_profile"):
            try:
                profile = app.fetch_user_profile() or {}
            except Exception:
                profile = {}

        if profile:
            role = profile.get("role")
            plan = profile.get("plan") or role or "free"
            return {
                "plan": str(plan).capitalize(),
                "full_name": profile.get("full_name") or "—",
                "email": profile.get("email") or "—",
            }

        # 3) Final fallback: use app.current_user/current_user_role
        role = self._fallback_role()
        email = self._fallback_email()
        full_name = self._fallback_full_name()

        plan_text = str(role).capitalize() if role else "Free"
        return {
            "plan": plan_text,
            "full_name": full_name or "—",
            "email": email or "—",
        }


    def _fetch_account_overview(self) -> Dict[str, Any]:
        """
        Try Supabase: SELECT email, full_name, role FROM user_overview WHERE uid = <uid>
        Fallback to app.current_user/app.current_user_role.
        """
        app = self.page.winfo_toplevel()

        # Resolve uid from app
        uid = getattr(app, "current_user_uid", None)
        user = getattr(app, "current_user", None)
        if not uid and isinstance(user, dict):
            uid = user.get("uid") or user.get("id")

        # If we can’t resolve uid, we can’t query the view.
        if not uid:
            return {}

        if not _SUPABASE_READY:
            return {}

        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_ANON_KEY")
        if not url or not key:
            return {}

        try:
            supabase = create_client(url, key)
            resp = (
                supabase.table("user_overview")
                .select("email, full_name, role")
                .eq("uid", uid)
                .single()
                .execute()
            )
            if resp and getattr(resp, "data", None):
                row = dict(resp.data)
                return {
                    "email": row.get("email"),
                    "full_name": row.get("full_name"),
                    "role": row.get("role") or row.get("roles"),
                }
        except Exception:
            # Swallow and fallback gracefully
            pass
        return {}

    # ---------- Fallbacks ----------

    def _fallback_role(self) -> str:
        app = self.page.winfo_toplevel()
        role = getattr(app, "current_user_role", None)
        if role:
            return str(role)
        user = getattr(app, "current_user", None)
        if isinstance(user, dict):
            return str(user.get("role") or user.get("roles") or "free")
        return "free"

    def _fallback_email(self) -> Optional[str]:
        user = getattr(self.page.winfo_toplevel(), "current_user", None)
        if isinstance(user, dict):
            return user.get("email")
        return None

    def _fallback_full_name(self) -> Optional[str]:
        user = getattr(self.page.winfo_toplevel(), "current_user", None)
        if isinstance(user, dict):
            return user.get("full_name") or user.get("username")
        return None
