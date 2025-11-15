"""Top-level app runner moved under src for packaging.""" 

from pathlib import Path

import customtkinter as ctk

from file_handler import FileHandler
from pages import (
    AuditorPage,
    DashboardPage,
    LoginPage,
    RegisterPage,
    VerifyEmailPage,
    LandingPage
)
from pages import SetupPage, DetectorsPage, ResultsPage


class App(ctk.CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("CryptoScope")
        self.geometry("1200x800")
        self.minsize(900, 600)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Auth-related state (you already effectively have these)
        self.auth_token = None
        self.current_user = None       # dict from Supabase login
        self.user_overview = None      # row from user_overview view
        self.FREE_SCAN_LIMIT = 5       # default free-tier limit


        # --- Free vs premium scan quota (per app session) ---
        # Free users: limited scans.
        # Premium users: unlimited.
        self.scan_usage = 0          # how many scans completed this session
        self.scan_limit_free = 5     # free-tier limit
        self.plan = "Free"           # default; overridden by Supabase user_overview.plan when available

        # Use pathlib.Path for cross-platform paths
        uploads_dir = Path(".") / "uploads"
        self.file_handler = FileHandler(upload_dir=uploads_dir)

        # --- Instantiate pages ---
        self._pages = {
            "login": LoginPage(self, self.switch_page),
            "register": RegisterPage(self, self.switch_page),
            "verify_email": VerifyEmailPage(self, self.switch_page),
            "dashboard": DashboardPage(self, self.switch_page, self.file_handler),
            "landing": LandingPage(self, self.switch_page),  # ← NEW
            "setup": SetupPage(self, self.switch_page),
            "detectors": DetectorsPage(self, self.switch_page),
            "auditor": AuditorPage(self, self.switch_page),
            "results": ResultsPage(self, self.switch_page),
        }

        for p in self._pages.values():
            p.grid(row=0, column=0, sticky="nsew")
            p.grid_remove()

        # --- Start on Login (not dashboard) ---
        self._current_page_name = "login"
        self.switch_page(self._current_page_name)

        # Debounced resize handling
        self._resize_job = None
        self.bind("<Configure>", self._on_configure)

        # Clean shutdown
        self._closing = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -------- Navigation --------
            # -------- Navigation --------
    def switch_page(self, name: str):
        """Central navigation helper.

        Also clears scan context when returning to the Landing page so that
        Detectors/Results reopen in standalone mode (no stale pipeline state).
        """
        if name == "landing":
            # Drop any pipeline-driven scan metadata from Setup
            self.current_scan_meta = None

            # Detectors: forget the case loaded from Setup
            det = self._pages.get("detectors")
            if det is not None:
                try:
                    # These attributes already exist on DetectorsPage
                    det._standalone_mode = True
                    det._loaded_case_workdir = None
                except Exception:
                    pass

            # Results: forget the case/file loaded from Detectors
            res = self._pages.get("results")
            if res is not None:
                try:
                    # These attributes already exist on ResultsPage
                    res.case_path = None
                    res.file_hash = None
                    res._standalone_mode = True
                    res._loaded_case_workdir = None
                except Exception:
                    pass

        self._current_page_name = name
        for n, page in self._pages.items():
            if n == name:
                page.grid()
                if hasattr(page, "on_enter"):
                    try:
                        page.on_enter()
                    except Exception:
                        pass
            else:
                page.grid_remove()

    # -------- Logout (clear state, reset pages, go to login) --------
    def logout(self):
        """Log out the current user and return to the login page."""

        # Clear auth + plan/session state
        self.auth_token = None
        self.current_user_role = "free"
        self.current_user_email = None
        self.current_scan_meta = None

        # Optional: reset free-tier scan usage
        try:
            self.scan_usage = 0
        except Exception:
            pass

        # Let pages clear their UI if they implement reset_ui()
        for key in ("dashboard", "analysis", "login", "setup", "detectors", "results"):
            page = self._pages.get(key)
            if page and hasattr(page, "reset_ui"):
                try:
                    page.reset_ui()
                except Exception:
                    pass

        # Also drop any pipeline context so standalone tabs open fresh
        det = self._pages.get("detectors")
        if det is not None:
            try:
                det._standalone_mode = True
                det._loaded_case_workdir = None
            except Exception:
                pass

        res = self._pages.get("results")
        if res is not None:
            try:
                res.case_path = None
                res.file_hash = None
                res._standalone_mode = True
                res._loaded_case_workdir = None
            except Exception:
                pass

        # Finally, go back to the login page
        self.switch_page("login")


    # ---------- Resize (debounced) ----------
    def _on_configure(self, event):
        # Ignore noisy events triggered during closing
        if self._closing:
            return
        # Debounce: schedule a single resize after 30ms
        if self._resize_job is not None:
            try:
                self.after_cancel(self._resize_job)
            except Exception:
                pass
        # schedule resize using a callable reference
        self._resize_job = self.after(30, self._do_resize)

    def _do_resize(self):
        self._resize_job = None
        if self._closing:
            return
        page = self._pages.get(self._current_page_name)
        try:
            if page is not None and page.winfo_exists() and hasattr(page, "on_resize"):
                w, h = self.winfo_width(), self.winfo_height()
                page.on_resize(w, h)
        except Exception:
            pass

    def _on_close(self):
        self._closing = True
        if self._resize_job is not None:
            try:
                self.after_cancel(self._resize_job)
            except Exception:
                pass
            self._resize_job = None
        self.destroy()

    def fetch_user_profile(self):
        """
        Return dict: {full_name, email, role, plan}.
        Prefer self.user_overview from Supabase if present.
        """
        try:
            u = getattr(self, "user_overview", None) or {}
            roles_val = u.get("roles")
            if isinstance(roles_val, (list, tuple)):
                roles_str = ", ".join(str(r) for r in roles_val)
            else:
                roles_str = roles_val or ""

            plan_val = u.get("plan") or getattr(self, "plan", "Free")

            return {
                "full_name": u.get("full_name") or u.get("name") or "User",
                "email": u.get("email", ""),
                "role": roles_str or getattr(self, "current_user_role", "free"),
                "plan": plan_val,
            }
        except Exception:
            return {
                "full_name": "User",
                "email": "",
                "role": getattr(self, "current_user_role", "free"),
                "plan": getattr(self, "plan", "Free"),
            }

        
    # ---------------------------------------------------------------
    # Quota helpers
    # ---------------------------------------------------------------
    def _get_quota_state(self) -> dict:
        """
        Canonical view of the current user's quota state.

        Returns:
            {
              "tier": "free" | "premium" | "admin",
              "count": int,   # analysis_count used so far
              "limit": int,   # analysis_quota_limit (or FREE_SCAN_LIMIT)
            }
        """
        uo = getattr(self, "user_overview", None) or {}

        # Tier: prefer user_overview.tier, fall back to current_user_role
        tier = (uo.get("tier") or getattr(self, "current_user_role", "free") or "free").lower()

        # Count: how many scans used so far
        try:
            count = int(uo.get("analysis_count") or 0)
        except Exception:
            count = 0

        # Limit: per-account quota; fall back to FREE_SCAN_LIMIT
        try:
            limit = int(
                uo.get("analysis_quota_limit")
                or getattr(self, "FREE_SCAN_LIMIT", 5)
                or 5
            )
        except Exception:
            limit = getattr(self, "FREE_SCAN_LIMIT", 5) or 5

        # For premium/admin, limit is conceptually "infinite",
        # but we still return the DB limit for display if needed.
        return {
            "tier": tier,
            "count": count,
            "limit": limit,
        }

    def can_run_scan(self) -> tuple[bool, str]:
        """
        Called by DetectorsPage before starting analysis.

        Returns:
            (allowed: bool, message: str)

        - Premium/Admin: always allowed, no limit.
        - Free: allowed only while analysis_count < analysis_quota_limit.
        - Does NOT increment anything; it is read-only.
        """
        qs = self._get_quota_state()
        tier = qs["tier"]
        used = qs["count"]
        limit = qs["limit"]

        # Premium/admin = unlimited scans
        if tier in ("premium", "admin"):
            return True, ""  # no quota message needed

        # Free tier
        if used >= limit:
            # Hard block: quota exhausted
            msg = f"You've used all {limit} free scans for this account."
            return False, msg

        remaining = limit - used
        msg = f"Free plan: {used}/{limit} scans used ({remaining} remaining)."
        return True, msg

    def record_scan_completed(self) -> None:
        """
        Called by DetectorsPage AFTER a batch finishes successfully.

        - Premium/Admin: no DB changes.
        - Free: increment analysis_count in Supabase and refresh user_overview.
        """
        qs = self._get_quota_state()
        tier = qs["tier"]

        # Premium/admin → unlimited scans, no bookkeeping needed
        if tier in ("premium", "admin"):
            return

        # Local pessimistic bump so the UI can show updated count immediately
        new_local_count = (qs["count"] or 0) + 1
        if self.user_overview is None:
            self.user_overview = {}

        self.user_overview["analysis_count"] = new_local_count

        # Best-effort push to Supabase
        token = getattr(self, "auth_token", None)
        user = getattr(self, "current_user", None) or {}
        uid = user.get("id")

        if not token or not uid:
            # Can't sync to backend; local count will still prevent runaway scans
            return

        try:
            from api_client_supabase import increment_analysis_count

            updated = increment_analysis_count(token, uid)
            if isinstance(updated, dict):
                # Replace/merge the latest view row so Detectors + AccountBubble see fresh data
                self.user_overview.update(updated)
        except Exception:
            # Never let quota bookkeeping crash the app
            import logging
            logging.getLogger(__name__).warning(
                "record_scan_completed: failed to update Supabase",
                exc_info=True,
            )


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    App().mainloop()
