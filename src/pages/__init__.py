"""Pages package (moved from top-level `pages/`).

This module exposes page classes but avoids hard failures when optional
dependencies are missing (for example the old `core` package). Pages are
imported safely; if a submodule fails to import we provide a lightweight
placeholder page class so importing `pages` won't raise ModuleNotFoundError.
"""

from importlib import import_module
from typing import Callable

import customtkinter as ctk


def _safe_import(module_name: str, symbol: str):
    """Try to import `symbol` from `.module_name`; return a safe fallback
    class if import fails.
    """
    try:
        mod = import_module(f".{module_name}", package=__name__)
        return getattr(mod, symbol)
    except Exception as exc:  # pragma: no cover - runtime resilience

        class _MissingPage(ctk.CTkFrame):
            def __init__(self, master, *args, **kwargs):
                super().__init__(master, fg_color="transparent")
                # show an inline message but avoid crashing during import
                try:
                    ctk.CTkLabel(
                        self,
                        text=f"{symbol} unavailable: {exc}",
                        text_color="#f88",
                        wraplength=480,
                    ).pack(padx=12, pady=12)
                except Exception:
                    pass

        return _MissingPage


# Pages the application expects; missing modules yield placeholder pages.
AdvisorPage = _safe_import("advisor", "AdvisorPage")
AnalysisPage = _safe_import("analysis", "AnalysisPage")
AuditorPage = _safe_import("auditor", "AuditorPage")
DashboardPage = _safe_import("dashboard", "DashboardPage")
LoginPage = _safe_import("login", "LoginPage")
RegisterPage = _safe_import("register", "RegisterPage")
VerifyEmailPage = _safe_import("verify_email", "VerifyEmailPage")
SetupPage = _safe_import("setup", "SetupPage")
LandingPage = _safe_import("landing", "LandingPage")
DetectorsPage = _safe_import("detectors", "DetectorsPage")
ResultsPage = _safe_import("results", "ResultsPage")

__all__ = [
    "AnalysisPage",
    "DashboardPage",
    "SetupPage",
    "DetectorsPage",
    "LoginPage",
    "RegisterPage",
    "VerifyEmailPage",
    "AdvisorPage",
    "LandingPage",
    "ResultsPage",
]
