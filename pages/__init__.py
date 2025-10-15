"""Package export for UI pages.

This module exposes the main CTk Frame classes used by `app.py` so the
application can instantiate pages with a stable import.
"""

from .advisor import AdvisorPage
from .analysis import AnalysisPage
from .auditor import AuditorPage
from .dashboard import DashboardPage
from .login import LoginPage
from .register import RegisterPage

__all__ = [
    "LoginPage",
    "RegisterPage",
    "DashboardPage",
    "AnalysisPage",
    "AdvisorPage",
    "AuditorPage",
]
