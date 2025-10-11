"""Package export for UI pages.

This module exposes the main CTk Frame classes used by `app.py` so the
application can instantiate pages with a stable import.
"""

from .login import LoginPage
from .register import RegisterPage
from .dashboard import DashboardPage
from .analysis import AnalysisPage
from .advisor import AdvisorPage

__all__ = ["LoginPage", "RegisterPage", "DashboardPage", "AnalysisPage", "AdvisorPage"]
