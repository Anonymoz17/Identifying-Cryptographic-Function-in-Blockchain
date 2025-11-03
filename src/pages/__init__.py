"""Pages package (moved from top-level `pages/`)."""

from .advisor import AdvisorPage
from .auditor import AuditorPage
from .dashboard import DashboardPage
from .landing import LandingPage
from .login import LoginPage
from .register import RegisterPage
from .reports import ReportsPage

__all__ = [
    "AnalysisPage",
    "AuditorPage",
    "DashboardPage",
    "LoginPage",
    "RegisterPage",
    "ReportsPage",
    "AdvisorPage",
    "LandingPage",
]
