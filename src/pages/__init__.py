"""Pages package (moved from top-level `pages/`)."""

from .advisor import AdvisorPage
from .analysis import AnalysisPage
from .auditor import AuditorPage
from .dashboard import DashboardPage
from .login import LoginPage
from .register import RegisterPage
from .reports import ReportsPage
from .landing import LandingPage

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
