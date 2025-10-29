"""Pages package (moved from top-level `pages/`)."""

from .advisor import AdvisorPage
from .analysis import AnalysisPage
from .auditor import AuditorPage
from .dashboard import DashboardPage
from .login import LoginPage
from .pipeline import PipelinePage
from .register import RegisterPage
from .reports import ReportsPage

__all__ = [
    "AnalysisPage",
    "AuditorPage",
    "DashboardPage",
    "PipelinePage",
    "LoginPage",
    "RegisterPage",
    "ReportsPage",
    "AdvisorPage",
]
