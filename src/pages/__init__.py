"""Pages package (moved from top-level `pages/`)."""

from .advisor import AdvisorPage
from .analysis import AnalysisPage
from .dashboard import DashboardPage
from .detectors import DetectorsPage
from .login import LoginPage
from .register import RegisterPage
from .reports import ReportsPage
from .results import ResultsPage
from .setup import SetupPage

__all__ = [
    "AnalysisPage",
    "DashboardPage",
    "SetupPage",
    "DetectorsPage",
    "ResultsPage",
    "LoginPage",
    "RegisterPage",
    "ReportsPage",
    "AdvisorPage",
]
