"""Pages package (moved from top-level `pages/`)."""

from .advisor import AdvisorPage
from .analysis import AnalysisPage
from .dashboard import DashboardPage
from .detectors import DetectorsPage
from .login import LoginPage
from .register import RegisterPage
from .setup import SetupPage

__all__ = [
    "AnalysisPage",
    "DashboardPage",
    "SetupPage",
    "DetectorsPage",
    "LoginPage",
    "RegisterPage",
    "AdvisorPage",
]
