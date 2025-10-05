# pages/__init__.py
from .login import LoginPage
from .register import RegisterPage
from .dashboard import DashboardPage
from .analysis import AnalysisPage
from .advisor import AdvisorPage

__all__ = ["LoginPage", "RegisterPage", "DashboardPage", "AnalysisPage", "AdvisorPage"]
