"""
Dynamic detection module for Frida-based runtime analysis.

This module provides dynamic analysis capabilities to detect
cryptographic operations at runtime by instrumenting Windows PE
binaries with Frida.

Public API:
    DynamicRunner - Main orchestrator
    DynamicContext - Input context
    DynamicResult - Output result
    run_dynamic_analysis - Convenience function

Example usage:
    from src.auditor.detectors.dynamic_detection import DynamicRunner, DynamicContext

    # Create context
    ctx = DynamicContext(
        file_hash="abc123...",
        preproc_dir="/workdir/preproc/abc123",
        hints_path="/workdir/analysis/static/abc123/hints.json",
        analysis_base="/workdir",
        mode="spawn",
        timeout=500
    )

    # Run analysis
    runner = DynamicRunner()
    result = runner.run(ctx)

    # Check result
    if result.is_success():
        print(f"Results: {result.dynamic_results_path}")
    else:
        print(f"Errors: {result.errors}")
"""

from .runner import DynamicRunner, run_dynamic_analysis
from .context import DynamicContext, DynamicResult, ToolVersions, TraceEvent, TraceSummary
from .config import Config, load_dynamic_config, get_default_config

__version__ = "0.1.0"

__all__ = [
    # Main classes
    "DynamicRunner",
    "DynamicContext",
    "DynamicResult",

    # Data structures
    "ToolVersions",
    "TraceEvent",
    "TraceSummary",

    # Configuration
    "Config",
    "load_dynamic_config",
    "get_default_config",

    # Convenience functions
    "run_dynamic_analysis",

    # Version
    "__version__",
]
