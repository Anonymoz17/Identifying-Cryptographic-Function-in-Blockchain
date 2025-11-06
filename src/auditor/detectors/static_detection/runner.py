"""StaticRunner orchestrator (skeleton).

The real runner wires adapters, preproc, ghidra, heuristics, scoring, and
packaging. This is a small stub exposing the eventual run API.
"""
from typing import Any

from .context import RunContext, RunResult


class StaticRunner:
    """Orchestrator for static detection runs.

    Public API: run(context: RunContext) -> RunResult
    """

    def __init__(self) -> None:
        # add dependencies or configuration here in future
        pass

    def run(self, ctx: RunContext) -> RunResult:
        """Run a static detection flow for the given RunContext.

        Currently a stub that raises NotImplementedError. The final
        implementation will ensure caching, call ghidra_adapter,
        heuristics_manager, scoring, and packaging.
        """
        raise NotImplementedError("StaticRunner.run is not implemented yet")
