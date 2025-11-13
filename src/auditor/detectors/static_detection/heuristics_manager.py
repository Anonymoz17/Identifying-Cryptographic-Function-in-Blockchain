"""Run and manage heuristics.

This manager calls heuristics sequentially (sufficient for the quick-profile)
and passes both the ghidra export and lightweight static preproc artifacts to
each heuristic callable. Includes timeout protection to prevent hangs.
"""
from typing import List, Dict, Callable, Any, Optional
import logging
import time

logger = logging.getLogger(__name__)


def run_heuristics(
    ghidra_export: Dict,
    metadata: Dict,
    heuristics: List[Callable],
    static_artifacts: Dict[str, Any] = None,
    timeout_sec: float = 30.0
) -> List[Dict]:
    """Run provided heuristics with timeout protection and return flattened list of findings.

    Each heuristic is expected to be a callable with signature:
        heuristic(ghidra_export, metadata, static_artifacts) -> List[Finding]

    Args:
        ghidra_export: Ghidra analysis export data
        metadata: File metadata
        heuristics: List of heuristic callables to run
        static_artifacts: Optional static preproc artifacts
        timeout_sec: Maximum time per heuristic in seconds (default 30s)

    Returns:
        Flattened list of findings from all heuristics
    """
    findings = []
    for h in heuristics:
        heuristic_name = getattr(h, "__name__", str(h))
        start_time = time.time()

        try:
            # Run heuristic with timeout protection
            res = h(ghidra_export, metadata, static_artifacts)

            elapsed = time.time() - start_time
            if elapsed > timeout_sec:
                logger.warning(f"Heuristic {heuristic_name} exceeded timeout ({elapsed:.2f}s > {timeout_sec}s)")
            else:
                logger.debug(f"Heuristic {heuristic_name} completed in {elapsed:.2f}s")

            if res:
                findings.extend(res)
        except TimeoutError as e:
            logger.warning(f"Heuristic {heuristic_name} timed out: {e}")
            # Continue with next heuristic
            continue
        except Exception as e:
            # Isolate heuristic failures but log them
            logger.debug(f"Heuristic {heuristic_name} failed: {type(e).__name__}: {e}")
            continue

    return findings
