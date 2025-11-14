"""Run and manage heuristics.

This manager calls heuristics sequentially (sufficient for the quick-profile)
and passes both the ghidra export and lightweight static preproc artifacts to
each heuristic callable. Includes ENFORCED timeout protection to prevent hangs.
"""
from typing import List, Dict, Callable, Any, Optional
import logging
import time
import threading

logger = logging.getLogger(__name__)


def _run_heuristic_with_thread_timeout(
    heuristic_func: Callable,
    args: tuple,
    timeout_sec: float,
    heuristic_name: str
) -> tuple:
    """Run heuristic in a thread with timeout enforcement.

    Uses threading to enforce timeouts - if heuristic exceeds timeout,
    the calling thread continues and heuristic is abandoned.

    Returns:
        Tuple of (result, elapsed_sec, timed_out)
    """
    result = [None]
    exception = [None]
    completed = [False]

    def target():
        try:
            result[0] = heuristic_func(*args)
            completed[0] = True
        except Exception as e:
            exception[0] = e
            completed[0] = True

    start_time = time.time()
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=timeout_sec)

    elapsed = time.time() - start_time
    timed_out = thread.is_alive()

    if timed_out:
        logger.warning(
            f"⏱️ [HEURISTICS] {heuristic_name} TIMEOUT after {elapsed:.1f}s "
            f"(exceeded {timeout_sec}s limit). Skipping findings from this heuristic."
        )
        return (None, elapsed, True)

    if exception[0]:
        logger.warning(
            f"[HEURISTICS] {heuristic_name} FAILED after {elapsed:.1f}s: "
            f"{type(exception[0]).__name__}: {str(exception[0])[:100]}"
        )
        return (None, elapsed, False)

    if completed[0]:
        return (result[0], elapsed, False)

    # Should not reach here, but if we do:
    logger.error(f"[HEURISTICS] {heuristic_name} in unknown state after {elapsed:.1f}s")
    return (None, elapsed, False)


def run_heuristics(
    ghidra_export: Dict,
    metadata: Dict,
    heuristics: List[Callable],
    static_artifacts: Dict[str, Any] = None,
    timeout_sec: float = 30.0,
    diag_tracker = None
) -> List[Dict]:
    """Run provided heuristics with ENFORCED timeout protection.

    Each heuristic is expected to be a callable with signature:
        heuristic(ghidra_export, metadata, static_artifacts) -> List[Finding]

    TIMEOUT ENFORCEMENT: If a heuristic exceeds the timeout, it is abandoned
    and the next heuristic runs immediately. This prevents any single heuristic
    from blocking the entire pipeline.

    Args:
        ghidra_export: Ghidra analysis export data
        metadata: File metadata
        heuristics: List of heuristic callables to run
        static_artifacts: Optional static preproc artifacts
        timeout_sec: Maximum time per heuristic in seconds (default 30s)
        diag_tracker: Optional diagnostic tracker for logging heuristic timings

    Returns:
        Flattened list of findings from all heuristics (excludes timed-out heuristics)
    """
    findings = []
    stage_start = time.time()

    for h in heuristics:
        heuristic_name = getattr(h, "__name__", str(h))

        # Run with enforced timeout using threading
        result, elapsed, timed_out = _run_heuristic_with_thread_timeout(
            h, (ghidra_export, metadata, static_artifacts), timeout_sec, heuristic_name
        )

        if timed_out:
            # Heuristic timed out - record and continue
            logger.warning(
                f"[HEURISTICS] ⏱️ {heuristic_name} TIMED OUT ({elapsed:.1f}s > {timeout_sec}s). "
                f"This heuristic's findings will not be included."
            )
            if diag_tracker:
                diag_tracker.log_heuristic_timing(heuristic_name, elapsed, status="timeout_enforced")
            continue
        elif result is None:
            # Heuristic failed or errored
            logger.debug(f"[HEURISTICS] {heuristic_name} returned no findings (in {elapsed:.1f}s)")
            if diag_tracker:
                diag_tracker.log_heuristic_timing(heuristic_name, elapsed, status="no_findings")
            continue
        else:
            # Heuristic succeeded
            logger.info(
                f"[HEURISTICS] ✓ {heuristic_name} completed in {elapsed:.2f}s "
                f"({len(result)} findings)"
            )
            if diag_tracker:
                diag_tracker.log_heuristic_timing(heuristic_name, elapsed, status="completed")
            if result:
                findings.extend(result)

    stage_elapsed = time.time() - stage_start
    logger.info(
        f"[HEURISTICS] All heuristics completed in {stage_elapsed:.2f}s "
        f"({len(findings)} total findings)"
    )

    return findings
