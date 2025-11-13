"""Phase 2 UI helpers for displaying Ghidra enrichment data.

This module provides utilities for formatting and displaying call chains,
function profiles, and context information in the Results page UI.
"""

from typing import Dict, List, Any, Optional


def format_function_signature(function_profile: Dict[str, Any]) -> str:
    """Format function signature for display.

    Args:
        function_profile: Dict with signature, parameters, calling_convention

    Returns:
        Human-readable function signature string
    """
    if not isinstance(function_profile, dict):
        return "Unknown function"

    signature = function_profile.get("signature", "")
    if signature:
        return signature

    # Fallback if no signature
    return "Function signature not available"


def format_call_chain(call_chain: List[str]) -> str:
    """Format call chain for display.

    Args:
        call_chain: List of function names from finding up to entry point

    Returns:
        Arrow-separated call chain string, e.g., "main -> crypto_init -> aes_encrypt"
    """
    if not isinstance(call_chain, list) or not call_chain:
        return "No call chain available"

    return " → ".join(call_chain)


def format_callers_list(callers: List[str]) -> str:
    """Format list of callers for display.

    Args:
        callers: List of function names that call this function

    Returns:
        Formatted string, e.g., "Called by: func1, func2, func3"
    """
    if not isinstance(callers, list) or not callers:
        return "Not called by any known function"

    return "Called by: " + ", ".join(callers[:5])


def format_callees_list(callees: List[str]) -> str:
    """Format list of callees for display.

    Args:
        callees: List of function names called by this function

    Returns:
        Formatted string, e.g., "Calls: func1, func2, func3"
    """
    if not isinstance(callees, list) or not callees:
        return "Does not call any known functions"

    return "Calls: " + ", ".join(callees[:5])


def extract_phase2_data(additional_data: Dict[str, Any]) -> Dict[str, str]:
    """Extract Phase 2 enrichment data for UI display.

    Args:
        additional_data: Dict containing enrichment data from ghidra_enrichment module

    Returns:
        Dict with formatted strings ready for display
    """
    phase2_display = {}

    # Function profile
    if "function_profile" in additional_data:
        profile = additional_data["function_profile"]
        phase2_display["signature"] = format_function_signature(profile)
        phase2_display["calling_convention"] = profile.get("calling_convention", "Unknown")
        phase2_display["size"] = f"{profile.get('size', 0)} bytes"

    # Call chain
    if "call_chain" in additional_data:
        phase2_display["call_chain"] = format_call_chain(additional_data["call_chain"])

    # Callers
    if "callers" in additional_data:
        phase2_display["callers"] = format_callers_list(additional_data["callers"])

    # Callees
    if "callees" in additional_data:
        phase2_display["callees"] = format_callees_list(additional_data["callees"])

    return phase2_display


def build_context_info_text(finding_data: Dict[str, Any]) -> str:
    """Build complete context information text for finding details display.

    Combines Phase 1 location data with Phase 2 enrichment data.

    Args:
        finding_data: Complete finding dict with additional_data

    Returns:
        Formatted multi-line string for display
    """
    additional_data = finding_data.get("additional_data", {})
    lines = []

    # === Location Info (Phase 1) ===
    lines.append("LOCATION INFO:")
    lines.append("-" * 40)

    if "address_or_range" in additional_data:
        addr_range = additional_data["address_or_range"]
        if isinstance(addr_range, dict):
            start = addr_range.get("start", "unknown")
            end = addr_range.get("end", "unknown")
            lines.append(f"  Address Range: {start} → {end}")
            if "size" in addr_range:
                lines.append(f"  Size: {addr_range['size']} bytes")
        else:
            lines.append(f"  Address: {addr_range}")

    if "section" in additional_data:
        lines.append(f"  Section: {additional_data['section']}")

    if "function_name" in additional_data:
        lines.append(f"  Function: {additional_data['function_name']}")

    # === Function Context (Phase 2) ===
    if "function_profile" in additional_data or "call_chain" in additional_data:
        lines.append("")
        lines.append("FUNCTION CONTEXT (Phase 2):")
        lines.append("-" * 40)

        phase2_data = extract_phase2_data(additional_data)

        if "signature" in phase2_data:
            lines.append(f"  Signature: {phase2_data['signature']}")

        if "calling_convention" in phase2_data:
            lines.append(f"  Calling Convention: {phase2_data['calling_convention']}")

        if "size" in phase2_data:
            lines.append(f"  Function Size: {phase2_data['size']}")

        if "call_chain" in phase2_data:
            lines.append(f"  Call Chain: {phase2_data['call_chain']}")

        if "callers" in phase2_data:
            lines.append(f"  {phase2_data['callers']}")

        if "callees" in phase2_data:
            lines.append(f"  {phase2_data['callees']}")

    return "\n".join(lines)


def get_context_summary(finding_data: Dict[str, Any]) -> str:
    """Get brief summary of context for inline display.

    Args:
        finding_data: Finding dict with additional_data

    Returns:
        Short string summarizing context, e.g., "SHA-256 in crypto_init (called from main)"
    """
    additional_data = finding_data.get("additional_data", {})
    parts = []

    # Add function name if available
    if "function_name" in additional_data:
        parts.append(f"in {additional_data['function_name']}")

    # Add calling context if available
    if "call_chain" in additional_data:
        call_chain = additional_data["call_chain"]
        if isinstance(call_chain, list) and len(call_chain) > 1:
            caller = call_chain[1] if len(call_chain) > 1 else None
            if caller:
                parts.append(f"(called from {caller})")

    if not parts:
        return "No additional context"

    return " ".join(parts)
