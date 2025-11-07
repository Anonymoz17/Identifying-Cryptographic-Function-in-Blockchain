"""Ghidra execution policy - determines when Ghidra should be invoked.

This module provides logic to decide whether to run Ghidra analysis based on
file characteristics like type, size, and format. The goal is to optimize
performance by skipping Ghidra for files where it provides no value (source code)
while ensuring it runs on relevant binaries (executables, compiled contracts).
"""
from typing import Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# Maximum binary size for Ghidra analysis (5MB default)
MAX_BINARY_SIZE_BYTES = 5 * 1024 * 1024

# MIME types that should NEVER use Ghidra (source code, configs, etc.)
SOURCE_CODE_MIMES = {
    "text/x-python",
    "text/x-script.python",
    "application/x-python",
    "text/javascript",
    "application/javascript",
    "application/json",
    "text/x-java",
    "text/x-c",
    "text/x-c++",
    "text/x-go",
    "text/x-rust",
    "text/plain",
    "text/x-solidity",  # Solidity source
    "text/x-yaml",
    "application/xml",
    "text/html",
    "text/css",
}

# MIME types that SHOULD use Ghidra (compiled binaries)
BINARY_MIMES = {
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/x-elf",
    "application/x-dosexec",  # Windows PE
    "application/octet-stream",  # Generic binary (could be EVM bytecode)
}


def should_run_ghidra(metadata: Dict, max_size_bytes: int = MAX_BINARY_SIZE_BYTES) -> Tuple[bool, str]:
    """Determine if Ghidra should run on this file based on metadata.
    
    Args:
        metadata: Parsed metadata.json dict containing file info
        max_size_bytes: Maximum file size to analyze (default 5MB)
    
    Returns:
        Tuple of (should_run: bool, reason: str)
        
    Decision logic:
        1. If is_binary=False → Skip (source code)
        2. If MIME is source code → Skip
        3. If size > max_size → Skip (too large)
        4. If MIME is known binary type → Run
        5. If is_binary=True but unknown MIME → Run (cautious)
    """
    # Extract relevant fields
    is_binary = metadata.get("is_binary", False)
    mime = metadata.get("mime", "").lower()
    size = metadata.get("size", 0)
    
    # Rule 1: Explicit non-binary flag
    if not is_binary:
        return False, f"is_binary=False (source code, mime={mime})"
    
    # Rule 2: Source code MIME types
    if mime in SOURCE_CODE_MIMES:
        return False, f"Source code MIME type: {mime}"
    
    # Rule 3: File too large
    if size > max_size_bytes:
        size_mb = size / (1024 * 1024)
        max_mb = max_size_bytes / (1024 * 1024)
        return False, f"Binary too large: {size_mb:.1f}MB > {max_mb:.1f}MB limit"
    
    # Rule 4: Known binary MIME types
    if mime in BINARY_MIMES:
        return True, f"Binary executable (mime={mime}, size={size} bytes)"
    
    # Rule 5: Unknown but marked as binary - analyze conservatively
    if is_binary:
        logger.warning(f"Unknown binary MIME type '{mime}', running Ghidra conservatively")
        return True, f"Unknown binary type (mime={mime}, size={size} bytes)"
    
    # Default: skip
    return False, f"Does not match binary criteria (mime={mime}, is_binary={is_binary})"


def log_ghidra_decision(file_hash: str, should_run: bool, reason: str):
    """Log the Ghidra execution decision for debugging/transparency.
    
    Args:
        file_hash: File hash being analyzed
        should_run: Whether Ghidra will run
        reason: Explanation for the decision
    """
    action = "RUNNING" if should_run else "SKIPPING"
    logger.info(f"Ghidra decision for {file_hash[:8]}...: {action} - {reason}")
