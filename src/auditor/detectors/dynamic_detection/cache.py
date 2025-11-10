"""
Cache management for dynamic detection.

Implements intelligent caching with TTL, tool version checking,
and configuration validation to avoid stale results.
"""

import json
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from .context import DynamicContext, ToolVersions


def get_cache_meta_path(analysis_dir: str) -> str:
    """
    Get path to cache metadata file.

    Args:
        analysis_dir: Analysis directory (e.g., analysis/dynamic/<hash>/)

    Returns:
        Path to .cache_meta.json
    """
    return os.path.join(analysis_dir, '.cache_meta.json')


def compute_config_hash(ctx: DynamicContext) -> str:
    """
    Compute hash of configuration parameters.

    This ensures cache is invalidated when config changes.

    Args:
        ctx: Dynamic analysis context

    Returns:
        SHA256 hash of configuration
    """
    config_str = json.dumps({
        'mode': ctx.mode,
        'timeout': ctx.timeout,
        'memory_limit': ctx.memory_limit,
        'instrumenters': ctx.instrumenters
    }, sort_keys=True)

    return hashlib.sha256(config_str.encode()).hexdigest()


def should_use_cache(ctx: DynamicContext, analysis_dir: str, ttl_hours: int = 24) -> bool:
    """
    Determine if cached results should be used.

    Checks:
    1. Cache file exists
    2. TTL not expired
    3. Tool versions match
    4. Configuration matches
    5. Not incomplete (or has shorter TTL if incomplete)
    6. Force flag not set

    Args:
        ctx: Dynamic analysis context
        analysis_dir: Analysis directory
        ttl_hours: Cache TTL in hours (default: 24)

    Returns:
        True if cache should be used, False otherwise
    """
    # Force re-run
    if ctx.force:
        return False

    # Check cache meta file exists
    cache_meta_path = get_cache_meta_path(analysis_dir)
    if not os.path.exists(cache_meta_path):
        return False

    # Check results file exists
    results_path = os.path.join(analysis_dir, 'dynamic_results.json')
    if not os.path.exists(results_path):
        return False

    # Load cache metadata
    try:
        with open(cache_meta_path, 'r') as f:
            cache_meta = json.load(f)
    except (json.JSONDecodeError, IOError):
        return False

    # Check TTL
    timestamp_str = cache_meta.get('timestamp')
    if not timestamp_str:
        return False

    try:
        cached_time = datetime.fromisoformat(timestamp_str)
        current_time = datetime.now()

        # Use shorter TTL for incomplete results (1 hour)
        if cache_meta.get('incomplete', False):
            effective_ttl = timedelta(hours=1)
        else:
            effective_ttl = timedelta(hours=ttl_hours)

        if current_time - cached_time > effective_ttl:
            return False
    except ValueError:
        return False

    # Check tool versions
    cached_versions = cache_meta.get('tool_versions', {})
    current_versions = {
        'frida': ctx.tool_versions.frida,
        'python': ctx.tool_versions.python,
        'detector_version': ctx.tool_versions.detector_version
    }

    # Only check detector version (frida/python can vary)
    if cached_versions.get('detector_version') != current_versions['detector_version']:
        return False

    # Check config hash
    cached_config_hash = cache_meta.get('config_hash')
    current_config_hash = compute_config_hash(ctx)

    if cached_config_hash != current_config_hash:
        return False

    # All checks passed
    return True


def write_cache_meta(ctx: DynamicContext, analysis_dir: str, incomplete: bool = False, incomplete_reason: Optional[str] = None):
    """
    Write cache metadata file.

    Args:
        ctx: Dynamic analysis context
        analysis_dir: Analysis directory
        incomplete: Whether run was incomplete
        incomplete_reason: Reason for incomplete run
    """
    cache_meta = {
        'file_hash': ctx.file_hash,
        'timestamp': datetime.now().isoformat(),
        'ttl_hours': 1 if incomplete else 24,  # Shorter TTL for incomplete
        'tool_versions': {
            'frida': ctx.tool_versions.frida,
            'python': ctx.tool_versions.python,
            'detector_version': ctx.tool_versions.detector_version,
            'platform': ctx.tool_versions.platform
        },
        'config_hash': compute_config_hash(ctx),
        'mode': ctx.mode,
        'incomplete': incomplete,
        'incomplete_reason': incomplete_reason
    }

    cache_meta_path = get_cache_meta_path(analysis_dir)

    # Ensure directory exists
    os.makedirs(analysis_dir, exist_ok=True)

    # Atomic write
    temp_path = cache_meta_path + '.tmp'
    with open(temp_path, 'w') as f:
        json.dump(cache_meta, f, indent=2)

    # Rename to final path (atomic on most systems)
    if os.path.exists(cache_meta_path):
        os.remove(cache_meta_path)
    os.rename(temp_path, cache_meta_path)


def invalidate_cache(analysis_dir: str):
    """
    Invalidate cached results by removing cache metadata.

    Args:
        analysis_dir: Analysis directory
    """
    cache_meta_path = get_cache_meta_path(analysis_dir)
    if os.path.exists(cache_meta_path):
        os.remove(cache_meta_path)


def get_cache_info(analysis_dir: str) -> Optional[Dict[str, Any]]:
    """
    Get cache metadata if available.

    Args:
        analysis_dir: Analysis directory

    Returns:
        Cache metadata dictionary or None if not cached
    """
    cache_meta_path = get_cache_meta_path(analysis_dir)
    if not os.path.exists(cache_meta_path):
        return None

    try:
        with open(cache_meta_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None
