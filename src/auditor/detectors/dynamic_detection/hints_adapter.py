"""
Adapter to load hints from static analysis stage.

Loads and validates hints.json produced by static detection,
which guides the dynamic analysis instrumentation.
"""

import json
import os
from typing import List, Dict, Any, Optional


class HintsLoadError(Exception):
    """Raised when hints cannot be loaded."""
    pass


def load_hints(hints_path: str) -> Dict[str, Any]:
    """
    Load hints from static analysis stage.

    Args:
        hints_path: Path to hints.json file

    Returns:
        Dictionary containing hints data with structure:
        {
            "file_hash": str,
            "hints": [
                {
                    "id": str,
                    "type": str,
                    "name": str (optional),
                    "address_or_range": str (optional),
                    "confidence": float,
                    ...
                }
            ]
        }

    Raises:
        HintsLoadError: If hints cannot be loaded or are invalid
    """
    # Check file exists
    if not os.path.exists(hints_path):
        raise HintsLoadError(f"Hints file not found: {hints_path}")

    # Load JSON
    try:
        with open(hints_path, 'r') as f:
            hints_data = json.load(f)
    except json.JSONDecodeError as e:
        raise HintsLoadError(f"Invalid JSON in hints file: {e}")
    except IOError as e:
        raise HintsLoadError(f"Failed to read hints file: {e}")

    # Validate structure
    if not isinstance(hints_data, dict):
        raise HintsLoadError("Hints file must contain a JSON object")

    if 'hints' not in hints_data:
        raise HintsLoadError("Hints file missing 'hints' field")

    if not isinstance(hints_data['hints'], list):
        raise HintsLoadError("'hints' field must be a list")

    # Validate each hint
    for i, hint in enumerate(hints_data['hints']):
        if not isinstance(hint, dict):
            raise HintsLoadError(f"Hint {i} is not a dictionary")

        # Required fields
        required_fields = ['id', 'type']
        for field in required_fields:
            if field not in hint:
                raise HintsLoadError(f"Hint {i} missing required field: {field}")

    return hints_data


def filter_hints_by_type(hints_data: Dict[str, Any], hint_types: List[str]) -> List[Dict[str, Any]]:
    """
    Filter hints by type.

    Args:
        hints_data: Hints data from load_hints()
        hint_types: List of hint types to include (e.g., ['crypto_function', 'instruction_pattern'])

    Returns:
        Filtered list of hints
    """
    all_hints = hints_data.get('hints', [])
    return [h for h in all_hints if h.get('type') in hint_types]


def filter_hints_by_confidence(hints_data: Dict[str, Any], min_confidence: float) -> List[Dict[str, Any]]:
    """
    Filter hints by minimum confidence threshold.

    Args:
        hints_data: Hints data from load_hints()
        min_confidence: Minimum confidence score (0.0-1.0)

    Returns:
        Filtered list of hints
    """
    all_hints = hints_data.get('hints', [])
    return [h for h in all_hints if h.get('confidence', 0.0) >= min_confidence]


def get_crypto_function_hints(hints_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get hints for crypto function calls.

    These are hints with type='crypto_function' that typically
    include a function name and module.

    Args:
        hints_data: Hints data from load_hints()

    Returns:
        List of crypto function hints
    """
    return filter_hints_by_type(hints_data, ['crypto_function'])


def get_address_hints(hints_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get hints with specific addresses or address ranges.

    These are hints that include an 'address_or_range' field
    for targeted instrumentation.

    Args:
        hints_data: Hints data from load_hints()

    Returns:
        List of hints with addresses
    """
    all_hints = hints_data.get('hints', [])
    return [h for h in all_hints if h.get('address_or_range')]


def get_high_confidence_hints(hints_data: Dict[str, Any], threshold: float = 0.8) -> List[Dict[str, Any]]:
    """
    Get high-confidence hints only.

    Args:
        hints_data: Hints data from load_hints()
        threshold: Confidence threshold (default: 0.8)

    Returns:
        List of high-confidence hints
    """
    return filter_hints_by_confidence(hints_data, threshold)


def summarize_hints(hints_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate summary statistics for hints.

    Args:
        hints_data: Hints data from load_hints()

    Returns:
        Dictionary with summary statistics:
        {
            "total_hints": int,
            "by_type": {"crypto_function": int, ...},
            "by_confidence_range": {"high": int, "medium": int, "low": int},
            "with_addresses": int
        }
    """
    all_hints = hints_data.get('hints', [])

    # Count by type
    by_type = {}
    for hint in all_hints:
        hint_type = hint.get('type', 'unknown')
        by_type[hint_type] = by_type.get(hint_type, 0) + 1

    # Count by confidence range
    by_confidence = {'high': 0, 'medium': 0, 'low': 0}
    for hint in all_hints:
        confidence = hint.get('confidence', 0.0)
        if confidence >= 0.8:
            by_confidence['high'] += 1
        elif confidence >= 0.5:
            by_confidence['medium'] += 1
        else:
            by_confidence['low'] += 1

    # Count with addresses
    with_addresses = len([h for h in all_hints if h.get('address_or_range')])

    return {
        'total_hints': len(all_hints),
        'by_type': by_type,
        'by_confidence_range': by_confidence,
        'with_addresses': with_addresses
    }


def resolve_hints_path(file_hash: str, analysis_base: str) -> str:
    """
    Resolve path to hints.json for a given file hash.

    Args:
        file_hash: SHA256 hash of binary
        analysis_base: Base analysis directory

    Returns:
        Path to hints.json

    Example:
        >>> resolve_hints_path("abc123", "/workdir")
        "/workdir/analysis/static/abc123/hints.json"
    """
    return os.path.join(analysis_base, 'analysis', 'static', file_hash, 'hints.json')


def load_hints_for_binary(file_hash: str, analysis_base: str) -> Dict[str, Any]:
    """
    Convenience function to load hints for a specific binary.

    Args:
        file_hash: SHA256 hash of binary
        analysis_base: Base analysis directory

    Returns:
        Hints data dictionary

    Raises:
        HintsLoadError: If hints cannot be loaded
    """
    hints_path = resolve_hints_path(file_hash, analysis_base)
    return load_hints(hints_path)
