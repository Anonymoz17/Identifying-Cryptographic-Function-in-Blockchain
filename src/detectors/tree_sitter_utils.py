"""Small helpers for Tree-sitter token normalization and heuristics.

Keep functions tiny and dependency-free so tests can run without optional libs.
"""

import re
from typing import Optional

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
HEX_CHUNK_RE = re.compile(r"(?:0x)?[0-9A-Fa-f_]+")


def normalize_hex_literal(token: str) -> Optional[str]:
    """Normalize a hex-like token into lowercase hex digits or return None.

    This is tolerant of surrounding punctuation, suffixes, and underscores.
    It finds the longest hex-like chunk (optionally prefixed with 0x) inside the
    input, strips underscores and an optional 0x prefix, and returns the
    lowercase hex string. If no valid hex chunk is found, returns None.
    """
    if not token:
        return None
    t = str(token)
    # search for all hex-like chunks (allow underscores inside)
    # prefer explicit 0x-prefixed chunks when available
    prefixed = re.findall(r"0x[0-9A-Fa-f_]+", t, flags=re.IGNORECASE)
    if prefixed:
        candidates = prefixed
    else:
        # if the input contains '0x' but there are no prefixed matches, treat as no hex
        if "0x" in t.lower():
            return None
        candidates = HEX_CHUNK_RE.findall(t)

    if not candidates:
        return None

    # pick the best candidate by normalized length (strip 0x and underscores first)
    def norm_and_len(raw: str):
        s = raw
        if s.lower().startswith("0x"):
            s = s[2:]
        s = s.replace("_", "")
        return s.lower(), len(s)

    best = None
    best_key = (0, -1)
    for idx, raw in enumerate(candidates):
        norm, ln = norm_and_len(raw)
        # only consider if all-hex
        if not norm or not HEX_RE.fullmatch(norm):
            continue
        # prefer longer normalized candidate; on tie prefer later occurrence
        key = (ln, idx)
        if key > best_key:
            best_key = key
            best = norm

    if not best:
        return None
    candidate = best
    # strip leading 0x/0X if present
    if candidate.lower().startswith("0x"):
        candidate = candidate[2:]
    # remove underscores
    candidate = candidate.replace("_", "")
    # only accept if non-empty and purely hex digits
    if candidate and HEX_RE.fullmatch(candidate):
        return candidate.lower()
    return None


def is_ethereum_address(token: str) -> bool:
    """Return True if token normalizes to a 20-byte (40 hex char) value."""
    norm = normalize_hex_literal(token)
    return bool(norm and len(norm) == 40)
