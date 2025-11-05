"""Compatibility wrapper for `auditor.intake`.

The original implementation has been moved to `auditor._legacy.intake`.
This module re-exports the legacy symbols to keep existing imports working
while you migrate callers to the new `auditor.setup_flow` APIs.
"""

from auditor._legacy import intake as _legacy

# Re-export the legacy public API for backwards compatibility
enumerate_inputs = _legacy.enumerate_inputs
enumerate_inputs_iter = _legacy.enumerate_inputs_iter
count_inputs = _legacy.count_inputs
write_manifest = _legacy.write_manifest
write_manifest_iter = _legacy.write_manifest_iter
hash_file_sha256 = _legacy.hash_file_sha256
OperationCancelled = _legacy.OperationCancelled

__all__ = [
    "enumerate_inputs",
    "enumerate_inputs_iter",
    "count_inputs",
    "write_manifest",
    "write_manifest_iter",
    "hash_file_sha256",
    "OperationCancelled",
]
"""auditor.intake

Simple intake module that enumerates inputs under given paths and computes
SHA-256 hashes plus basic metadata (mtime, size). Writes `inputs.manifest.json`.

This is intentionally minimal: production code should add owners, UID/GID,
platform-specific metadata, SBOM capture hooks, and exclusion rules.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

"""Compatibility wrapper for `auditor.intake`.

The original implementation has been moved to `auditor._legacy.intake`.
This module re-exports the legacy symbols to keep existing imports working
while you migrate callers to the new `auditor.setup_flow` APIs.
"""

from auditor._legacy import intake as _legacy

# Re-export the legacy public API for backwards compatibility
enumerate_inputs = _legacy.enumerate_inputs
enumerate_inputs_iter = _legacy.enumerate_inputs_iter
count_inputs = _legacy.count_inputs
write_manifest = _legacy.write_manifest
write_manifest_iter = _legacy.write_manifest_iter
hash_file_sha256 = _legacy.hash_file_sha256
OperationCancelled = _legacy.OperationCancelled

__all__ = [
    """Compatibility wrapper for `auditor.intake`.

    The original implementation has been moved to `auditor._legacy.intake`.
    This module re-exports the legacy symbols to keep existing imports working
    while you migrate callers to the new `auditor.setup_flow` APIs.
    """

    from auditor._legacy import intake as _legacy

    # Re-export the legacy public API for backwards compatibility
    enumerate_inputs = _legacy.enumerate_inputs
    enumerate_inputs_iter = _legacy.enumerate_inputs_iter
    count_inputs = _legacy.count_inputs
    write_manifest = _legacy.write_manifest
    write_manifest_iter = _legacy.write_manifest_iter
    hash_file_sha256 = _legacy.hash_file_sha256
    OperationCancelled = _legacy.OperationCancelled

    __all__ = [
        "enumerate_inputs",
        "enumerate_inputs_iter",
        "count_inputs",
        "write_manifest",
        "write_manifest_iter",
        "hash_file_sha256",
        "OperationCancelled",
    ]
