"""Detector adapters package.

Adapters provide a small, stable contract so detectors can consume
preprocessing outputs (files, AST caches, disasm caches) without
relying on repository-specific paths.

Example adapters are provided in this package.
"""

from .adapter import BaseAdapter

__all__ = ["BaseAdapter"]
