"""
Instrumenters for dynamic analysis.

This package contains pluggable instrumentation strategies
for different types of runtime analysis.

Available instrumenters:
- crypto_ops: Hook Windows crypto APIs (bcrypt.dll, crypt32.dll)
- memory_scan: Scan for high-entropy buffers (potential keys)
- call_graph: Build runtime call graph from crypto calls
"""

__all__ = []
