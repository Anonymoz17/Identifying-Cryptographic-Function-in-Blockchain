"""Ghidra-enhanced analysis for Phase 2: function enrichment and call graph.

This module provides utilities to:
1. Build a call graph from Ghidra function data
2. Enrich findings with function context (callers, callees, cross-references)
3. Create function profiles with detailed metadata
4. Link findings to their containing/calling functions

Phase 2 Enhancement: Move beyond simple location tracking to understanding HOW
crypto functions are called and WHO calls them. This helps auditors understand
the complete context and data flow.
"""

from typing import Dict, List, Set, Tuple, Optional, Any
import hashlib
import time
import logging

logger = logging.getLogger(__name__)


def _make_id(prefix: str, text: str) -> str:
    """Generate deterministic ID from text."""
    return f"{prefix}-{hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()[:8]}"


class CallGraph:
    """Build and analyze function call graphs from Ghidra exports."""

    def __init__(self, ghidra_export: List[Dict]):
        """Initialize call graph from Ghidra function list.

        Args:
            ghidra_export: List of function dicts from Ghidra containing:
                - name, address, prototype, disasm, etc.
        """
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.function_by_address: Dict[str, str] = {}
        self.call_graph: Dict[str, Set[str]] = {}  # fn_name -> {called_names}
        self.called_by: Dict[str, Set[str]] = {}  # fn_name -> {caller_names}

        # Build function index and extract calls from disassembly
        if isinstance(ghidra_export, list):
            for fn in ghidra_export:
                name = fn.get("name", "")
                address = fn.get("address") or fn.get("addr") or fn.get("entry_point")

                if not name:
                    continue

                # Index by name and address
                self.functions[name] = fn
                if address:
                    self.function_by_address[str(address)] = name

                # Initialize call sets
                self.call_graph[name] = set()
                if name not in self.called_by:
                    self.called_by[name] = set()

            # Extract calls from disassembly (simple heuristic: look for function names in disasm)
            self._extract_calls_from_disasm()

    def _extract_calls_from_disasm(self, timeout_sec: float = 30.0):
        """Extract function calls from disassembly snippets using simple heuristic.

        OPTIMIZED: Uses timeout protection and pre-computed lowercase names to prevent
        O(N²) hangs on binaries with many functions (e.g., 500+ functions = 250K iterations).

        Args:
            timeout_sec: Maximum time to spend on call graph extraction (default 30s)
        """
        start_time = time.time()

        # Pre-compute lowercase function names to avoid repeated .lower() calls
        # This is a key optimization for large function lists
        function_names_lower = {name: name.lower() for name in self.functions.keys()}

        # Track statistics
        total_iterations = 0
        calls_found = 0
        timeout_triggered = False

        for fn_idx, (fn_name, fn_data) in enumerate(self.functions.items()):
            # Periodic timeout check (every 50 functions checked)
            if fn_idx % 50 == 0:
                elapsed = time.time() - start_time
                if elapsed > timeout_sec:
                    logger.warning(
                        f"[GHIDRA ENRICHMENT] Call graph extraction timeout after {elapsed:.1f}s "
                        f"({fn_idx}/{len(self.functions)} functions, {calls_found} calls found). "
                        f"Partial call graph will be used."
                    )
                    timeout_triggered = True
                    break

            disasm = fn_data.get("disasm", "")
            if not disasm:
                continue

            # Pre-convert disasm once per function (not once per comparison)
            disasm_lower = disasm.lower()

            for other_name in self.functions.keys():
                total_iterations += 1

                if other_name == fn_name:
                    continue

                # Skip very generic names to reduce false positives
                other_name_lower = function_names_lower[other_name]
                if len(other_name_lower) < 3:
                    continue

                # Simple substring check
                if other_name_lower in disasm_lower:
                    self.call_graph[fn_name].add(other_name)
                    self.called_by[other_name].add(fn_name)
                    calls_found += 1

        elapsed = time.time() - start_time
        if not timeout_triggered:
            logger.debug(
                f"[GHIDRA ENRICHMENT] Call graph extracted in {elapsed:.2f}s "
                f"({total_iterations} iterations, {calls_found} calls found)"
            )

    def get_callers(self, function_name: str) -> List[str]:
        """Get functions that call this function."""
        return list(self.called_by.get(function_name, set()))

    def get_callees(self, function_name: str) -> List[str]:
        """Get functions called by this function."""
        return list(self.call_graph.get(function_name, set()))

    def get_function_data(self, function_name: str) -> Optional[Dict]:
        """Get full function data from Ghidra export."""
        return self.functions.get(function_name)

    def find_crypto_function_path(self, finding_type: str, finding_name: str) -> List[str]:
        """Trace path from finding to likely entry point or crypto function.

        For example, if we find a crypto pattern in function X, find what functions
        call X and where the crypto operation was initiated from.

        Args:
            finding_type: Type of finding (e.g., 'instruction_pattern')
            finding_name: Name of function containing finding

        Returns:
            List of function names in call chain (longest path up to 5 hops)
        """
        # Start from finding location
        current = finding_name
        path = [current]
        visited = {current}
        max_depth = 5

        # Walk up the call chain
        while len(path) < max_depth:
            callers = self.get_callers(current)
            if not callers:
                break

            # Pick the most likely caller (heuristic: longest/most complex name)
            # Real implementation would use better heuristics
            next_caller = max(callers, key=lambda x: len(x)) if callers else None

            if not next_caller or next_caller in visited:
                break

            path.append(next_caller)
            visited.add(next_caller)
            current = next_caller

        return path


class FunctionProfile:
    """Detailed profile of a function with enriched metadata."""

    def __init__(self, ghidra_fn_data: Dict, callers: List[str] = None, callees: List[str] = None):
        """Create function profile from Ghidra data and call graph info.

        Args:
            ghidra_fn_data: Function data from Ghidra export
            callers: List of functions that call this one
            callees: List of functions called by this one
        """
        self.name = ghidra_fn_data.get("name", "")
        self.address = ghidra_fn_data.get("address") or ghidra_fn_data.get("addr")
        self.size = ghidra_fn_data.get("size", 0)
        self.prototype = ghidra_fn_data.get("prototype", "")
        self.parameters = ghidra_fn_data.get("parameters", [])
        self.calling_convention = ghidra_fn_data.get("calling_convention", "")
        self.disasm = ghidra_fn_data.get("disasm", "")

        self.callers = callers or []
        self.callees = callees or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "prototype": self.prototype,
            "parameters": self.parameters,
            "calling_convention": self.calling_convention,
            "callers": self.callers,
            "callees": self.callees,
        }

    def get_signature_summary(self) -> str:
        """Get human-readable function signature."""
        if self.prototype:
            return self.prototype.strip()

        # Fallback: build from name and parameters
        param_str = ", ".join([p.get("name", "") for p in self.parameters if p.get("name")])
        return f"{self.name}({param_str})"


def enrich_findings_with_context(
    findings: List[Dict],
    ghidra_export: List[Dict],
    function_name_extractor=None,
) -> List[Dict]:
    """Enrich findings with function context from Ghidra.

    Args:
        findings: List of findings from detectors (with function_name in additional_data)
        ghidra_export: List of function dicts from Ghidra
        function_name_extractor: Optional callable to extract function name from finding

    Returns:
        Enriched findings with additional context
    """
    if not ghidra_export:
        return findings

    # Build call graph
    cg = CallGraph(ghidra_export)

    # Enrich each finding
    enriched = []
    for finding in findings:
        enriched_finding = dict(finding)

        # Extract function name from various sources
        fn_name = None

        # Try additional_data first
        if isinstance(finding.get("additional_data"), dict):
            fn_name = finding["additional_data"].get("function_name")

        # Try top-level field
        if not fn_name:
            fn_name = finding.get("function_name")

        # Try evidence field
        if not fn_name and isinstance(finding.get("evidence"), dict):
            fn_name = finding["evidence"].get("function_name")

        # If we found a function, enrich it
        if fn_name and fn_name in cg.functions:
            # Ensure additional_data exists
            if "additional_data" not in enriched_finding:
                enriched_finding["additional_data"] = {}

            additional_data = enriched_finding["additional_data"]

            # Add call context
            callers = cg.get_callers(fn_name)
            callees = cg.get_callees(fn_name)

            if callers:
                additional_data["callers"] = callers[:3]  # Top 3 callers

            if callees:
                additional_data["callees"] = callees[:3]  # Top 3 callees

            # Add function profile
            fn_data = cg.get_function_data(fn_name)
            if fn_data:
                profile = FunctionProfile(fn_data, callers, callees)
                additional_data["function_profile"] = {
                    "signature": profile.get_signature_summary(),
                    "size": profile.size,
                    "calling_convention": profile.calling_convention,
                }

            # Add call chain (path from finding up to entry point)
            call_path = cg.find_crypto_function_path(finding.get("type", ""), fn_name)
            if len(call_path) > 1:
                additional_data["call_chain"] = call_path

        enriched.append(enriched_finding)

    return enriched


def build_function_index(ghidra_export: List[Dict]) -> Dict[str, Dict[str, Any]]:
    """Build comprehensive function index from Ghidra exports.

    Useful for UI display and quick lookup.

    Returns dict with structure:
    {
        "function_name": {
            "address": "0x...",
            "size": 1234,
            "prototype": "...",
            "parameters": [...],
            "callers": [...],
            "callees": [...],
        },
        ...
    }
    """
    if not ghidra_export:
        return {}

    cg = CallGraph(ghidra_export)
    index = {}

    for fn_name, fn_data in cg.functions.items():
        profile = FunctionProfile(
            fn_data,
            callers=cg.get_callers(fn_name),
            callees=cg.get_callees(fn_name),
        )
        index[fn_name] = profile.to_dict()

    return index


def detect_crypto_usage_patterns(ghidra_export: List[Dict]) -> List[Dict]:
    """Detect common crypto usage patterns from function relationships.

    Examples:
    - Key generation functions calling key initialization
    - Cipher initialization calling cipher update
    - Signature verification calling signature verification functions

    Returns list of pattern findings with context.
    """
    if not ghidra_export:
        return []

    patterns = []
    cg = CallGraph(ghidra_export)

    crypto_keywords = [
        "aes", "sha", "md5", "rsa", "dsa", "ecdsa", "hmac",
        "encrypt", "decrypt", "hash", "sign", "verify", "key",
        "chacha", "blake", "curve", "secp",
    ]

    # Find crypto functions
    crypto_functions = {
        fn_name: fn_data
        for fn_name, fn_data in cg.functions.items()
        if any(kw in fn_name.lower() for kw in crypto_keywords)
    }

    # Detect usage patterns
    for fn_name, fn_data in crypto_functions.items():
        callers = cg.get_callers(fn_name)
        callees = cg.get_callees(fn_name)

        # Pattern 1: Crypto function with multiple callers (high reuse)
        if len(callers) >= 2:
            patterns.append({
                "id": _make_id("crypto-usage", fn_name),
                "type": "crypto_high_reuse",
                "function": fn_name,
                "caller_count": len(callers),
                "callers": callers,
                "confidence": 0.7,
                "reason": f"Crypto function '{fn_name}' called by {len(callers)} functions",
            })

        # Pattern 2: Crypto function calling other crypto functions (composition)
        crypto_callees = [
            ce for ce in callees
            if any(kw in ce.lower() for kw in crypto_keywords)
        ]
        if crypto_callees:
            patterns.append({
                "id": _make_id("crypto-composition", fn_name),
                "type": "crypto_composition",
                "function": fn_name,
                "crypto_callees": crypto_callees,
                "confidence": 0.75,
                "reason": f"Function '{fn_name}' composes crypto operations: {crypto_callees}",
            })

    return patterns
