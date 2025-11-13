"""Constants/table detection heuristics for cryptographic primitives.

This heuristic identifies potential cryptographic constants and tables:
- S-boxes (substitution boxes used in AES, DES, etc.)
- Initialization vectors (IVs)
- Round constants (used in hash functions)
- Permutation tables
- Magic numbers from known crypto algorithms
- High-entropy repeated patterns

Known crypto constants we look for:
- AES S-box patterns
- SHA-2/SHA-3 round constants
- MD5/SHA-1 magic numbers
- Common crypto initialization values
"""
from typing import List, Dict, Any, Set, Tuple
import hashlib
import json
import struct


def _make_id(prefix: str, text: str) -> str:
    return f"{prefix}-{hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()[:8]}"


# Known cryptographic constants (as hex patterns)
KNOWN_CRYPTO_CONSTANTS = {
    # AES S-box first bytes
    "637c777bf26b6fc5": {"name": "AES_SBOX", "algorithm": "AES", "type": "substitution_box"},
    "c66363a5f87c7c84": {"name": "AES_SBOX_VARIANT", "algorithm": "AES", "type": "substitution_box"},
    
    # SHA-256 initial hash values (first 32 bits of fractional parts of square roots)
    "6a09e667": {"name": "SHA256_H0", "algorithm": "SHA-256", "type": "initial_value"},
    "bb67ae85": {"name": "SHA256_H1", "algorithm": "SHA-256", "type": "initial_value"},
    "3c6ef372": {"name": "SHA256_H2", "algorithm": "SHA-256", "type": "initial_value"},
    "a54ff53a": {"name": "SHA256_H3", "algorithm": "SHA-256", "type": "initial_value"},
    
    # SHA-256 round constants (K)
    "428a2f98": {"name": "SHA256_K0", "algorithm": "SHA-256", "type": "round_constant"},
    "71374491": {"name": "SHA256_K1", "algorithm": "SHA-256", "type": "round_constant"},
    "b5c0fbcf": {"name": "SHA256_K2", "algorithm": "SHA-256", "type": "round_constant"},
    
    # SHA-1 constants
    "67452301": {"name": "SHA1_H0", "algorithm": "SHA-1", "type": "initial_value"},
    "efcdab89": {"name": "SHA1_H1", "algorithm": "SHA-1", "type": "initial_value"},
    "98badcfe": {"name": "SHA1_H2", "algorithm": "SHA-1", "type": "initial_value"},
    "10325476": {"name": "SHA1_H3", "algorithm": "SHA-1", "type": "initial_value"},
    "c3d2e1f0": {"name": "SHA1_H4", "algorithm": "SHA-1", "type": "initial_value"},
    
    # MD5 constants
    "d76aa478": {"name": "MD5_A", "algorithm": "MD5", "type": "initial_value"},
    "e8c7b756": {"name": "MD5_B", "algorithm": "MD5", "type": "initial_value"},
    "242070db": {"name": "MD5_C", "algorithm": "MD5", "type": "initial_value"},
    "c1bdceee": {"name": "MD5_D", "algorithm": "MD5", "type": "initial_value"},
    
    # ChaCha20 constants ("expand 32-byte k")
    "61707865": {"name": "CHACHA_CONST0", "algorithm": "ChaCha20", "type": "constant"},
    "3320646e": {"name": "CHACHA_CONST1", "algorithm": "ChaCha20", "type": "constant"},
    "79622d32": {"name": "CHACHA_CONST2", "algorithm": "ChaCha20", "type": "constant"},
    "6b206574": {"name": "CHACHA_CONST3", "algorithm": "ChaCha20", "type": "constant"},
    
    # BLAKE2 initialization vectors
    "6a09e667f3bcc908": {"name": "BLAKE2_IV0", "algorithm": "BLAKE2", "type": "initial_value"},
    "bb67ae8584caa73b": {"name": "BLAKE2_IV1", "algorithm": "BLAKE2", "type": "initial_value"},
}


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence."""
    if not data:
        return 0.0
    
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    
    import math
    entropy = 0.0
    length = len(data)
    
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy


def _is_likely_sbox(data: bytes) -> Tuple[bool, float]:
    """Check if byte sequence looks like an S-box.
    
    S-boxes typically have:
    - Length of 256 bytes (8-bit lookup table)
    - High entropy (all or most values 0-255 present)
    - Uniform distribution
    """
    if len(data) != 256:
        return False, 0.0
    
    # Check uniqueness (good S-boxes are permutations)
    unique_values = len(set(data))
    uniqueness_ratio = unique_values / 256.0
    
    # High entropy (close to 8.0 for 8-bit data)
    entropy = _calculate_entropy(data)
    
    # S-boxes should have high entropy and high uniqueness
    confidence = 0.0
    if uniqueness_ratio >= 0.95 and entropy >= 7.8:
        confidence = 0.9  # Very likely S-box
    elif uniqueness_ratio >= 0.85 and entropy >= 7.5:
        confidence = 0.7  # Probable S-box
    elif uniqueness_ratio >= 0.70 and entropy >= 7.0:
        confidence = 0.5  # Possible S-box
    
    return confidence > 0.0, confidence


def _check_known_constant(pattern_hex: str) -> Tuple[bool, Dict]:
    """Check if a hex pattern matches known crypto constants."""
    # Check exact matches
    if pattern_hex in KNOWN_CRYPTO_CONSTANTS:
        return True, KNOWN_CRYPTO_CONSTANTS[pattern_hex]
    
    # Check substrings (for partial matches)
    for known_hex, info in KNOWN_CRYPTO_CONSTANTS.items():
        if known_hex in pattern_hex or pattern_hex in known_hex:
            return True, info
    
    return False, {}


def _find_pattern_offsets(binary_data: bytes, pattern_bytes: bytes,
                          timeout_sec: float = 5.0, start_time=None) -> List[int]:
    """Find all offsets where pattern occurs in binary.

    OPTIMIZED: Includes timeout protection to prevent hangs on large binaries
    with many pattern matches. If timeout is exceeded, returns partial results.

    Args:
        binary_data: The binary content to search
        pattern_bytes: The pattern to find
        timeout_sec: Maximum time to spend searching (default 5 seconds)
        start_time: Shared timeout start time (for batch operations)

    Returns:
        List of offsets where pattern is found (may be partial if timeout exceeded)
    """
    import time

    if start_time is None:
        start_time = time.time()

    offsets = []
    pos = 0
    iterations = 0
    timeout_triggered = False

    while True:
        # Periodic timeout check (every 1000 iterations to minimize overhead)
        if iterations % 1000 == 0:
            elapsed = time.time() - start_time
            if elapsed > timeout_sec:
                timeout_triggered = True
                break

        iterations += 1
        pos = binary_data.find(pattern_bytes, pos)
        if pos == -1:
            break
        offsets.append(pos)
        pos += 1

    if timeout_triggered and offsets:
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(
            f"[CONSTANTS] Pattern search timeout after {time.time() - start_time:.2f}s "
            f"({iterations} iterations, {len(offsets)} matches found, partial results)"
        )

    return offsets


def _get_section_for_offset(sections_data: List[Dict], offset: int) -> str:
    """Determine which section contains this offset.

    Args:
        sections_data: List of section dicts with 'name', 'offset', 'size'
        offset: The offset to map to a section

    Returns:
        Section name or 'unknown'
    """
    if not sections_data:
        return "unknown"

    for section in sections_data:
        sec_start = section.get("offset", 0)
        sec_size = section.get("size", 0)
        sec_end = sec_start + sec_size

        if sec_start <= offset < sec_end:
            return section.get("name", "unknown")

    return "unknown"


def _analyze_repetition_pattern(pattern_bytes: bytes, count: int) -> Dict:
    """Analyze repetition pattern for crypto indicators."""
    entropy = _calculate_entropy(pattern_bytes)
    length = len(pattern_bytes)
    
    analysis = {
        "entropy": round(entropy, 3),
        "length": length,
        "repeat_count": count,
        "likely_crypto": False,
        "indicators": [],
    }
    
    # 4-byte patterns with high entropy and repetition = likely crypto constants
    if length == 4 and entropy >= 1.5 and count >= 4:
        analysis["likely_crypto"] = True
        analysis["indicators"].append("4byte_repeated_constant")
    
    # 8-byte patterns = likely 64-bit constants
    if length == 8 and entropy >= 2.0 and count >= 3:
        analysis["likely_crypto"] = True
        analysis["indicators"].append("8byte_constant_array")
    
    # 16-byte patterns = likely AES-related
    if length == 16 and entropy >= 3.0:
        analysis["likely_crypto"] = True
        analysis["indicators"].append("16byte_aes_related")
    
    # 32-byte patterns = likely SHA-256 related
    if length == 32 and entropy >= 4.0:
        analysis["likely_crypto"] = True
        analysis["indicators"].append("32byte_hash_related")
    
    # High repetition of moderate-entropy patterns = likely lookup table
    if count >= 10 and entropy >= 1.0:
        analysis["likely_crypto"] = True
        analysis["indicators"].append("lookup_table_pattern")
    
    return analysis


def constants_heuristic(ghidra_export: Dict, metadata: Dict, static_artifacts: Dict[str, Any] = None) -> List[Dict]:
    """Detect cryptographic constants and tables.

    Detection strategies:
    1. Match against known crypto constants (SHA, AES, MD5, etc.)
    2. Identify S-box patterns (256-byte permutation tables)
    3. Detect repeated patterns with crypto-indicative properties
    4. Analyze high-entropy constant regions

    Enhancements:
    - Extracts offset information from binary
    - Maps offsets to binary sections
    - Populates address_or_range field for location tracking
    """
    findings: List[Dict] = []

    if not static_artifacts:
        return findings

    const_path = static_artifacts.get("constants.json")
    if not const_path:
        return findings

    try:
        with open(const_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        consts = doc.get("constants", [])
    except Exception:
        return findings

    # Load binary file for offset extraction
    binary_data = None
    input_path = static_artifacts.get("__input_path__")
    if input_path:
        try:
            with open(input_path, "rb") as fh:
                binary_data = fh.read()
        except Exception:
            pass

    # Load sections data for location mapping
    sections_data = []
    sections_path = static_artifacts.get("sections.json")
    if sections_path:
        try:
            with open(sections_path, "r", encoding="utf-8") as fh:
                sections_doc = json.load(fh)
                sections_data = sections_doc.get("sections", [])
        except Exception:
            pass

    seen_patterns: Set[str] = set()
    
    for c in consts:
        pattern_hex = c.get("pattern", "")
        count = c.get("count", 0)
        
        if not pattern_hex:
            continue
        
        # Avoid duplicate findings
        if pattern_hex in seen_patterns:
            continue
        seen_patterns.add(pattern_hex)
        
        # Convert hex to bytes for analysis
        try:
            pattern_bytes = bytes.fromhex(pattern_hex)
        except ValueError:
            continue
        
        # DETECTION 1: Check against known crypto constants
        is_known, known_info = _check_known_constant(pattern_hex)
        if is_known:
            fid = _make_id("known-const", pattern_hex)
            confidence = 0.95  # High confidence for known constants

            # Extract location data
            section = "unknown"
            address_or_range = None
            if binary_data:
                try:
                    pattern_bytes = bytes.fromhex(pattern_hex)
                    offsets = _find_pattern_offsets(binary_data, pattern_bytes)
                    if offsets:
                        # Use first occurrence
                        first_offset = offsets[0]
                        section = _get_section_for_offset(sections_data, first_offset)

                        # Create address range
                        if offsets:
                            start_hex = hex(offsets[0])
                            end_hex = hex(offsets[-1] + len(pattern_bytes))
                            address_or_range = {
                                "start": start_hex,
                                "end": end_hex,
                                "count": len(offsets)
                            }
                except Exception:
                    pass

            finding = {
                "id": fid,
                "type": "known_crypto_constant",
                "name": known_info.get("name", "UNKNOWN"),
                "confidence": confidence,
                "reason_tags": ["known_constant", known_info.get("algorithm", "").lower()],
                "evidence_snippet": f"{known_info.get('algorithm')} {known_info.get('type')}: {pattern_hex[:32]}",
                "evidence": {
                    "pattern": pattern_hex[:64],
                    "algorithm": known_info.get("algorithm"),
                    "constant_type": known_info.get("type"),
                    "repeat_count": count,
                },
                "count": count,
            }

            # Add location data if available
            if address_or_range:
                finding["additional_data"] = {
                    "address_or_range": address_or_range,
                    "section": section,
                }

            findings.append(finding)
            continue
        
        # DETECTION 2: Check for S-box pattern (256 bytes)
        if len(pattern_bytes) == 256:
            is_sbox, sbox_confidence = _is_likely_sbox(pattern_bytes)
            if is_sbox:
                fid = _make_id("sbox", pattern_hex[:32])

                # Extract location data
                section = "unknown"
                address_or_range = None
                if binary_data:
                    try:
                        offsets = _find_pattern_offsets(binary_data, pattern_bytes)
                        if offsets:
                            first_offset = offsets[0]
                            section = _get_section_for_offset(sections_data, first_offset)

                            # Create address range
                            start_hex = hex(offsets[0])
                            end_hex = hex(offsets[-1] + len(pattern_bytes))
                            address_or_range = {
                                "start": start_hex,
                                "end": end_hex,
                                "count": len(offsets)
                            }
                    except Exception:
                        pass

                finding = {
                    "id": fid,
                    "type": "sbox_table",
                    "name": "substitution_box",
                    "confidence": sbox_confidence,
                    "reason_tags": ["sbox", "lookup_table", "256byte_table"],
                    "evidence_snippet": f"256-byte S-box candidate: entropy={_calculate_entropy(pattern_bytes):.2f}",
                    "evidence": {
                        "pattern_preview": pattern_hex[:64] + "...",
                        "length": 256,
                        "entropy": round(_calculate_entropy(pattern_bytes), 3),
                        "unique_bytes": len(set(pattern_bytes)),
                    },
                    "count": count,
                }

                # Add location data if available
                if address_or_range:
                    finding["additional_data"] = {
                        "address_or_range": address_or_range,
                        "section": section,
                    }

                findings.append(finding)
                continue
        
        # DETECTION 3: Analyze repetition patterns
        # Skip single-occurrence patterns unless they're known constants
        if count <= 1:
            continue
        
        pattern_analysis = _analyze_repetition_pattern(pattern_bytes, count)
        
        if pattern_analysis["likely_crypto"]:
            fid = _make_id("const", pattern_hex + str(count))

            # Base confidence from repetition count
            confidence = min(0.3 + 0.1 * (count - 1), 0.8)

            # Boost confidence based on entropy
            if pattern_analysis["entropy"] >= 2.0:
                confidence += 0.1

            # Boost for specific indicators
            if "4byte_repeated_constant" in pattern_analysis["indicators"]:
                confidence += 0.15

            confidence = min(confidence, 0.95)

            reason_tags = ["repeated_pattern", "constant_table"]
            reason_tags.extend(pattern_analysis["indicators"])

            # Extract location data
            section = "unknown"
            address_or_range = None
            if binary_data:
                try:
                    offsets = _find_pattern_offsets(binary_data, pattern_bytes)
                    if offsets:
                        first_offset = offsets[0]
                        section = _get_section_for_offset(sections_data, first_offset)

                        # Create address range
                        start_hex = hex(offsets[0])
                        end_hex = hex(offsets[-1] + len(pattern_bytes))
                        address_or_range = {
                            "start": start_hex,
                            "end": end_hex,
                            "count": len(offsets)
                        }
                except Exception:
                    pass

            finding = {
                "id": fid,
                "type": "constant_table",
                "name": "crypto_constant_candidate",
                "confidence": confidence,
                "reason_tags": reason_tags,
                "evidence_snippet": f"{len(pattern_bytes)}-byte pattern (×{count}): entropy={pattern_analysis['entropy']:.2f}, indicators={', '.join(pattern_analysis['indicators'][:3])}",
                "evidence": {
                    "pattern": pattern_hex[:128],
                    "length": len(pattern_bytes),
                    "repeat_count": count,
                    "entropy": pattern_analysis["entropy"],
                    "indicators": pattern_analysis["indicators"],
                },
                "count": count,
            }

            # Add location data if available
            if address_or_range:
                finding["additional_data"] = {
                    "address_or_range": address_or_range,
                    "section": section,
                }

            findings.append(finding)
    
    return findings
