"""Tests for constants detection heuristic."""
import json
import os
from pathlib import Path

from src.auditor.detectors.static_detection.heuristics.constants import (
    constants_heuristic,
    _calculate_entropy,
    _is_likely_sbox,
    _check_known_constant,
    _analyze_repetition_pattern,
    KNOWN_CRYPTO_CONSTANTS,
)


def test_calculate_entropy_uniform():
    """Test entropy calculation for uniform distribution."""
    # All bytes equal = 0 entropy
    data = bytes([42] * 256)
    entropy = _calculate_entropy(data)
    assert entropy == 0.0, "Uniform data should have 0 entropy"


def test_calculate_entropy_random():
    """Test entropy calculation for random-looking data."""
    # Pseudo-random bytes (high entropy)
    data = bytes(range(256))
    entropy = _calculate_entropy(data)
    assert entropy >= 7.5, "All unique bytes should have high entropy"


def test_calculate_entropy_empty():
    """Test entropy calculation for empty data."""
    entropy = _calculate_entropy(b"")
    assert entropy == 0.0, "Empty data should have 0 entropy"


def test_is_likely_sbox_perfect():
    """Test S-box detection with perfect permutation."""
    # Perfect S-box: 256 unique bytes (permutation of 0-255)
    import random
    sbox_data = list(range(256))
    random.shuffle(sbox_data)
    sbox_bytes = bytes(sbox_data)
    
    is_sbox, confidence = _is_likely_sbox(sbox_bytes)
    assert is_sbox, "Perfect permutation should be detected as S-box"
    assert confidence >= 0.85, "Perfect S-box should have high confidence"


def test_is_likely_sbox_good():
    """Test S-box detection with high uniqueness."""
    # Good S-box: 250 unique bytes out of 256
    sbox_data = list(range(250)) + [0] * 6
    import random
    random.shuffle(sbox_data)
    sbox_bytes = bytes(sbox_data)
    
    is_sbox, confidence = _is_likely_sbox(sbox_bytes)
    assert is_sbox, "High uniqueness should be detected as potential S-box"
    assert confidence >= 0.5, "Good S-box should have reasonable confidence"


def test_is_likely_sbox_wrong_size():
    """Test that wrong-sized data is not detected as S-box."""
    data = bytes(range(128))  # Wrong size
    is_sbox, confidence = _is_likely_sbox(data)
    assert not is_sbox, "Wrong-sized data should not be S-box"
    assert confidence == 0.0


def test_check_known_constant_sha256():
    """Test detection of known SHA-256 constants."""
    # SHA-256 H0 constant
    is_known, info = _check_known_constant("6a09e667")
    assert is_known, "Should recognize SHA-256 H0"
    assert info["algorithm"] == "SHA-256"
    assert info["type"] == "initial_value"


def test_check_known_constant_aes():
    """Test detection of AES S-box pattern."""
    # AES S-box first bytes
    is_known, info = _check_known_constant("637c777bf26b6fc5")
    assert is_known, "Should recognize AES S-box pattern"
    assert info["algorithm"] == "AES"
    assert info["type"] == "substitution_box"


def test_check_known_constant_chacha20():
    """Test detection of ChaCha20 constants."""
    # ChaCha20 "expand 32-byte k" constants
    is_known, info = _check_known_constant("61707865")
    assert is_known, "Should recognize ChaCha20 constant"
    assert info["algorithm"] == "ChaCha20"


def test_check_known_constant_unknown():
    """Test that unknown constants are not matched."""
    is_known, info = _check_known_constant("deadbeef")
    assert not is_known, "Should not match unknown constant"
    assert info == {}


def test_analyze_repetition_4byte_constant():
    """Test analysis of 4-byte repeated pattern."""
    pattern = bytes.fromhex("428a2f98")  # SHA-256 K constant
    analysis = _analyze_repetition_pattern(pattern, count=16)
    
    assert analysis["length"] == 4
    assert analysis["repeat_count"] == 16
    assert analysis["likely_crypto"], "High-repetition 4-byte pattern should be flagged"
    assert "4byte_repeated_constant" in analysis["indicators"]


def test_analyze_repetition_sbox_pattern():
    """Test analysis of 256-byte S-box pattern."""
    # Create S-box-like pattern
    sbox = bytes(range(256))
    analysis = _analyze_repetition_pattern(sbox, count=1)
    
    assert analysis["length"] == 256
    # Note: the function doesn't explicitly check for 256-byte S-boxes in repetition
    # That's handled by _is_likely_sbox


def test_analyze_repetition_16byte_aes():
    """Test analysis of 16-byte AES-related pattern."""
    pattern = bytes([i ^ 0x63 for i in range(16)])  # High entropy 16-byte pattern
    analysis = _analyze_repetition_pattern(pattern, count=4)
    
    assert analysis["length"] == 16
    if analysis["entropy"] >= 3.0:
        assert analysis["likely_crypto"], "16-byte high-entropy pattern should be flagged"


def test_constants_heuristic_known_constants(tmp_path):
    """Test detection of known crypto constants."""
    # Create constants.json with SHA-256 constants
    constants_data = {
        "generated": True,
        "constants": [
            {"pattern": "6a09e667", "count": 1},  # SHA-256 H0
            {"pattern": "bb67ae85", "count": 1},  # SHA-256 H1
            {"pattern": "428a2f98", "count": 8},  # SHA-256 K0 (repeated)
            {"pattern": "deadbeef", "count": 2},  # Unknown constant
        ]
    }
    
    const_path = tmp_path / "constants.json"
    with open(const_path, "w") as f:
        json.dump(constants_data, f)
    
    static_artifacts = {"constants.json": str(const_path)}
    
    findings = constants_heuristic(
        ghidra_export={},
        metadata={},
        static_artifacts=static_artifacts
    )
    
    # Should detect the known SHA-256 constants
    assert len(findings) >= 2, "Should detect known constants"
    
    # Check for SHA-256 detections
    sha256_findings = [f for f in findings if f.get("evidence", {}).get("algorithm") == "SHA-256"]
    assert len(sha256_findings) >= 2, "Should detect multiple SHA-256 constants"
    
    # Known constants should have high confidence
    for finding in sha256_findings:
        assert finding["confidence"] >= 0.9, "Known constants should have high confidence"
        assert finding["type"] == "known_crypto_constant"


def test_constants_heuristic_sbox_detection(tmp_path):
    """Test S-box detection in constants."""
    # Create a 256-byte S-box pattern
    import random
    sbox = list(range(256))
    random.shuffle(sbox)
    sbox_hex = bytes(sbox).hex()
    
    constants_data = {
        "generated": True,
        "constants": [
            {"pattern": sbox_hex, "count": 2},
        ]
    }
    
    const_path = tmp_path / "constants.json"
    with open(const_path, "w") as f:
        json.dump(constants_data, f)
    
    static_artifacts = {"constants.json": str(const_path)}
    
    findings = constants_heuristic(
        ghidra_export={},
        metadata={},
        static_artifacts=static_artifacts
    )
    
    # Should detect the S-box
    assert len(findings) >= 1, "Should detect S-box pattern"
    
    sbox_finding = next((f for f in findings if f["type"] == "sbox_table"), None)
    assert sbox_finding is not None, "Should have S-box type finding"
    assert sbox_finding["confidence"] >= 0.5, "S-box should have decent confidence"
    assert "sbox" in sbox_finding["reason_tags"]


def test_constants_heuristic_repeated_patterns(tmp_path):
    """Test detection of repeated constant patterns."""
    constants_data = {
        "generated": True,
        "constants": [
            {"pattern": "12345678", "count": 10},  # 4-byte repeated 10 times
            {"pattern": "aabbccdd", "count": 3},   # 4-byte repeated 3 times
            {"pattern": "11111111", "count": 50},  # Low entropy, many repeats
        ]
    }
    
    const_path = tmp_path / "constants.json"
    with open(const_path, "w") as f:
        json.dump(constants_data, f)
    
    static_artifacts = {"constants.json": str(const_path)}
    
    findings = constants_heuristic(
        ghidra_export={},
        metadata={},
        static_artifacts=static_artifacts
    )
    
    # Should detect repeated patterns
    assert len(findings) >= 1, "Should detect repeated patterns"
    
    # High repeat count should boost confidence
    high_repeat_finding = next(
        (f for f in findings if f.get("count", 0) >= 10),
        None
    )
    if high_repeat_finding:
        assert high_repeat_finding["confidence"] >= 0.4, "High repeat count should boost confidence"


def test_constants_heuristic_no_artifacts():
    """Test graceful handling of missing artifacts."""
    findings = constants_heuristic(
        ghidra_export={},
        metadata={},
        static_artifacts=None
    )
    
    assert findings == [], "Should return empty list without artifacts"


def test_constants_heuristic_chacha20_detection(tmp_path):
    """Test detection of ChaCha20 constants."""
    constants_data = {
        "generated": True,
        "constants": [
            {"pattern": "61707865", "count": 1},  # "expa"
            {"pattern": "3320646e", "count": 1},  # "nd 3"
            {"pattern": "79622d32", "count": 1},  # "2-by"
            {"pattern": "6b206574", "count": 1},  # "te k"
        ]
    }
    
    const_path = tmp_path / "constants.json"
    with open(const_path, "w") as f:
        json.dump(constants_data, f)
    
    static_artifacts = {"constants.json": str(const_path)}
    
    findings = constants_heuristic(
        ghidra_export={},
        metadata={},
        static_artifacts=static_artifacts
    )
    
    # Should detect ChaCha20 constants
    chacha_findings = [
        f for f in findings 
        if f.get("evidence", {}).get("algorithm") == "ChaCha20"
    ]
    assert len(chacha_findings) >= 1, "Should detect ChaCha20 constants"


def test_constants_heuristic_avoid_duplicates(tmp_path):
    """Test that duplicate patterns are not reported multiple times."""
    constants_data = {
        "generated": True,
        "constants": [
            {"pattern": "6a09e667", "count": 5},
            {"pattern": "6a09e667", "count": 3},  # Duplicate
        ]
    }
    
    const_path = tmp_path / "constants.json"
    with open(const_path, "w") as f:
        json.dump(constants_data, f)
    
    static_artifacts = {"constants.json": str(const_path)}
    
    findings = constants_heuristic(
        ghidra_export={},
        metadata={},
        static_artifacts=static_artifacts
    )
    
    # Should only report the pattern once
    sha256_h0_findings = [
        f for f in findings
        if "6a09e667" in f.get("evidence", {}).get("pattern", "")
    ]
    assert len(sha256_h0_findings) == 1, "Should not report duplicate patterns"


def test_constants_comprehensive_crypto_suite(tmp_path):
    """Test detection of a comprehensive set of crypto constants."""
    constants_data = {
        "generated": True,
        "constants": [
            # SHA-256
            {"pattern": "6a09e667", "count": 1},
            {"pattern": "428a2f98", "count": 64},
            # MD5
            {"pattern": "d76aa478", "count": 1},
            # AES S-box
            {"pattern": "637c777bf26b6fc5", "count": 1},
            # ChaCha20
            {"pattern": "61707865", "count": 1},
            # High-entropy unknown pattern
            {"pattern": "a5c3f1e9", "count": 16},
        ]
    }
    
    const_path = tmp_path / "constants.json"
    with open(const_path, "w") as f:
        json.dump(constants_data, f)
    
    static_artifacts = {"constants.json": str(const_path)}
    
    findings = constants_heuristic(
        ghidra_export={},
        metadata={},
        static_artifacts=static_artifacts
    )
    
    # Should detect multiple crypto algorithms
    algorithms_found = set()
    for finding in findings:
        algo = finding.get("evidence", {}).get("algorithm")
        if algo:
            algorithms_found.add(algo)
    
    assert len(algorithms_found) >= 3, f"Should detect multiple algorithms, found: {algorithms_found}"
    assert len(findings) >= 4, "Should have multiple findings for comprehensive suite"
