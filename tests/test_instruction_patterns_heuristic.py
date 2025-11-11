"""Tests for instruction patterns heuristic."""
import json
import os
from pathlib import Path

from src.auditor.detectors.static_detection.heuristics.instruction_patterns import (
    instruction_patterns_heuristic,
    _analyze_disassembly_patterns,
    _cluster_entropy_regions,
)


def test_analyze_disassembly_xor_heavy():
    """Test detection of XOR-heavy code (stream cipher pattern)."""
    disasm = """
    xor eax, ebx
    xor ecx, edx
    mov [esi], eax
    xor eax, [key]
    xor ebx, ecx
    add esi, 4
    loop start
    """
    patterns, confidence = _analyze_disassembly_patterns(disasm, "encrypt_stream")
    
    assert patterns["xor"] >= 4, "Should detect XOR instructions"
    assert confidence >= 0.25, "XOR-heavy code should have meaningful confidence"


def test_analyze_disassembly_rotation_pattern():
    """Test detection of rotation operations (block cipher indicator)."""
    disasm = """
    mov eax, [data]
    rol eax, 7
    xor eax, ebx
    ror eax, 3
    rol ecx, 5
    add eax, ecx
    """
    patterns, confidence = _analyze_disassembly_patterns(disasm, "cipher_round")
    
    assert patterns["rol"] >= 2, "Should detect ROL instructions"
    assert patterns["ror"] >= 1, "Should detect ROR instructions"
    assert confidence >= 0.2, "Rotation pattern should increase confidence"


def test_analyze_disassembly_bitwise_loop():
    """Test detection of bitwise operations in loops."""
    disasm = """
    start:
    xor eax, [key+ecx*4]
    shl ebx, 2
    and eax, 0xFF
    or ebx, eax
    add ecx, 1
    cmp ecx, 16
    jne start
    """
    patterns, confidence = _analyze_disassembly_patterns(disasm, "round_function")
    
    assert patterns["loop"] >= 1, "Should detect loop/jump instructions"
    assert patterns["xor"] >= 1, "Should detect XOR"
    assert patterns["and"] >= 1, "Should detect AND"
    assert confidence >= 0.3, "Loop + bitwise should boost confidence"


def test_instruction_patterns_with_ghidra_export(tmp_path):
    """Test instruction pattern detection with Ghidra function export."""
    # Mock Ghidra export with crypto-like disassembly
    ghidra_functions = [
        {
            "name": "aes_encrypt_block",
            "address": "0x401000",
            "function_hash": "abc123",
            "disasm": """
                mov eax, [state]
                xor eax, [roundkey]
                rol eax, 8
                xor eax, ebx
                shl eax, 1
                xor eax, ecx
                rol eax, 16
                and eax, 0xFFFFFFFF
                mov [state], eax
                loop round_loop
            """,
        },
        {
            "name": "normal_function",
            "address": "0x402000",
            "function_hash": "def456",
            "disasm": """
                push ebp
                mov ebp, esp
                call helper
                pop ebp
                ret
            """,
        },
    ]
    
    findings = instruction_patterns_heuristic(
        ghidra_export=ghidra_functions,
        metadata={},
        static_artifacts=None
    )
    
    # Should find the crypto-like function
    assert len(findings) >= 1, "Should detect at least one pattern"
    
    crypto_finding = next((f for f in findings if "aes_encrypt_block" in str(f.get("evidence", {}))), None)
    assert crypto_finding is not None, "Should detect the AES-like function"
    assert crypto_finding["confidence"] >= 0.15, "Should have meaningful confidence"
    assert "bitwise_ops" in crypto_finding["reason_tags"]


def test_instruction_patterns_entropy_detection(tmp_path):
    """Test high-entropy region detection."""
    # Create mock entropy map
    entropy_map = {
        "generated": True,
        "entropy_map": [
            {"offset": 0, "entropy": 6.5},      # Normal
            {"offset": 256, "entropy": 7.9},    # High
            {"offset": 512, "entropy": 8.0},    # Very high
            {"offset": 768, "entropy": 7.8},    # High (clustered)
            {"offset": 1024, "entropy": 6.2},   # Normal
            {"offset": 2048, "entropy": 7.6},   # High (separate cluster)
        ]
    }
    
    entropy_path = tmp_path / "entropy_map.json"
    with open(entropy_path, "w") as f:
        json.dump(entropy_map, f)
    
    static_artifacts = {"entropy_map.json": str(entropy_path)}
    
    findings = instruction_patterns_heuristic(
        ghidra_export=[],
        metadata={},
        static_artifacts=static_artifacts
    )
    
    # Should detect multiple high-entropy regions
    assert len(findings) >= 1, "Should detect high-entropy regions"
    
    # Check that high entropy regions are properly identified
    high_entropy_findings = [f for f in findings if f["type"] == "high_entropy_region"]
    assert len(high_entropy_findings) >= 1, "Should have high-entropy findings"
    
    # Verify confidence scaling
    very_high_finding = next(
        (f for f in high_entropy_findings if f.get("evidence", {}).get("avg_entropy", 0) >= 7.8),
        None
    )
    if very_high_finding:
        assert very_high_finding["confidence"] >= 0.65, "Very high entropy should have high confidence"


def test_cluster_entropy_regions():
    """Test entropy region clustering logic."""
    regions = [
        (0, 7.5),
        (256, 7.8),    # Should cluster with next
        (512, 7.9),    # Clustered
        (2048, 7.6),   # Separate cluster (gap > 512)
    ]
    
    clustered = _cluster_entropy_regions(regions, max_gap=512)
    
    # Should produce 2 clusters: [0], [256,512], [2048]
    # Actually [0] might be solo, [256,512] together, [2048] solo
    assert len(clustered) >= 2, "Should cluster nearby regions"
    
    # Find the cluster containing offsets 256-512
    found_cluster = False
    for start, end, max_ent, avg_ent in clustered:
        if start <= 256 and end >= 512:
            found_cluster = True
            assert max_ent >= 7.8, "Should capture max entropy"
            assert avg_ent >= 7.5, "Should calculate average entropy"
    
    assert found_cluster, "Should cluster offsets 256 and 512 together"


def test_no_findings_without_artifacts():
    """Test that heuristic handles missing artifacts gracefully."""
    findings = instruction_patterns_heuristic(
        ghidra_export=[],
        metadata={},
        static_artifacts=None
    )
    
    assert findings == [], "Should return empty list without artifacts"


def test_arm_instruction_detection():
    """Test detection of ARM instructions (common in blockchain)."""
    disasm = """
    eor r0, r0, r1
    eor r2, r2, r3
    lsl r0, r0, #4
    lsr r1, r1, #2
    orr r0, r0, r2
    bl crypto_func
    """
    
    patterns, confidence = _analyze_disassembly_patterns(disasm, "arm_crypto")
    
    # ARM uses 'eor' for XOR, 'lsl' for left shift, 'lsr' for right shift
    # Our pattern matching should catch these
    assert patterns["xor"] >= 2, "Should detect EOR (XOR) instructions"
    assert patterns["shl"] >= 1, "Should detect LSL (left shift)"
    assert patterns["shr"] >= 1, "Should detect LSR (right shift)"
    assert confidence > 0.0, "Should have some confidence for ARM crypto patterns"
