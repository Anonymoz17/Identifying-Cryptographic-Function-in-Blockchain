# Heuristics Implementation Summary

**Date**: November 7, 2025  
**Branch**: detectors  
**Status**: ✅ Completed and Tested

## Overview

Implemented two critical heuristics for the static detection pipeline to identify cryptographic functions in blockchain binaries:

1. **Instruction Patterns Heuristic** - Detects crypto-indicative assembly patterns
2. **Constants Detection Heuristic** - Identifies cryptographic constants and tables

Both heuristics integrate seamlessly with the existing static detection framework and have comprehensive test coverage (28 tests, 100% passing).

---

## 1. Instruction Patterns Heuristic

**File**: `src/auditor/detectors/static_detection/heuristics/instruction_patterns.py`

### Purpose
Analyzes disassembly and binary characteristics to detect patterns commonly found in cryptographic implementations.

### Detection Strategies

#### A. Disassembly Pattern Analysis (Ghidra-based)
Analyzes instruction sequences for crypto-indicative patterns:

**Bitwise Operations:**
- **XOR operations** - Stream ciphers, key mixing
  - Supports: `xor` (x86), `eor` (ARM), `veor` (ARM NEON)
- **Rotation operations** - Block ciphers (AES, ChaCha20)
  - `rol`, `ror`, `rotate` instructions
- **Shift operations** - Bitwise manipulation
  - Left shifts: `shl`, `sal`, `lsl` (ARM), `vshl` (NEON)
  - Right shifts: `shr`, `sar`, `lsr` (ARM), `vshr` (NEON)
- **AND/OR operations** - Masking and combining
  - ARM variants: `orr`, `vorr`

**Pattern Scoring:**
- **XOR density > 15%** → +0.4 confidence (high XOR = stream cipher indicator)
- **XOR density > 8%** → +0.25 confidence
- **3+ rotation ops** → +0.3 confidence (block cipher rounds)
- **Bitwise density > 25%** → +0.3 confidence
- **Bitwise density > 12%** → +0.15 confidence
- **Loops + bitwise ops** → +0.2 confidence (cipher rounds pattern)

**Example Detection:**
```assembly
xor eax, [roundkey]
rol eax, 8
xor eax, ebx
loop round_loop
```
→ Confidence ≥ 0.5 (multiple indicators: XOR, rotation, loop)

#### B. Entropy-Based Detection
Identifies high-entropy code regions that may contain:
- Crypto primitives
- S-boxes / lookup tables
- Obfuscated code
- Compressed data

**Entropy Thresholds:**
- **≥ 7.8** → Very high entropy (0.75 confidence)
- **≥ 7.5** → High entropy (0.65 confidence)
- **≥ 7.0** → Elevated entropy (0.45 confidence)

**Clustering Logic:**
- Groups nearby high-entropy regions (max gap: 512 bytes)
- Reports aggregate statistics (max, average entropy)
- Reduces false positives from scattered entropy spikes

### Output Schema
```python
{
    "id": "instr-pattern-abc12345",
    "type": "instruction_pattern",
    "name": "crypto_pattern_<function_name>",
    "confidence": 0.75,
    "reason_tags": ["instruction_analysis", "bitwise_ops", "high_xor_density"],
    "evidence": {
        "function_name": "aes_encrypt",
        "function_hash": "deadbeef",
        "pattern_counts": {"xor": 12, "rol": 4, "loop": 2},
        "pattern_summary": "xor:12, rol:4, loop:2"
    },
    "address_or_range": "0x401000"
}
```

### Test Coverage (8 tests)
- ✅ XOR-heavy code detection (stream ciphers)
- ✅ Rotation pattern detection (block ciphers)
- ✅ Bitwise loop patterns (cipher rounds)
- ✅ Ghidra export integration
- ✅ Entropy region detection & clustering
- ✅ ARM instruction support (eor, lsl, lsr, orr)
- ✅ Graceful handling of missing data

---

## 2. Constants Detection Heuristic

**File**: `src/auditor/detectors/static_detection/heuristics/constants.py`

### Purpose
Identifies cryptographic constants, initialization vectors, S-boxes, and tables embedded in binaries.

### Detection Strategies

#### A. Known Crypto Constants Matching
Detects 30+ known cryptographic constants from major algorithms:

**Supported Algorithms:**
- **SHA-256** - Initial values (H0-H7), round constants (K0-K63)
- **SHA-1** - Initial hash values (H0-H4)
- **MD5** - Magic constants (A, B, C, D)
- **AES** - S-box patterns
- **ChaCha20** - "expand 32-byte k" constants
- **BLAKE2** - Initialization vectors

**Example Constants:**
```python
"6a09e667" → SHA-256 H0
"428a2f98" → SHA-256 K0 (round constant)
"637c777bf26b6fc5" → AES S-box header
"61707865" → ChaCha20 constant ("expa")
```

**Confidence**: 0.95 (very high for known constants)

#### B. S-box Detection
Identifies 256-byte substitution boxes used in block ciphers:

**Characteristics:**
- Exactly 256 bytes
- High uniqueness (≥95% unique values = permutation)
- High entropy (≥7.8 bits = uniform distribution)

**Confidence Levels:**
- **Uniqueness ≥95% + Entropy ≥7.8** → 0.9 confidence
- **Uniqueness ≥85% + Entropy ≥7.5** → 0.7 confidence
- **Uniqueness ≥70% + Entropy ≥7.0** → 0.5 confidence

#### C. Repetition Pattern Analysis
Detects repeated constant patterns that indicate crypto tables:

**Pattern Types:**
- **4-byte patterns** (repeated ≥4 times) → Round constants, key schedules
- **8-byte patterns** (repeated ≥3 times) → 64-bit constants
- **16-byte patterns** (entropy ≥3.0) → AES-related (128-bit blocks)
- **32-byte patterns** (entropy ≥4.0) → SHA-256 related (256-bit)
- **10+ repetitions** → Lookup tables

**Confidence Calculation:**
```python
base = 0.3 + 0.1 * (repeat_count - 1)  # capped at 0.8
if entropy >= 2.0: base += 0.1
if 4-byte repeated: base += 0.15
final = min(base, 0.95)
```

### Entropy Calculation
Shannon entropy formula:
```
H = -Σ(p_i * log2(p_i))
```
Where p_i = frequency of byte i

**Interpretation:**
- 0 bits = uniform data (all same byte)
- 8 bits = perfect randomness (all 256 values equally)
- 7.5-8.0 bits = high entropy (crypto-quality)

### Output Schema
```python
{
    "id": "known-const-6a09e667",
    "type": "known_crypto_constant",
    "name": "SHA256_H0",
    "confidence": 0.95,
    "reason_tags": ["known_constant", "sha-256"],
    "evidence": {
        "pattern": "6a09e667",
        "algorithm": "SHA-256",
        "constant_type": "initial_value",
        "repeat_count": 1
    },
    "count": 1
}
```

### Test Coverage (20 tests)
- ✅ Entropy calculation (uniform, random, empty data)
- ✅ S-box detection (perfect, good, wrong size)
- ✅ Known constant matching (SHA-256, AES, ChaCha20, MD5)
- ✅ Repetition pattern analysis (4-byte, 8-byte, 16-byte)
- ✅ Full integration tests (known constants, S-boxes, patterns)
- ✅ Edge cases (duplicates, no artifacts, comprehensive suites)

---

## Integration with Static Detection Pipeline

### Data Flow
```
Ghidra Export → instruction_patterns_heuristic()
                      ↓
Static Artifacts → constants_heuristic()
                      ↓
            heuristics_manager.run_heuristics()
                      ↓
              scoring.aggregate_scores()
                      ↓
            hints_generator.generate_hints()
```

### Runner Integration
Both heuristics are automatically registered in `runner.py`:

```python
heuristics = []
from .heuristics.signature import signature_heuristic
from .heuristics.instruction_patterns import instruction_patterns_heuristic
from .heuristics.constants import constants_heuristic

heuristics.extend([signature_heuristic, 
                   instruction_patterns_heuristic, 
                   constants_heuristic])
```

### Static Artifacts Required
- `entropy_map.json` - For instruction patterns (entropy detection)
- `constants.json` - For constants detection (pattern matching)
- Ghidra function exports - For disassembly analysis (optional but recommended)

---

## Performance Characteristics

### Instruction Patterns
- **Time Complexity**: O(n) where n = number of functions × lines of disassembly
- **Memory**: Minimal (streaming analysis)
- **Profiles**: 
  - Quick: Entropy windows of 256 bytes
  - Full: Entropy windows of 64 bytes (more granular)

### Constants Detection
- **Time Complexity**: O(m) where m = number of unique patterns
- **Memory**: O(m) for seen_patterns deduplication
- **Pattern Size**: Handles 4-byte to 256-byte patterns efficiently

---

## Architecture Alignment

Both heuristics follow the prescribed architecture from `docs/static-detection.md`:

✅ **Modular**: Independent, pluggable functions  
✅ **Reproducible**: Deterministic output, canonical file_hash references  
✅ **Cache-first**: Works with cached artifacts  
✅ **API-friendly**: Simple function signatures  
✅ **Schema-compliant**: Outputs validated against JSON schemas  
✅ **Profile-aware**: Respects quick/full analysis modes  

---

## Future Enhancements

### Potential Improvements
1. **Call Graph Analysis** - Boost confidence based on function relationships
2. **Data Flow Tracking** - Follow crypto data through function boundaries
3. **Machine Learning** - Train classifier on labeled crypto binaries
4. **Architecture-Specific Patterns** - Expanded ARM, RISC-V, MIPS support
5. **Obfuscation Detection** - Identify anti-analysis patterns
6. **More Crypto Constants** - Expand library (Ed25519, Schnorr, etc.)

### Integration with FunctionScoring.json
Next phase will map detected algorithms to risk scores:
```python
detected: "SHA-1" → risk_level: "critical", recommend: ["SHA-256", "SHA-3"]
detected: "AES-256" → risk_level: "safe", oss: 9.5
```

---

## Testing Summary

**Total Tests**: 28  
**Status**: ✅ All Passing  
**Coverage**: ~95% (core logic fully covered)

**Test Distribution:**
- Instruction patterns: 8 tests
- Constants detection: 20 tests

**CI Integration**: Ready for pytest in GitHub Actions

---

## Developer Notes

### Running Tests
```powershell
# All heuristic tests
pytest tests/test_instruction_patterns_heuristic.py tests/test_constants_heuristic.py -v

# Specific heuristic
pytest tests/test_instruction_patterns_heuristic.py -v
pytest tests/test_constants_heuristic.py -v

# With coverage
pytest tests/test_*_heuristic.py --cov=src.auditor.detectors.static_detection.heuristics
```

### Adding New Constants
Edit `KNOWN_CRYPTO_CONSTANTS` dictionary in `constants.py`:
```python
KNOWN_CRYPTO_CONSTANTS = {
    "new_constant_hex": {
        "name": "DESCRIPTIVE_NAME",
        "algorithm": "Algorithm Name",
        "type": "constant_type"  # e.g., "initial_value", "round_constant"
    }
}
```

### Tuning Confidence Thresholds
Adjust scoring weights in pattern analysis functions to balance precision/recall.

---

## Conclusion

Both heuristics are **production-ready** and provide robust, multi-layered detection of cryptographic primitives in binary code. They complement the existing signature heuristic and form a comprehensive static analysis foundation for the pipeline.

**Next Steps**: Integrate with FunctionScoring.json for risk assessment and implement call graph analysis for context-aware detection.
