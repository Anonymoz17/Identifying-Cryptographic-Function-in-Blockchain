# Phase 7 Integration Testing Plan - Dynamic Cryptographic Function Detector

**Date:** 2025-11-11
**Status:** Phase 7 @ 75% Complete (Unit + E2E Done, Integration Tests Pending)
**Author:** Analysis Report
**Target Completion:** 2025-11-15

---

## Executive Summary

This document provides a comprehensive analysis of the current test coverage for the dynamic cryptographic function detector and outlines a detailed integration test plan to achieve 100% Phase 7 completion.

### Current State

- **Phase 1-6:** 100% complete with full UI integration
- **Phase 7 Progress:** 75% complete
  - ✅ Unit tests: 9/9 passing (100%)
  - ✅ E2E tests: 8/8 passing (100%)
  - ⚠️ Integration tests: 0/8 complete (0%)
- **Total Tests:** 17/17 passing (100% pass rate)
- **Code Base:** 4,500+ lines production code, 17 Python modules, 3 JSON schemas

### Gap Analysis

The current test suite covers:
- Component-level functionality (unit tests)
- Mock-based full pipeline execution (E2E tests)

**Missing coverage:**
- Real PE binary execution with Frida
- Timeout enforcement with actual long-running binaries
- Memory limit scenarios
- Large trace collection (10k event limit)
- Batch processing with multiple binaries
- Error recovery and edge cases

---

## 1. Current Test Coverage Analysis

### 1.1 Unit Tests (9/9 Passing - 100%)

**File:** `tests/test_dynamic_detection_units.py` (493 lines)

| Test | Component | Coverage |
|------|-----------|----------|
| `test_context_dataclass` | DynamicContext | Dataclass instantiation, validation |
| `test_dynamic_result_state` | DynamicResult | State management, error tracking |
| `test_trace_event_creation` | TraceEvent | Event creation |
| `test_trace_sanitizer` | TraceSanitizer | Buffer hashing, secret redaction |
| `test_trace_manager` | TraceManager | Event collection, limits |
| `test_findings_generation` | results_packager | Findings from events |
| `test_summary_generation` | results_packager | Summary generation |
| `test_results_validation` | validator | JSON schema validation |
| `test_config_defaults` | Config | Default loading, custom config |

**Strengths:**
- Comprehensive component isolation
- All core data structures tested
- Limit enforcement verified (max_events, max_crypto_calls, max_size)
- Sanitization verified (no raw data leaks)

**Gaps:**
- No real Frida execution
- No actual binary instrumentation
- No timeout scenarios
- No memory limit testing

### 1.2 E2E Tests (8/8 Passing - 100%)

**File:** `tests/test_dynamic_detection_e2e.py` (622 lines)

| Test | Coverage | Notes |
|------|----------|-------|
| `test_context_creation` | DynamicContext | Basic instantiation |
| `test_config_loading` | Config | Default loading |
| `test_hints_loading` | hints_adapter | Load from static analysis |
| `test_hook_generation` | frida_scripter | Generate JavaScript hooks |
| `test_trace_management` | trace_manager | Event collection with limits |
| `test_trace_sanitization` | traces_sanitizer | Buffer hashing |
| `test_runner_without_frida` | DynamicRunner | Pre-flight checks |
| `test_full_pipeline_mock` | Full pipeline | Mock end-to-end flow |

**Test Environment Created:**
- Mock binary (104 bytes, PE header)
- Mock metadata.json
- Mock hints.json with 3 hints (BCryptEncrypt, CryptEncrypt, instruction_pattern)

**Strengths:**
- Full pipeline orchestration tested
- All 10 stages verified
- Sanitization verified
- Mock events collection works

**Gaps:**
- Uses mock binary (not real crypto operations)
- No actual Frida spawn/attach
- No real trace collection
- No timeout enforcement
- No memory limit testing
- E2E tests fail with pytest (fixture issues) but pass standalone

### 1.3 Available Test Binaries

**Directory:** `test_binaries/`

1. **test_crypto.exe** (136 KB)
   - Source: `test_crypto.c` (43 lines)
   - Functions: `xor_encrypt`, `simple_hash`, `aes_like_function`
   - Self-contained, no external dependencies
   - Suitable for basic instrumentation testing

**Gaps:**
- No bcrypt.dll-using binary
- No crypt32.dll-using binary
- No OpenSSL-linked binary
- No stripped/obfuscated binaries
- No large binaries (>50MB)
- No long-running binaries (>500s)

---

## 2. Identified Testing Gaps

### 2.1 CRITICAL Gaps

| ID | Gap | Impact | Risk |
|----|-----|--------|------|
| G1 | No real binary Frida execution | Cannot verify Frida integration works | HIGH |
| G2 | No timeout enforcement testing | Timeout may not trigger correctly | HIGH |
| G3 | No batch processing integration test | Multi-binary scenarios untested | MEDIUM |
| G4 | No error recovery testing | Unknown behavior on crashes | MEDIUM |

### 2.2 HIGH Priority Gaps

| ID | Gap | Impact | Risk |
|----|-----|--------|------|
| G5 | No Windows Crypto API (bcrypt/crypt32) testing | Core detection untested | HIGH |
| G6 | No 10k event limit testing with real traces | Limit enforcement unverified | MEDIUM |
| G7 | No memory limit enforcement | Could cause OOM | MEDIUM |
| G8 | No cache hit/miss with real binaries | Cache logic unverified | LOW |

### 2.3 MEDIUM Priority Gaps

| ID | Gap | Impact | Risk |
|----|-----|--------|------|
| G9 | No stripped binary testing | Symbol-less binaries untested | MEDIUM |
| G10 | No multi-threaded crypto testing | Concurrent calls untested | LOW |
| G11 | No network blocking verification | May leak network traffic | MEDIUM |
| G12 | No large binary testing (>50MB) | Performance unknown | LOW |

---

## 3. Recommended Integration Tests

### 3.1 CRITICAL Priority Tests (Must-Have for Phase 7)

#### INT-01: Real Binary with Frida Spawn Mode

**Priority:** CRITICAL
**Estimated Time:** 4 hours
**Complexity:** Medium

**Objective:** Verify Frida can spawn and instrument a real PE binary

**Test Scenario:**
1. Use `test_crypto.exe` (136KB, contains xor_encrypt, simple_hash)
2. Create minimal hints.json pointing to xor_encrypt
3. Run DynamicRunner with spawn mode
4. Verify:
   - Binary spawns successfully
   - Frida hooks load without errors
   - At least 1 trace event collected
   - Process completes normally
   - Results JSON written correctly

**Expected Results:**
- `dynamic_results.json` exists
- `trace.ndjson` exists with >0 events
- Summary shows execution_time > 0
- No errors in DynamicResult.errors

**Test Data Required:**
- `test_crypto.exe` (already exists)
- Hints JSON with function entry hooks
- Expected: 3-5 trace events (function calls)

**Failure Modes:**
- Frida not installed → clear error message
- Binary crashes → incomplete flag set
- Hooks fail to load → error in results

---

#### INT-02: Timeout Enforcement (500s Limit)

**Priority:** CRITICAL
**Estimated Time:** 6 hours
**Complexity:** High

**Objective:** Verify timeout enforcement works and partial results are captured

**Test Scenario:**
1. Create or modify binary to run for >10 seconds (use sleep/busy loop)
2. Set timeout to 5 seconds
3. Run DynamicRunner
4. Verify:
   - Process terminated at ~5 seconds (±1s tolerance)
   - `incomplete` flag = True
   - `incomplete_reason` = "timeout"
   - Partial trace events saved (events collected before timeout)
   - Results JSON written with incomplete flag

**Expected Results:**
- Execution time ≈ 5 seconds (not 10+)
- `dynamic_results.json` has `incomplete: true`
- Trace events collected up to timeout point
- No crashes or hangs

**Test Data Required:**
- Modified `test_crypto.exe` with sleep(15) added
- Timeout config: 5 seconds
- Expected: Partial traces, incomplete result

**Edge Cases:**
- Binary ignores SIGTERM → force kill required
- No events collected before timeout → empty trace file OK
- Timeout during hook loading → error handling

---

#### INT-03: Batch Processing with Multiple Binaries

**Priority:** CRITICAL
**Estimated Time:** 5 hours
**Complexity:** Medium

**Objective:** Verify batch processing handles multiple binaries correctly

**Test Scenario:**
1. Create 3 different binaries:
   - Binary A: Normal execution, completes successfully
   - Binary B: Crashes immediately (invalid memory access)
   - Binary C: Times out (long-running)
2. Run batch processing via UI integration
3. Verify:
   - All 3 binaries processed
   - Binary A: success with results
   - Binary B: error captured, other binaries continue
   - Binary C: timeout captured, marked incomplete
   - Batch summary shows 1 success, 1 error, 1 timeout

**Expected Results:**
- 3 separate result directories
- Batch doesn't abort on Binary B failure
- Progress tracking works (1/3, 2/3, 3/3)
- UI displays all results correctly

**Test Data Required:**
- 3 binaries with different behaviors
- Batch runner integration
- Expected: Mixed results (success/error/timeout)

**Failure Modes:**
- First failure aborts batch → must continue
- Resource leaks across binaries → cleanup verification
- UI hangs → threading issues

---

#### INT-04: Large Trace Collection (10k Event Limit)

**Priority:** HIGH
**Estimated Time:** 5 hours
**Complexity:** Medium

**Objective:** Verify trace manager enforces 10k event limit correctly

**Test Scenario:**
1. Create or modify binary to make 15,000+ crypto calls
2. Run with default config (max_trace_events=10000)
3. Verify:
   - Only 10,000 events written to trace.ndjson
   - `limits_reached.max_events` = true in trace_summary
   - No memory exhaustion
   - Results still valid despite limit

**Expected Results:**
- Exactly 10,000 lines in trace.ndjson
- `trace_summary.limits_reached.max_events: true`
- Summary shows truncation warning
- Process completes normally

**Test Data Required:**
- Binary with loop calling crypto function 15k times
- Expected: 10k events, limit flag set

**Performance:**
- Event collection overhead <10% (verify with profiling)
- Memory usage <100MB for 10k events

---

### 3.2 HIGH Priority Tests (Important for Robustness)

#### INT-05: Windows Crypto API Detection (bcrypt.dll)

**Priority:** HIGH
**Estimated Time:** 8 hours
**Complexity:** High

**Objective:** Verify detection of real Windows Crypto API usage

**Test Scenario:**
1. Create C program using `BCryptEncrypt` from bcrypt.dll
2. Compile to PE binary
3. Generate hints from static analysis
4. Run dynamic analysis
5. Verify:
   - BCryptEncrypt calls detected
   - Arguments hashed (no raw keys)
   - Return values captured
   - Call graph shows function relationships

**Expected Results:**
- `findings` array contains BCryptEncrypt entry
- `count` matches actual calls
- `args_hashes` present for all calls
- No raw crypto keys in traces

**Test Data Required:**
- Binary using BCryptEncrypt (requires Windows SDK)
- Compile with: `cl.exe /MD bcrypt_test.c /link bcrypt.lib`
- Expected: 1-5 BCryptEncrypt calls

**Code Example:**
```c
#include <windows.h>
#include <bcrypt.h>

int main() {
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);

    UCHAR key[16] = {0};
    UCHAR data[16] = {0};
    ULONG result;

    BCryptEncrypt(hAlg, data, 16, NULL, NULL, 0, data, 16, &result, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}
```

---

#### INT-06: Memory Limit Scenario (>512MB)

**Priority:** HIGH
**Estimated Time:** 4 hours
**Complexity:** Medium

**Objective:** Verify memory limit warning/enforcement

**Test Scenario:**
1. Create binary that allocates large buffers (1GB+)
2. Set memory_limit to 512MB
3. Run dynamic analysis
4. Verify:
   - Analysis completes (or terminates gracefully)
   - Warning logged if limit approached
   - No system-wide memory exhaustion

**Expected Results:**
- Process monitored for memory usage
- Warning if >80% of limit used
- Graceful termination if limit exceeded

**Test Data Required:**
- Binary allocating 1GB in chunks
- Expected: Memory warning, possible incomplete result

**Note:** Current implementation has monitoring only, not enforcement. Test should verify monitoring works.

---

#### INT-07: Error Recovery - Binary Crash Handling

**Priority:** HIGH
**Estimated Time:** 4 hours
**Complexity:** Medium

**Objective:** Verify graceful handling of binary crashes

**Test Scenario:**
1. Create binary that crashes (segfault, divide by zero, etc.)
2. Run dynamic analysis
3. Verify:
   - Crash detected
   - Partial results saved
   - `incomplete` = true
   - `incomplete_reason` = "crash" or "process_exited"
   - No runner crashes
   - Cleanup happens

**Expected Results:**
- `dynamic_results.json` written
- Events collected before crash saved
- Error message describes crash
- Sandbox cleaned up

**Test Data Required:**
- Binary with intentional crash (null pointer deref)
- Expected: Partial traces, incomplete result

**Code Example:**
```c
int main() {
    printf("Before crash\n");
    int *p = NULL;
    *p = 42;  // Crash here
    return 0;
}
```

---

#### INT-08: Cache Hit/Miss with Real Binaries

**Priority:** MEDIUM
**Estimated Time:** 3 hours
**Complexity:** Low

**Objective:** Verify cache works correctly with real analysis results

**Test Scenario:**
1. Run analysis on test_crypto.exe (cache miss)
2. Verify cache metadata written
3. Run analysis again with same config (cache hit)
4. Verify:
   - Second run uses cache
   - Results identical
   - Execution time much faster (<1s)
   - Cache metadata validates correctly

**Expected Results:**
- First run: `cached: false`, normal execution time
- Second run: `cached: true`, <1s execution time
- Results match exactly

**Cache Invalidation Test:**
- Modify hints.json
- Re-run → cache miss
- New results generated

---

### 3.3 MEDIUM Priority Tests (Nice-to-Have)

#### INT-09: Stripped Binary (No Debug Symbols)

**Priority:** MEDIUM
**Estimated Time:** 3 hours
**Complexity:** Low

**Objective:** Verify analysis works without debug symbols

**Test Scenario:**
1. Compile test_crypto.exe with `/RELEASE` (no symbols)
2. Run dynamic analysis
3. Verify hooks still work (address-based, not symbol-based)

**Expected Results:**
- Hooks load successfully
- Trace events collected
- Results valid

---

#### INT-10: Network Blocking Verification

**Priority:** MEDIUM
**Estimated Time:** 4 hours
**Complexity:** Medium

**Objective:** Verify network operations are blocked during analysis

**Test Scenario:**
1. Create binary that attempts HTTP request
2. Run with network blocking enabled (via Frida hooks)
3. Verify:
   - Network call blocked
   - Warning logged
   - Binary doesn't hang
   - Analysis completes

**Expected Results:**
- Network operations fail
- No actual network traffic
- Event logged in traces

---

#### INT-11: Multi-threaded Crypto Operations

**Priority:** LOW
**Estimated Time:** 6 hours
**Complexity:** High

**Objective:** Verify concurrent crypto calls are traced correctly

**Test Scenario:**
1. Create binary with 4 threads calling BCryptEncrypt
2. Run dynamic analysis
3. Verify:
   - All threads' calls captured
   - No race conditions in trace collection
   - Thread IDs logged
   - Call graph shows parallel paths

**Expected Results:**
- Events from all threads present
- `thread_id` field populated
- No missing events due to races

---

#### INT-12: Large Binary (>50MB)

**Priority:** LOW
**Estimated Time:** 3 hours
**Complexity:** Low

**Objective:** Verify performance with large binaries

**Test Scenario:**
1. Use large binary (>50MB) or artificially inflate test_crypto.exe
2. Run dynamic analysis
3. Verify:
   - Analysis completes in reasonable time (<10 minutes)
   - Memory usage acceptable (<1GB)
   - Results valid

---

## 4. Test Infrastructure Requirements

### 4.1 Test Binaries Needed

| Binary | Purpose | Size | Complexity | Priority |
|--------|---------|------|------------|----------|
| `test_crypto_timeout.exe` | Timeout testing | <1MB | Low | CRITICAL |
| `test_bcrypt.exe` | Windows Crypto API | <1MB | Medium | HIGH |
| `test_crash.exe` | Error recovery | <100KB | Low | HIGH |
| `test_crypto_heavy.exe` | 10k events | <2MB | Medium | HIGH |
| `test_crypto_stripped.exe` | No symbols | <1MB | Low | MEDIUM |
| `test_crypto_network.exe` | Network blocking | <1MB | Medium | MEDIUM |
| `test_crypto_multithread.exe` | Concurrency | <2MB | High | LOW |
| `test_crypto_large.exe` | Performance | >50MB | Low | LOW |

### 4.2 Test Fixtures

**Create:** `tests/fixtures/dynamic/`

```
tests/fixtures/dynamic/
├── binaries/
│   ├── test_crypto_timeout.exe
│   ├── test_bcrypt.exe
│   ├── test_crash.exe
│   └── ...
├── hints/
│   ├── test_crypto_timeout_hints.json
│   ├── test_bcrypt_hints.json
│   └── ...
├── configs/
│   ├── timeout_5s.json
│   ├── high_limit.json
│   └── ...
└── expected_results/
    ├── test_bcrypt_expected.json
    └── ...
```

### 4.3 Pytest Fixtures Required

```python
# tests/conftest.py additions

import pytest
from pathlib import Path

@pytest.fixture
def dynamic_fixtures_dir():
    """Return path to dynamic test fixtures."""
    return Path(__file__).parent / "fixtures" / "dynamic"

@pytest.fixture
def test_binaries_dir(dynamic_fixtures_dir):
    """Return path to test binaries."""
    return dynamic_fixtures_dir / "binaries"

@pytest.fixture
def test_crypto_exe(test_binaries_dir):
    """Return path to test_crypto.exe."""
    return test_binaries_dir / "test_crypto.exe"

@pytest.fixture
def test_bcrypt_exe(test_binaries_dir):
    """Return path to test_bcrypt.exe."""
    exe_path = test_binaries_dir / "test_bcrypt.exe"
    if not exe_path.exists():
        pytest.skip("test_bcrypt.exe not compiled")
    return exe_path

@pytest.fixture
def frida_available():
    """Check if Frida is available."""
    try:
        import frida
        return True
    except ImportError:
        return False

@pytest.fixture
def skip_if_no_frida(frida_available):
    """Skip test if Frida not available."""
    if not frida_available:
        pytest.skip("Frida not installed")
```

### 4.4 CI/CD Considerations

**Pytest Markers:**
```python
# pyproject.toml
[tool.pytest.ini_options]
markers = [
    "integration: Integration tests (requires Frida, binaries)",
    "slow: Slow tests (>30s)",
    "requires_frida: Requires Frida installation",
    "windows_only: Windows-specific tests",
]
```

**Running Tests:**
```bash
# Unit + E2E only (fast, no Frida required)
pytest tests/test_dynamic_detection_units.py tests/test_dynamic_detection_e2e.py

# Integration tests (requires Frida)
pytest tests/test_dynamic_detection_integration.py -m integration

# All tests
pytest tests/test_dynamic_detection_*.py

# Skip slow tests
pytest tests/test_dynamic_detection_*.py -m "not slow"
```

---

## 5. Implementation Timeline

### Week 1: Critical Tests (Nov 11-13)

| Day | Tests | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | INT-01: Real Binary + Setup | 6h | Test framework, fixtures, INT-01 passing |
| Tue | INT-02: Timeout + INT-03: Batch | 8h | Timeout binary, batch test passing |
| Wed | INT-04: 10k Events | 5h | High-frequency binary, limit test passing |

**Milestone 1:** 4/12 integration tests passing (33%)

### Week 2: High Priority Tests (Nov 14-15)

| Day | Tests | Hours | Deliverables |
|-----|-------|-------|--------------|
| Thu | INT-05: BCrypt API + INT-06: Memory | 10h | BCrypt binary, memory test |
| Fri | INT-07: Crash + INT-08: Cache | 7h | Crash binary, cache test |

**Milestone 2:** 8/12 integration tests passing (67%)

### Optional: Medium Priority (Nov 16-17)

| Day | Tests | Hours | Deliverables |
|-----|-------|-------|--------------|
| Sat | INT-09-12: Remaining tests | 12h | All integration tests complete |

**Milestone 3:** 12/12 integration tests passing (100%)

---

## 6. Success Criteria

### Phase 7 Completion Checklist

- [x] Unit tests: 9/9 passing (100%)
- [x] E2E tests: 8/8 passing (100%)
- [ ] Integration tests: 0/8 passing (0%) → **TARGET: 8/8**
- [ ] Test documentation complete
- [ ] CI/CD pipeline configured
- [ ] All test binaries compiled and checked in

### Quality Metrics

| Metric | Target | Current | Gap |
|--------|--------|---------|-----|
| Test Pass Rate | 100% | 100% | ✅ |
| Code Coverage | 80% | ~68% | 12% |
| Integration Coverage | 8/8 tests | 0/8 | 8 tests |
| Documentation | Complete | 75% | 25% |

---

## 7. Risk Assessment

### High Risk Items

1. **Frida Installation on CI** - May require Docker or pre-installed environment
   - *Mitigation:* Mark integration tests as `@pytest.mark.requires_frida`, skip if not available

2. **Binary Compilation Complexity** - BCrypt test requires Windows SDK
   - *Mitigation:* Provide pre-compiled binaries, document build steps

3. **Timeout Test Flakiness** - Timing-dependent tests can be unstable
   - *Mitigation:* Use generous tolerances (±2s), retry logic

### Medium Risk Items

4. **Large Trace Collection Performance** - May be slow on CI
   - *Mitigation:* Mark as `@pytest.mark.slow`, allow 5-10 minutes

5. **Network Blocking Verification** - Requires actual network access check
   - *Mitigation:* Use local loopback, verify connection refused

---

## 8. Estimated Effort Summary

### By Priority

| Priority | Tests | Total Hours | Binaries Needed |
|----------|-------|-------------|-----------------|
| CRITICAL | 4 | 20h | 3 |
| HIGH | 4 | 21h | 3 |
| MEDIUM | 4 | 16h | 2 |
| **TOTAL** | **12** | **57h** | **8** |

### Minimal Viable Set (Phase 7 Completion)

**Recommendation:** Focus on CRITICAL + HIGH priority tests (8 tests, 41 hours)

This provides:
- Real Frida execution verification (INT-01)
- Timeout enforcement (INT-02)
- Batch processing (INT-03)
- Limit enforcement (INT-04)
- Windows Crypto API (INT-05)
- Memory limits (INT-06)
- Error recovery (INT-07)
- Cache validation (INT-08)

**Estimated Time:** 1.5-2 weeks with 1 developer

---

## 9. Recommended Next Actions

### Immediate (Nov 11-12)

1. **Set up test infrastructure**
   - Create `tests/fixtures/dynamic/` directory structure
   - Add pytest fixtures to `conftest.py`
   - Configure pytest markers in `pyproject.toml`

2. **Compile test binaries**
   - Start with `test_crypto_timeout.exe` (simple sleep binary)
   - Compile `test_crash.exe` (intentional crash)
   - Compile `test_bcrypt.exe` (Windows Crypto API)

3. **Implement INT-01**
   - Real binary with Frida spawn mode
   - Verify end-to-end integration works
   - Debug any Frida integration issues

### Short-term (Nov 13-15)

4. **Implement CRITICAL tests (INT-02, INT-03, INT-04)**
   - Timeout enforcement
   - Batch processing
   - 10k event limit

5. **Implement HIGH priority tests (INT-05 through INT-08)**
   - BCrypt API detection
   - Memory limits
   - Error recovery
   - Cache validation

### Before Phase 7 Sign-off

6. **Documentation updates**
   - Update `dynamic_analysis_progress.md` with test results
   - Document all test binaries and their purposes
   - Create test execution guide

7. **CI/CD configuration**
   - Add integration test job (optional, requires Frida)
   - Configure test markers and timeouts
   - Add badge to README

---

## 10. Appendix

### A. Test Binary Compilation Guide

#### Timeout Test Binary
```c
// test_crypto_timeout.c
#include <stdio.h>
#include <windows.h>

int main() {
    printf("Starting long operation...\n");
    Sleep(15000);  // 15 seconds
    printf("Completed\n");
    return 0;
}
```

**Compile:**
```cmd
cl.exe test_crypto_timeout.c /Fe:test_crypto_timeout.exe
```

#### BCrypt Test Binary
```c
// test_bcrypt.c
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

int main() {
    BCRYPT_ALG_HANDLE hAlg;
    NTSTATUS status;

    printf("Opening BCrypt algorithm...\n");
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        printf("Failed to open algorithm\n");
        return 1;
    }

    // Encrypt dummy data
    UCHAR key[16] = {0x01, 0x02, 0x03, 0x04, /* ... */};
    UCHAR data[16] = {0x11, 0x12, 0x13, 0x14, /* ... */};
    ULONG result;

    printf("Calling BCryptEncrypt...\n");
    status = BCryptEncrypt(
        hAlg,
        data,
        16,
        NULL,
        NULL,
        0,
        data,
        16,
        &result,
        0
    );

    printf("BCryptEncrypt returned: 0x%x\n", status);

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}
```

**Compile:**
```cmd
cl.exe /MD test_bcrypt.c /link bcrypt.lib
```

#### Crash Test Binary
```c
// test_crash.c
#include <stdio.h>

int main() {
    printf("About to crash...\n");
    int *p = NULL;
    *p = 42;  // Segfault
    return 0;
}
```

**Compile:**
```cmd
cl.exe test_crash.c /Fe:test_crash.exe
```

### B. Expected Test Results Structure

```json
{
  "file_hash": "abc123...",
  "schema_version": "1.0",
  "timestamp": "2025-11-11T12:00:00Z",
  "mode": "spawn",
  "incomplete": false,
  "summary": {
    "total_crypto_calls": 1,
    "unique_functions": ["BCryptEncrypt"],
    "execution_time_seconds": 0.5
  },
  "findings": [
    {
      "id": "dynamic_1",
      "type": "crypto_call",
      "function": "BCryptEncrypt",
      "module": "bcrypt.dll",
      "count": 1,
      "confidence": 1.0
    }
  ],
  "trace_summary": {
    "total_events": 2,
    "crypto_calls": 1,
    "crypto_returns": 1,
    "size_bytes": 256,
    "limits_reached": {
      "max_events": false,
      "max_crypto_calls": false,
      "max_size": false
    }
  }
}
```

### C. Integration Test Template

```python
# tests/test_dynamic_detection_integration.py

import pytest
import os
import json
from pathlib import Path
from auditor.detectors.dynamic_detection import DynamicRunner, DynamicContext

pytestmark = pytest.mark.integration

@pytest.fixture
def temp_workspace(tmp_path):
    """Create temporary workspace for integration tests."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Create directory structure
    (workspace / "preproc").mkdir()
    (workspace / "analysis" / "static").mkdir(parents=True)
    (workspace / "analysis" / "dynamic").mkdir(parents=True)

    return workspace

@pytest.mark.requires_frida
def test_int_01_real_binary_spawn(test_crypto_exe, temp_workspace, skip_if_no_frida):
    """INT-01: Real binary with Frida spawn mode."""

    # Setup
    file_hash = "test_abc123"
    preproc_dir = temp_workspace / "preproc" / file_hash
    preproc_dir.mkdir()

    # Copy binary
    import shutil
    shutil.copy(test_crypto_exe, preproc_dir / "input.bin")

    # Create metadata
    metadata = {
        "file_hash": file_hash,
        "filename": "test_crypto.exe",
        "size": os.path.getsize(test_crypto_exe),
        "file_type": "pe"
    }
    with open(preproc_dir / "metadata.json", "w") as f:
        json.dump(metadata, f)

    # Create minimal hints
    hints = {
        "file_hash": file_hash,
        "hints": [
            {
                "id": "h1",
                "type": "crypto_function",
                "name": "xor_encrypt",
                "confidence": 0.8
            }
        ]
    }
    static_dir = temp_workspace / "analysis" / "static" / file_hash
    static_dir.mkdir(parents=True)
    hints_path = static_dir / "hints.json"
    with open(hints_path, "w") as f:
        json.dump(hints, f)

    # Run dynamic analysis
    ctx = DynamicContext(
        file_hash=file_hash,
        preproc_dir=str(preproc_dir),
        hints_path=str(hints_path),
        analysis_base=str(temp_workspace),
        mode="spawn",
        timeout=10
    )

    runner = DynamicRunner()
    result = runner.run(ctx)

    # Assertions
    assert result.is_success(), f"Analysis failed: {result.errors}"
    assert os.path.exists(result.dynamic_results_path), "Results file not created"
    assert os.path.exists(result.trace_path), "Trace file not created"

    # Verify results structure
    with open(result.dynamic_results_path, "r") as f:
        results_data = json.load(f)

    assert results_data["file_hash"] == file_hash
    assert results_data["mode"] == "spawn"
    assert results_data["incomplete"] == False
    assert "summary" in results_data
    assert "findings" in results_data

    # Verify traces exist
    with open(result.trace_path, "r") as f:
        trace_lines = f.readlines()

    assert len(trace_lines) > 0, "No trace events collected"

    print(f"✓ INT-01 PASSED: Collected {len(trace_lines)} events")
```

---

## Conclusion

Phase 7 integration testing is essential to validate the dynamic analysis system with real-world scenarios. The current 75% completion (17/17 tests passing) represents excellent progress on unit and E2E testing, but integration tests with real binaries are critical for production readiness.

**Recommended Path Forward:**
1. Implement 8 CRITICAL + HIGH priority integration tests (41 hours)
2. Compile 6 test binaries (8 hours)
3. Document test execution and results (4 hours)
4. **Total Effort:** ~53 hours (1.5-2 weeks)

This will achieve **100% Phase 7 completion** and provide confidence that the dynamic analysis system works correctly in production scenarios before proceeding to Phase 8 (Hardening & Infrastructure).

---

**Document Version:** 1.0
**Last Updated:** 2025-11-11
**Next Review:** 2025-11-15 (Phase 7 completion target)
