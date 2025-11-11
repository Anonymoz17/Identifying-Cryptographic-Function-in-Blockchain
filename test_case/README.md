# Test Case Setup - Binary Compilation Guide

## Overview

This directory contains **test files + real system binaries** for full pipeline testing (Setup → Static Analysis → Dynamic Analysis).

### Files Included

#### Source Code Files (Processed by Setup & Static Analysis)

- **crypto_hash.py**: Python file demonstrating SHA256, MD5, SHA512, HMAC, and secrets module
- **file_operations.py**: Python file with NO crypto - for contrast testing
- **crypto_utils.c**: C source with Windows Crypto APIs (BCrypt)
- **file_utils.c**: C source with NO crypto - for contrast

#### Pre-compiled Windows Binaries (For Dynamic Analysis - shows actual results!)

- **certutil.exe**: Certificate management utility - **USES CRYPTO APIs** ✓
- **cipher.exe**: File encryption/decryption utility - **USES CRYPTO APIs** ✓
- **certreq.exe**: Certificate request tool - **USES CRYPTO APIs** ✓
- **bcdedit.exe**: Boot configuration tool - may use crypto for TPM
- **dism.exe**: Deployment image tool - may use crypto
- **powershell.exe**: PowerShell - uses crypto for security policies
- **minimal_crypto.exe**: Minimal test binary

## Compilation Instructions

### ✅ Binaries Already Included!

Real system binaries are already in this folder:

- **certutil.exe** (2-3 MB) - Uses Windows Crypto APIs
- **cipher.exe** (500 KB) - Encryption utility
- **certreq.exe** (800 KB) - Certificate request
- **bcdedit.exe**, **dism.exe**, **powershell.exe** - Other system utilities

**No compilation needed!** These are ready to use with Frida.

## Expected Analysis Results

### Setup Phase

- ✅ Will enumerate: crypto_hash.py, file_operations.py, crypto_utils.c, file_utils.c
- ❌ Will skip: .exe files (by design - binaries intentionally excluded during Setup)
- Creates: hints.json with function metadata from source files

### Static Analysis Phase

- ✅ crypto_hash.py: Detects hashlib, hmac, secrets imports → Flags as CRYPTO
- ✅ file_operations.py: Detects json, csv imports → Flags as NON-CRYPTO
- ✅ crypto_utils.c: Detects BCryptHashData, BCryptCreateHash → Flags as CRYPTO
- ✅ file_utils.c: Detects standard file I/O → Flags as NON-CRYPTO
- **Result**: hints.json populated with crypto function signatures

### Dynamic Analysis Phase ⭐

- ✅ Requires hints.json from Static Analysis (now available!)
- ✅ Frida attaches to .exe processes
- ✅ **SHOWS ACTUAL CRYPTO CALL TRACES** from certutil.exe, cipher.exe, etc.
- ✅ Compares runtime calls against hints → **REAL RESULTS**
- ✓ You will see crypto function calls detected!

**Key Difference from Source Code**:

- Source code (.py, .c) → 0 calls (cannot execute)
- Real binaries (.exe) → ACTUAL CRYPTO CALLS (shows real results!)

## Full Test Workflow

```powershell
# 1. Load test_case folder as a Case in Detectors page
# 2. Run Setup
#    → Processes .py and .c source files
#    → Creates hints.json with function signatures

# 3. Run Static Analysis
#    → Analyzes source patterns
#    → Populates hints with crypto calls

# 4. Run Dynamic Analysis (WITH REAL BINARIES!)
#    → Loads hints.json
#    → Runs certutil.exe, cipher.exe via Frida
#    → Captures actual crypto API calls
#    → Shows REAL RESULTS ✅
```

## Expected Outcome

- ✅ Setup: Creates hints.json
- ✅ Static Analysis: Detects crypto in source files
- ✅ Dynamic Analysis: **SHOWS ACTUAL CRYPTO TRACES** (not 0!)
- ✅ Results folder: Created with trace events

## Troubleshooting

### Dynamic Analysis still shows "Incomplete"

- Verify hints.json was created after Static Analysis
- Check that dynamic runner has hints.json path configured
- Review logs for Frida attachment status

### "No crypto calls" in Dynamic Analysis

- This is EXPECTED if using only source code
- **Solution**: We now have real .exe binaries that use crypto!
- certutil.exe, cipher.exe will show actual traces

### .exe files excluded from Setup

- **By design**: Setup skips binary files (DEFAULT_DENY_BIN_EXTS)
- Dynamic Analysis uses binaries AFTER Static creates hints
- Pipeline: Source files → hints → Apply to binaries

## Key Differences

| Before                            | Now                               |
| --------------------------------- | --------------------------------- |
| ❌ Only source code (.py, .c)     | ✅ Real Windows binaries (.exe)   |
| ❌ 0 crypto calls (can't execute) | ✅ ACTUAL CALLS (real execution!) |
| ❌ "Incomplete" status            | ✅ "Completed" status             |
| ❌ No trace results               | ✅ Real trace events in results/  |

## Next Steps

1. ✅ Load test_case as Case
2. ✅ Run Setup (creates hints.json)
3. ✅ Run Static Analysis (populates hints)
4. ✅ Run Dynamic Analysis (shows REAL crypto traces!)
5. ✅ Review results/ for trace events

For detailed troubleshooting, see: `DYNAMIC_ANALYSIS_TROUBLESHOOTING.md`
