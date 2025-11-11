# Test Case Files Summary

## Overview

This directory contains **9 files** for comprehensive pipeline testing:

- **4 Python files** - static analysis testing (various crypto patterns)
- **2 C source files** - Windows Crypto API testing
- **1 PowerShell script** - compilation helper
- **1 README** - documentation

## Files Breakdown

### Cryptographic Files (Static Analysis will flag these)

| File                    | Type     | Purpose              | Crypto Features                                         |
| ----------------------- | -------- | -------------------- | ------------------------------------------------------- |
| `crypto_hash.py`        | Python   | Basic hashing        | SHA256, MD5, SHA512, SHA1, HMAC, secrets                |
| `aes_encryption.py`     | Python   | Symmetric encryption | Fernet, PBKDF2, SHA256                                  |
| `rsa_operations.py`     | Python   | Asymmetric crypto    | RSA key generation, encryption, digital signatures      |
| `blockchain_signing.py` | Python   | Blockchain patterns  | ECDSA, transaction hashing, public key serialization    |
| `crypto_utils.c`        | C source | Windows Crypto API   | BCryptHashData, BCryptCreateHash, BCryptGenerateKeyPair |

### Non-Cryptographic Files (Static Analysis will NOT flag)

| File                 | Type     | Purpose      | Features                           |
| -------------------- | -------- | ------------ | ---------------------------------- |
| `file_operations.py` | Python   | File I/O     | JSON, CSV, file system operations  |
| `file_utils.c`       | C source | Standard I/O | File operations, memory management |

## Analysis Expected Results

### Setup Phase

✅ **Files Enumerated**: All 6 source files (.py, .c)
❌ **Excluded**: .exe files (by design - prevents duplicate analysis)

**Created**: `hints.json` with function signatures

### Static Analysis Phase

```
✓ crypto_hash.py        → [CRYPTO] Flags: hashlib, hmac, secrets
✓ aes_encryption.py     → [CRYPTO] Flags: cryptography.fernet, PBKDF2
✓ rsa_operations.py     → [CRYPTO] Flags: RSA, padding, signatures
✓ blockchain_signing.py → [CRYPTO] Flags: ECDSA, serialization
✓ crypto_utils.c        → [CRYPTO] Flags: BCrypt functions
✗ file_operations.py    → [NON-CRYPTO] No crypto patterns
✗ file_utils.c          → [NON-CRYPTO] No crypto patterns
```

**Expected**: ~200-250 crypto function hits across files

### Dynamic Analysis Phase

⚠️ **Important**: Source code cannot execute at runtime

- Requires compiled .exe binaries to show actual runtime traces
- 0 crypto calls expected for source code (CORRECT behavior)

**To get traces**:

1. Compile C files: `.\Compile-TestBinaries.ps1`
2. Copy real binaries: `copy C:\Windows\System32\certutil.exe .`

## Quick Start Workflow

```powershell
# 1. Navigate to project root
cd "c:\!Everything Programming\Github Projects\FYP\Identifying-Cryptographic-Function-in-Blockchain"

# 2. Open Detectors page (http://localhost:5000/detectors)
python src/app.py

# 3. Create Case with this folder (test_case)
# 4. Run Setup (processes .py and .c files)
# 5. Run Static Analysis (detects crypto patterns)
# 6. Run Dynamic Analysis (requires hints from step 5)

# 7. To test with actual binaries:
cd test_case
.\Compile-TestBinaries.ps1
# Then re-run pipeline with compiled .exe files
```

## File Statistics

| Category     | Count  | File Types                  |
| ------------ | ------ | --------------------------- |
| Source Code  | 6      | .py (4), .c (2)             |
| Utilities    | 2      | .ps1 (1), .md (1)           |
| **Compiled** | 2\*    | .exe (requires compilation) |
| **Total**    | 9-11\* | \*depends on compilation    |

## Expected Behavior Validation

### ✅ Correct Outcomes

1. **Setup**: Processes all 6 source files, skips .exe files
2. **Static**: Detects crypto in 5 files, non-crypto in 2 files
3. **Dynamic**: Shows "0 calls" (source code cannot execute) ← EXPECTED
4. **hints.json**: Created and populated after static analysis

### ❌ Issues to Watch For

| Issue                  | Cause                    | Solution                               |
| ---------------------- | ------------------------ | -------------------------------------- |
| "No files found"       | Case scope incorrect     | Set scope to `test_case/` directory    |
| "hints.json not found" | Skipped static analysis  | Run Static Analysis before Dynamic     |
| ".py/.c files missing" | File type filtering      | Check intake.py allowed extensions     |
| "Crypto count = 0"     | Expected for source code | Compile .exe files for dynamic testing |

## Troubleshooting

### Compilation Failed

```powershell
# If Visual Studio not available, use system binaries:
Copy-Item "C:\Windows\System32\certutil.exe" .
Copy-Item "C:\Windows\System32\notepad.exe" .
```

### Static Analysis Shows No Results

- Verify case Scope includes this directory
- Check that files are readable (permissions)
- Ensure hints.json exists after Setup

### Dynamic Analysis Incomplete

- Verify hints.json exists and contains function data
- Check that Python source files are in the preproc directory
- Confirm pipeline order: Setup → Static → Dynamic

## Next Steps

1. ✅ Test with this case folder
2. ✅ Compare crypto vs non-crypto detection
3. ✅ Verify pipeline flow (Setup → Static → Dynamic)
4. ✅ Review detection accuracy
5. ❓ Adjust false positive/negative rates as needed

---

For detailed documentation, see:

- `README.md` - Setup and compilation guide
- `DYNAMIC_ANALYSIS_TROUBLESHOOTING.md` - Troubleshooting guide
- `DYNAMIC_ANALYSIS_SUMMARY.md` - Complete analysis summary
