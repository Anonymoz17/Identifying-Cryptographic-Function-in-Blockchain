# Dynamic Detection Issue: Root Cause Analysis & Solutions

## Executive Summary

Your dynamic analysis is working correctly, but it's detecting **0 crypto calls** because your test case contains **source code files** (Python, C, etc.), not compiled binaries.

**Dynamic analysis requires compiled binaries** to work. It uses Frida to intercept function calls at runtime by hooking into DLL exports (like `bcrypt.dll`). Source code files cannot be executed directly and therefore have no runtime function calls to intercept.

---

## Why This Happens

### How Dynamic Analysis Works

Dynamic analysis uses **Frida** to:

1. Spawn or attach to a binary process
2. Inject JavaScript hooks into the process
3. Intercept calls to crypto functions (e.g., `BCryptEncrypt` from `bcrypt.dll`)
4. Collect trace data when these functions are called

### Why Source Code Files Fail

Source code files (`.py`, `.c`, `.java`, etc.) **cannot** be executed directly:

- They're text files, not executable programs
- Frida needs a running process to inject into
- Even if "executed", the source code won't have compiled crypto function calls
- Therefore: **No calls to intercept = No traces collected = 0 crypto findings**

### What You're Seeing

```
Summary: 180 successful, 0 errors
Traces: AGGREGATED FINDINGS (0 crypto calls from 180 binaries)
Result: Marked as incomplete
```

This is actually **correct behavior**:

- ✓ All 180 files were "analyzed" (process completed)
- ✓ No errors occurred
- ✓ Correctly reported 0 crypto calls (because none exist at runtime)
- ⚠️ Marked incomplete because Frida couldn't actually hook any functions

---

## Verification: Confirm Your Case Has Source Code

Your case structure likely looks like:

```
workspace/
├── preproc/
│   ├── hash1/
│   │   ├── input.bin          (Python source: test.py)
│   │   └── metadata.json      (file_type: "python")
│   ├── hash2/
│   │   ├── input.bin          (C source: crypto.c)
│   │   └── metadata.json      (file_type: "c")
│   └── ... (180 files total)
├── analysis/
│   ├── static/                (✓ Works fine)
│   └── dynamic/               (✗ No traces)
```

To verify, run:

```python
from pathlib import Path
import json

workspace = Path("your_workspace_path")
preproc_dir = workspace / "preproc"

file_types = {}
for hash_dir in preproc_dir.iterdir():
    metadata = hash_dir / "metadata.json"
    if metadata.exists():
        with open(metadata) as f:
            meta = json.load(f)
            file_type = meta.get('file_type')
            file_types[file_type] = file_types.get(file_type, 0) + 1

print("Files by type:")
for ft, count in sorted(file_types.items()):
    print(f"  {ft}: {count}")
```

---

## Solutions

### Option 1: ✓ Use Static Analysis Only (RECOMMENDED for Source Code)

**Best for:** Source code analysis, open-source projects, development code

Static analysis directly reads the source code and doesn't need compilation:

```python
from auditor.detectors import StaticDetector

detector = StaticDetector()
result = detector.analyze(
    file_hash='your_hash',
    workspace='your_workspace'
)

print(f"Crypto functions found: {result['summary']['total_functions']}")
```

**Advantages:**

- ✓ Works with source code directly
- ✓ Gives function definitions, argument types, etc.
- ✓ Faster (no compilation needed)
- ✓ No runtime overhead

**Limitations:**

- ✗ Cannot detect runtime behavior (e.g., which functions actually get called)
- ✗ May miss dynamically generated code

---

### Option 2: Compile Source to Binaries (For True Dynamic Analysis)

**Best for:** Windows executables, production binaries, compiled languages

If you want to use dynamic analysis, compile your source code first:

**For Python:**

```bash
# Create an executable wrapper
pyinstaller --onefile your_script.py
# Binary will be in: dist/your_script.exe
```

**For C/C++:**

```bash
# Compile with MSVC
cl.exe crypto.c /Fe crypto.exe

# Or with MinGW-w64
gcc crypto.c -o crypto.exe
```

**For C#:**

```bash
# Compile to EXE
csc.exe your_code.cs
```

Once compiled:

1. Copy `.exe` file to preproc as `input.bin`
2. Update `metadata.json` with correct `file_type` ("executable", "pe32", etc.)
3. Run dynamic analysis

---

### Option 3: Use Both (Hybrid Approach)

**Best for:** Complete analysis

1. **Static analysis** on source code → Find crypto functions
2. **Dynamic analysis** on compiled binaries → Verify runtime behavior

---

## How to Fix the UI

### 1. Add Pre-Analysis Validation

Update `src/pages/detectors.py` to warn users about source code files:

```python
def _validate_for_dynamic_analysis(self, workdir):
    """Check if case is suitable for dynamic analysis."""
    warnings = []
    source_types = {
        'python', 'c', 'cpp', 'java', 'javascript',
        'csharp', 'go', 'rust', 'source', 'text'
    }

    preproc_dir = Path(workdir) / "preproc"
    source_count = 0
    binary_count = 0

    for hash_dir in preproc_dir.iterdir():
        metadata = hash_dir / "metadata.json"
        if metadata.exists():
            with open(metadata) as f:
                meta = json.load(f)
                file_type = meta.get('file_type', '').lower()

                if any(st in file_type for st in source_types):
                    source_count += 1
                else:
                    binary_count += 1

    if source_count > binary_count:
        warnings.append(
            f"⚠️ {source_count}/{source_count+binary_count} files are source code.\n"
            "Dynamic analysis requires compiled BINARIES.\n"
            "Consider using Static Analysis instead."
        )

    return warnings
```

### 2. Show Warning Before Analysis

```python
def _on_run_dynamic_analysis_clicked(self):
    """Run dynamic analysis with pre-checks."""
    warnings = self._validate_for_dynamic_analysis(self._case_workdir)

    if warnings:
        from tkinter import messagebox
        choice = messagebox.askyesno(
            "Source Code Detected",
            "\n".join(warnings) + "\n\nContinue anyway?"
        )
        if not choice:
            return

    # Proceed with analysis...
    self._batch_dynamic_analysis_thread()
```

---

## Understanding the Results

### Why "180 successful" but no traces?

1. **Spawn mode working correctly:**

   - ✓ Frida spawns each binary
   - ✓ Scripts inject successfully
   - ✓ Hooks install (on dlls that load)
   - ✗ Source code binaries don't load crypto DLLs
   - ✗ No function calls occur
   - ✓ Process completes normally
   - Result: "Successful" but "incomplete" (no traces)

2. **Hook mode showing errors:**
   - ✓ Frida tries to hook
   - ✗ Source code is a text file, not executable
   - ✓ Gets caught in error handling
   - Result: "Error" status

### Empty Call Graph

The call graph is empty because:

- No crypto function calls were intercepted
- Dynamic analysis only captures actual runtime calls
- Source code files never execute at runtime

---

## Best Practices Going Forward

### For Production Use

**Workflow:**

```
Setup Case
    ↓
Static Analysis (works on source code)
    ↓
Review Findings
    ↓
Compile Binaries (if needed)
    ↓
Dynamic Analysis (on compiled binaries)
    ↓
Compare Results
```

### For Testing

Use actual binaries:

```powershell
# Get a real Windows executable
# E.g., from System32: C:\Windows\System32\certutil.exe

# Or create a test binary
python -m PyInstaller --onefile test_crypto.py

# Add to your test case
cp dist/test_crypto.exe preproc/{hash}/input.bin
```

---

## FAQ

**Q: Why does it say "180 successful" if there are no results?**
A: The analysis process completed successfully for all 180 files. It just found no crypto calls at runtime, which is expected for source code.

**Q: Can I make dynamic analysis work with source code?**
A: No, not directly. You must compile it first. Frida hooks DLL functions in running executables, not text files.

**Q: Why is the result marked as "incomplete"?**
A: Because Frida couldn't hook any actual crypto function calls. The system recognizes this as incomplete analysis data.

**Q: Should I be worried?**
A: No! Static analysis is actually superior for source code. Dynamic analysis is better for:

- Binaries without source code
- Verifying runtime behavior
- Finding dynamically loaded modules

**Q: How do I know if my case has binaries or source?**
A: Check `metadata.json` in each file's preproc directory. Look for `file_type`. If it says "python", "c", "java", etc., it's source code.

---

## Next Steps

### Immediate

1. **Confirm your case has source code:**

   ```python
   import json
   from pathlib import Path

   meta = json.load(open("workspace/preproc/{hash}/metadata.json"))
   print(f"File type: {meta['file_type']}")
   ```

2. **If it's source code:** Use static analysis (which already works!)

   ```python
   # Static analysis is fine for source code
   # Dynamic analysis will find nothing useful
   ```

3. **If you want dynamic analysis:** Compile your source code first

### Long-term

1. Add metadata display to UI showing which analysis works for each file type
2. Auto-skip dynamic analysis for known source code types
3. Add "Analysis Compatibility" section to case summary

---

## Support

If you have a case with actual `.exe` or `.dll` files that still shows 0 calls:

1. Run the diagnostic:

   ```bash
   python diagnose_dynamic_issue.py "workspace_path"
   ```

2. Check if:

   - ✓ Frida is properly installed
   - ✓ Binaries are actually PE format
   - ✓ Static hints were generated
   - ✓ Crypto APIs are loaded during execution

3. The issue might be that the binaries don't actually use crypto functions at runtime

---

## Appendix: How to Tell If Analysis Is Right

| Aspect                       | Static        | Dynamic          |
| ---------------------------- | ------------- | ---------------- |
| **Input**                    | Source/Binary | Binary only      |
| **Speed**                    | Fast          | Slow             |
| **Runtime Data**             | No            | Yes              |
| **For Source Code**          | ✓ Works       | ✗ Fails          |
| **For Binaries**             | ✓ Works       | ✓ Works (better) |
| **Detects Crypto Functions** | ✓ Yes         | ✓ If called      |
| **Shows Execution Flow**     | Partial       | Full             |

---

Generated: November 11, 2025
For: Identifying-Cryptographic-Function-in-Blockchain
