# Quick Fix Guide: Dynamic Detection Issue

## TL;DR

Your dynamic analysis is working correctly, but showing **0 crypto calls** because your test case has **source code files** (Python, C, etc.), not compiled binaries.

**Why?** Dynamic analysis needs a **running executable process** to hook into. Source code is just text and can't execute.

**Fix:** Either:

1. **Use Static Analysis** (works on source code - you already did this!)
2. **Compile to binaries** then run dynamic analysis

---

## What's Happening

### Your Results

```
✓ 180 successful analyses
✓ No errors
✗ 0 crypto calls found
✗ Marked as incomplete
```

### Why

- **Spawn mode:** Frida successfully spawned 180 processes, but source code files aren't executables so they either:

  - Fail to execute
  - Don't load crypto DLLs
  - Have no runtime function calls to hook
  - Result: 0 traces, marked incomplete

- **Hook mode:** Same issue, but reported as errors (tried to attach to non-executables)

---

## Verify Your Case Has Source Code

```bash
# Quick check in PowerShell
cd your_workspace
python -c "
import json
from pathlib import Path

preproc = Path('preproc')
types = {}
for h in preproc.iterdir():
    m = json.load(open(h/'metadata.json'))
    ft = m.get('file_type', 'unknown')
    types[ft] = types.get(ft, 0) + 1

for ft, count in types.items():
    print(f'{ft}: {count}')
"
```

If you see "python", "c", "java", "javascript", etc. → **Source code confirmed**

---

## Solution: Use What You Have (Static Analysis)

You already have static analysis working! It's actually **better for source code**:

```python
# Static analysis directly reads source code
# No compilation needed
# Shows function definitions, imports, patterns

# It already found your crypto functions!
# See: workspace/analysis/static/{hash}/findings.json
```

### Why Not Dynamic?

Dynamic analysis requires:

- Executable files (.exe, .dll, etc.)
- Running process
- Loaded DLLs (bcrypt.dll, crypt32.dll, etc.)
- Runtime function calls

Source code has none of these at runtime.

---

## If You Want Dynamic Analysis

### Step 1: Compile Your Source Code

**Python to EXE:**

```bash
pip install pyinstaller
pyinstaller --onefile your_script.py
# Output: dist/your_script.exe
```

**C to EXE:**

```bash
# MSVC
cl crypto.c /Fe crypto.exe

# Or MinGW
gcc crypto.c -o crypto.exe
```

**C# to EXE:**

```bash
csc.exe yourcode.cs
```

### Step 2: Update Your Case

```bash
# Copy compiled binary to preproc
cp your_script.exe workspace/preproc/{hash}/input.bin

# Update metadata.json
{
  "file_hash": "...",
  "file_type": "executable",        # Changed from "python"
  "size_bytes": 123456,
  "original_filename": "your_script.py",
  ...
}
```

### Step 3: Run Dynamic Analysis

Now it will work! Frida can hook into the running process.

---

## Recommended Workflow

For a mixed codebase (source + binaries):

```
┌─ Source Code Files
│  └─ Use Static Analysis ✓
│
├─ Binary Files
│  ├─ Use Static Analysis ✓
│  └─ Use Dynamic Analysis ✓ (better)
│
└─ For Both
   ├─ Run static first (finds all crypto functions)
   └─ Then run dynamic on binaries only (shows runtime behavior)
```

---

## FAQ

**Q: Does this mean something is broken?**
A: No! Your installation is correct. This is expected behavior for source code.

**Q: Will dynamic analysis ever work on source code?**
A: Only if compiled to executable binary first.

**Q: Should I worry about the "incomplete" status?**
A: No. It's correctly marking that no traces were collected (because there's nothing to trace).

**Q: Can I mix static and dynamic results?**
A: Yes! Run static on everything, dynamic on binaries only, then combine.

**Q: How do I know if static analysis is enough?**
A: For source code inspection, always. For binary behavior verification, you need dynamic.

---

## What I Fixed

1. **Added file type validation** - Now detects when you try to run dynamic on source code
2. **Better error messages** - Will tell you specifically: "Python file detected. Use static analysis instead."
3. **Diagnostic tool** - `python diagnose_dynamic_issue.py <workspace>` tells you exactly what's in your case

---

## Next Time

When loading a case with source code:

- ✓ Use **Static Detector** for function analysis
- ✓ Use results for pattern detection
- ✗ Skip Dynamic Detector (will show 0 calls)

For binaries:

- ✓ Use both Static (fast) and Dynamic (accurate runtime info)
- ✓ Combine results for complete picture

---

## Still Have Questions?

Check the full analysis document:

- `docs/DYNAMIC_ANALYSIS_SOURCE_CODE_ISSUE.md`

Or run diagnostics:

```bash
python diagnose_dynamic_issue.py "C:\path\to\workspace"
```

---

**Summary:** Your setup is working correctly. Source code needs static analysis. Binaries can use both. No action needed unless you want to test with actual executables!
