# Quick Start - Run the Pipeline Now! 🚀

## What You Have

✅ **Real Windows binaries** that use crypto APIs (certutil.exe, cipher.exe, certreq.exe, etc.)
✅ **Source code files** for static analysis (Python and C files)
✅ **Complete pipeline setup** ready to test

## 3-Step Quick Start

### Step 1: Load the Test Case

```
1. Open Detectors page: http://localhost:5000/detectors
2. Create a new Case
3. Set Scope to: test_case/
4. Click "Create Case"
```

### Step 2: Run the Pipeline

```
Setup Phase:
  - Click "Setup" button
  - Wait for completion
  - ✅ Should create hints.json

Static Analysis Phase:
  - Click "Static Analysis" button
  - Wait for completion
  - ✅ Should show crypto detections

Dynamic Analysis Phase:
  - Click "Dynamic Analysis" button
  - Wait for completion
  - ✅ SHOULD NOW SHOW ACTUAL CRYPTO TRACES! (not 0 calls)
```

### Step 3: Review Results

```
1. Check results/ folder for trace events
2. Compare crypto vs non-crypto file results
3. Verify hints.json was used
4. Review SETUP_COMPLETE.md for details
```

## What to Expect

| Phase   | Status                | Details                         |
| ------- | --------------------- | ------------------------------- |
| Setup   | ✅ Complete           | Files found, hints.json created |
| Static  | ✅ Complete           | Crypto patterns detected        |
| Dynamic | ✅ NEW: SHOWS RESULTS | Real traces from binaries!      |

## Key Difference

**Before**: 0 crypto calls (source code can't execute)
**Now**: ACTUAL crypto calls (real binaries execute and use crypto)

## Included Binaries

- **certutil.exe** (1.51 MB) - Certificate utility with crypto
- **cipher.exe** (76 KB) - File encryption tool
- **certreq.exe** (520 KB) - Certificate request tool
- **powershell.exe** (444 KB) - Shell with security features
- And more...

All of these actually USE Windows Crypto APIs that Frida can hook!

## Troubleshooting

**Q: Pipeline not starting?**

- Make sure test_case folder is set as Scope
- Check logs for errors

**Q: Still showing "Incomplete" in Dynamic?**

- Verify hints.json exists (created by Setup/Static)
- Check if Dynamic Analysis is reading it

**Q: Crypto calls not showing?**

- The real binaries SHOULD show calls now!
- If not, review logs for Frida issues

## Files to Review

- **README.md** - Full setup guide
- **SETUP_COMPLETE.md** - What changed and why
- **TEST_SUMMARY.md** - Expected results
- **DYNAMIC_ANALYSIS_TROUBLESHOOTING.md** - More help

---

**Ready to test?** Load the test_case in Detectors and run the pipeline!
