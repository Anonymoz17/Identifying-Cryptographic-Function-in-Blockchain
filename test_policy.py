"""Quick test to verify ghidra_policy filters correctly"""
import json
from pathlib import Path
from src.auditor.detectors.static_detection import ghidra_policy

# Test case 1: Python file (should skip)
metadata_python = {
    "mime": "text/x-python",
    "is_binary": False,
    "size": 4214
}

should_run, reason = ghidra_policy.should_run_ghidra(metadata_python)
print(f"Python file: should_run={should_run}, reason={reason}")
assert should_run == False, "Python files should be skipped"

# Test case 2: ELF binary (should run)
metadata_elf = {
    "mime": "application/x-executable",
    "is_binary": True,
    "size": 15000
}

should_run, reason = ghidra_policy.should_run_ghidra(metadata_elf)
print(f"ELF binary: should_run={should_run}, reason={reason}")
assert should_run == True, "ELF binaries should run Ghidra"

# Test case 3: Large file (should skip)
metadata_large = {
    "mime": "application/x-executable",
    "is_binary": True,
    "size": 10 * 1024 * 1024  # 10MB
}

should_run, reason = ghidra_policy.should_run_ghidra(metadata_large)
print(f"Large binary: should_run={should_run}, reason={reason}")
assert should_run == False, "Large files should be skipped"

# Test case 4: JavaScript (should skip)
metadata_js = {
    "mime": "application/javascript",
    "is_binary": False,
    "size": 1500
}

should_run, reason = ghidra_policy.should_run_ghidra(metadata_js)
print(f"JavaScript file: should_run={should_run}, reason={reason}")
assert should_run == False, "JavaScript files should be skipped"

# Test case 5: Windows PE (should run)
metadata_pe = {
    "mime": "application/x-dosexec",
    "is_binary": True,
    "size": 50000
}

should_run, reason = ghidra_policy.should_run_ghidra(metadata_pe)
print(f"Windows PE: should_run={should_run}, reason={reason}")
assert should_run == True, "Windows PE files should run Ghidra"

# Test case 6: Unknown but marked as binary (should run conservatively)
metadata_unknown = {
    "mime": "application/octet-stream",
    "is_binary": True,
    "size": 8000
}

should_run, reason = ghidra_policy.should_run_ghidra(metadata_unknown)
print(f"Unknown binary: should_run={should_run}, reason={reason}")
assert should_run == True, "Unknown binaries should run conservatively"

print("\n✅ All policy tests passed!")
print("\nPolicy summary:")
print("- Source code files (Python, JS, JSON, etc.) = SKIP")
print("- Known binaries (ELF, PE, Mach-O) = RUN")
print("- Files > 5MB = SKIP")
print("- Unknown files marked as binary = RUN (conservative)")
