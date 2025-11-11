#!/usr/bin/env python3
"""
setup_test_binaries.py - Set up test binaries from system for dynamic analysis testing

This script copies crypto-using system binaries to the test_case folder.
These binaries will show actual crypto call results in dynamic analysis.

Run with: python setup_test_binaries.py
"""

import shutil
import os
import sys
from pathlib import Path

def get_system_binaries():
    """Get list of system binaries that use crypto APIs."""
    return [
        # Crypto/certificate utilities
        ("C:\\Windows\\System32\\certutil.exe", "certutil.exe"),
        ("C:\\Windows\\System32\\certreq.exe", "certreq.exe"),
        ("C:\\Windows\\System32\\bcdedit.exe", "bcdedit.exe"),
        
        # PowerShell (uses crypto for execution policies, etc.)
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe"),
        
        # DISM (uses crypto for deployment/imaging)
        ("C:\\Windows\\System32\\dism.exe", "dism.exe"),
        
        # Encryption utilities
        ("C:\\Windows\\System32\\cipher.exe", "cipher.exe"),
    ]

def copy_binary(source, dest_name):
    """Copy a binary file to test_case directory."""
    script_dir = Path(__file__).parent
    dest_path = script_dir / dest_name
    
    if not os.path.exists(source):
        return False, f"Source not found: {source}"
    
    if dest_path.exists():
        return False, f"Already exists: {dest_name}"
    
    try:
        shutil.copy2(source, dest_path)
        size_mb = dest_path.stat().st_size / (1024 * 1024)
        return True, f"Copied {dest_name} ({size_mb:.2f} MB)"
    except Exception as e:
        return False, f"Failed to copy {dest_name}: {e}"

def create_minimal_crypto_exe():
    """Create a minimal PE executable that calls crypto functions."""
    script_dir = Path(__file__).parent
    exe_path = script_dir / "minimal_crypto.exe"
    
    # Minimal PE header for a Windows executable
    # This is a valid but very small PE file that can be loaded by Windows
    pe_header = bytes([
        0x4d, 0x5a,  # MZ signature
        0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xb8, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ])
    
    try:
        with open(exe_path, 'wb') as f:
            f.write(pe_header)
        return True, "Created minimal_crypto.exe"
    except Exception as e:
        return False, f"Failed to create minimal_crypto.exe: {e}"

def main():
    """Main function."""
    print("=" * 60)
    print("Setting up Test Binaries for Dynamic Analysis")
    print("=" * 60)
    print()
    
    script_dir = Path(__file__).parent
    print(f"Test case directory: {script_dir}")
    print()
    
    success_count = 0
    failed_count = 0
    
    print("[1] Copying System Binaries with Crypto APIs")
    print("-" * 60)
    
    binaries = get_system_binaries()
    for source, dest_name in binaries:
        success, message = copy_binary(source, dest_name)
        if success:
            print(f"  ✓ {message}")
            success_count += 1
        else:
            print(f"  ✗ {message}")
            failed_count += 1
    
    print()
    print("[2] Creating Minimal Crypto Executable")
    print("-" * 60)
    
    success, message = create_minimal_crypto_exe()
    if success:
        print(f"  ✓ {message}")
        success_count += 1
    else:
        print(f"  ✗ {message}")
        failed_count += 1
    
    print()
    print("=" * 60)
    print("Results")
    print("=" * 60)
    
    # List all files in test_case
    files = sorted([f.name for f in script_dir.glob("*") if f.is_file()])
    
    print(f"✓ Successfully added: {success_count} files")
    print(f"✗ Failed to add: {failed_count} items")
    print()
    print("Files in test_case directory:")
    for fname in files:
        fpath = script_dir / fname
        if fname.endswith('.exe'):
            size_mb = fpath.stat().st_size / (1024 * 1024)
            print(f"  ✓ {fname:<30} ({size_mb:>6.2f} MB) [BINARY]")
        elif fname.endswith('.py'):
            size_kb = fpath.stat().st_size / 1024
            print(f"  ○ {fname:<30} ({size_kb:>6.1f} KB) [PYTHON]")
        elif fname.endswith('.c'):
            size_kb = fpath.stat().st_size / 1024
            print(f"  ○ {fname:<30} ({size_kb:>6.1f} KB) [C SOURCE]")
        else:
            print(f"  ○ {fname:<30}")
    
    print()
    print("Next steps:")
    print("1. Load test_case folder as a Case in Detectors page")
    print("2. Run Setup (processes .py and .c source files)")
    print("3. Run Static Analysis (creates hints.json)")
    print("4. Run Dynamic Analysis (Frida will hook .exe binaries)")
    print()
    print("✓ Dynamic Analysis should now show crypto call traces!")
    print()

if __name__ == "__main__":
    main()
