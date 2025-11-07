# Ghidra Setup - Comprehensive Solution Plan

**Goal:** Zero or minimal effort Ghidra setup for users

**Current Situation:**  
- Ghidra exists on your Desktop: `C:\Users\luizt\Desktop\ghidra_11.4.2_PUBLIC_20250826`
- Static detection system ready but can't find Ghidra
- Users shouldn't need to manually configure paths

---

## Solution Overview

### 🎯 Three-Tier Approach

1. **Smart Auto-Detection** (New: `setup-ghidra.ps1`) ✅ CREATED
   - Searches common locations automatically
   - Detects existing installations
   - Configures with minimal/zero user input
   
2. **Automated Download** (Existing: `install-ghidra.ps1`) ✅ EXISTS
   - Downloads if not found locally
   - Verifies checksum
   - Installs to standard location

3. **Unified Wrapper** (Enhanced: `install-all.ps1`) ⏳ TO ENHANCE
   - One command for all dependencies
   - Tries smart detection first
   - Falls back to download if needed

---

## Implementation Details

### ✅ COMPLETED: Smart Setup Script (`setup-ghidra.ps1`)

**Location:** `installation/setup-ghidra.ps1`

**Features:**
- **Auto-detection** from multiple common locations:
  - `Desktop\ghidra*` ← Your case!
  - `Downloads\ghidra*`
  - `%LOCALAPPDATA%\Ghidra\ghidra_*`
  - `Program Files\ghidra*`
  - `C:\ghidra*`, `D:\ghidra*`
  
- **Verification** of each found installation:
  - Checks for `analyzeHeadless.bat`
  - Extracts version from `application.properties` or folder name
  - Validates structure

- **Smart Configuration**:
  - Tries Python helper (`set_ghidra_config.py`) first
  - Falls back to PowerShell JSON write
  - Atomic writes to `%APPDATA%\cryptoscope\config.json`

- **Verification** after configuration:
  - Tests if static detection system can find Ghidra
  - Confirms version detection works

**Usage Modes:**

```powershell
# Interactive (recommended for users)
.\installation\setup-ghidra.ps1

# Fully automatic (for your case!)
.\installation\setup-ghidra.ps1 -AutoDetect

# Explicit path
.\installation\setup-ghidra.ps1 -GhidraPath "C:\Users\luizt\Desktop\ghidra_11.4.2_PUBLIC_20250826"

# Skip download offer if not found
.\installation\setup-ghidra.ps1 -SkipDownload

# CI/Automation
.\installation\setup-ghidra.ps1 -AcceptLicense -AutoDetect
```

### ✅ EXISTING: Download Installer (`install-ghidra.ps1`)

**Already works well - no changes needed**

Features:
- Downloads from official Ghidra site
- SHA256 verification
- Per-user installation
- Python helper integration
- PowerShell fallback

### ⏳ TO DO: Enhance Unified Wrapper (`install-all.ps1`)

**Goal:** Make `install-all.ps1` the ONE command users need

**Enhancement Plan:**

```powershell
.\installation\install-all.ps1
```

Should:
1. Try `setup-ghidra.ps1` FIRST (auto-detect)
2. If found → configure and done
3. If not found → offer to download
4. Run `install-ghidra.ps1` if user agrees
5. Repeat for other components (Frida, etc.)

**Changes Needed:**
- Add special case for Ghidra (runs setup first)
- Show user-friendly progress messages
- Handle both interactive and automated modes
- Propagate `-AutoDetect` flag to setup script

---

## User Experience Flows

### Flow 1: User with Existing Ghidra (Your Case)

```powershell
> cd installation
> .\setup-ghidra.ps1 -AutoDetect

[2025-11-07 10:30:00] Searching for Ghidra installations...
[2025-11-07 10:30:01]   Found: C:\Users\luizt\Desktop\ghidra_11.4.2_PUBLIC_20250826 (v11.4.2)
[2025-11-07 10:30:01] Using the only installation found:
[2025-11-07 10:30:01]   Path: C:\Users\luizt\Desktop\ghidra_11.4.2_PUBLIC_20250826
[2025-11-07 10:30:01]   Version: 11.4.2
[2025-11-07 10:30:01] Configuring Ghidra installation path...
[2025-11-07 10:30:01]   Configuration saved via Python
[2025-11-07 10:30:02] Verifying configuration...

╔══════════════════════════════════════════════════════════════╗
║                   Setup Successful! ✓                        ║
╚══════════════════════════════════════════════════════════════╝

Ghidra is now configured and ready to use:
  • Path: C:\Users\luizt\Desktop\ghidra_11.4.2_PUBLIC_20250826\support\analyzeHeadless.bat
  • Version: 11.4.2

The static detection system can now use Ghidra for deep binary analysis!
```

**Time:** ~2 seconds  
**User effort:** One command, zero prompts

### Flow 2: User Without Ghidra

```powershell
> cd installation
> .\setup-ghidra.ps1

[2025-11-07 10:30:00] Searching for Ghidra installations...
[2025-11-07 10:30:02] No Ghidra installations found on this system

Would you like to download and install Ghidra automatically?
This will:
  • Download Ghidra from official source
  • Verify checksum
  • Install to C:\Users\<user>\AppData\Local\Ghidra
  • Configure automatically

Download and install Ghidra? (y/N): y

[2025-11-07 10:30:05] Starting Ghidra download and installation...
[2025-11-07 10:30:05] Running: install-ghidra.ps1 -Version 11.2.1
[2025-11-07 10:30:05] This may take several minutes...
[2025-11-07 10:30:07] Downloading...
[2025-11-07 10:32:15] Checksum OK
[2025-11-07 10:32:20] Extracting archive...
[2025-11-07 10:32:45] Installation completed successfully!

╔══════════════════════════════════════════════════════════════╗
║                   Setup Successful! ✓                        ║
╚══════════════════════════════════════════════════════════════╝

✓ Ghidra downloaded, installed, and configured successfully!
```

**Time:** ~3 minutes (download time)  
**User effort:** One command, one prompt (y/N)

### Flow 3: Already Configured

```powershell
> cd installation
> .\setup-ghidra.ps1

[2025-11-07 10:30:00] Checking current Ghidra configuration...
[2025-11-07 10:30:01] Ghidra is already configured and working!
[2025-11-07 10:30:01]   Path: C:\...\ghidra_11.4.2\support\analyzeHeadless.bat
[2025-11-07 10:30:01]   Version: 11.4.2

✓ No action needed - Ghidra is ready to use!
```

**Time:** <1 second  
**User effort:** None (script exits immediately)

### Flow 4: Multiple Installations Found

```powershell
> cd installation
> .\setup-ghidra.ps1

[2025-11-07 10:30:00] Searching for Ghidra installations...
[2025-11-07 10:30:01]   Found: C:\Users\user\Desktop\ghidra_11.4.2 (v11.4.2)
[2025-11-07 10:30:01]   Found: C:\Users\user\Downloads\ghidra_11.2.1 (v11.2.1)
[2025-11-07 10:30:01]   Found: C:\Program Files\ghidra_10.4 (v10.4)

Multiple installations found:
  [1] C:\Users\user\Desktop\ghidra_11.4.2 (v11.4.2)
  [2] C:\Users\user\Downloads\ghidra_11.2.1 (v11.2.1)
  [3] C:\Program Files\ghidra_10.4 (v10.4)

Select installation to configure [1-3]: 1

[2025-11-07 10:30:05] Configuring Ghidra...
[2025-11-07 10:30:05]   Configuration saved to: ...

╔══════════════════════════════════════════════════════════════╗
║                   Setup Successful! ✓                        ║
╚══════════════════════════════════════════════════════════════╝
```

**With `-AutoDetect`:** Automatically selects newest version (11.4.2)

---

## Integration Points

### 1. Static Detection System

After running setup, the system automatically finds Ghidra via:

```python
from auditor.detectors.static_detection import ghidra_adapter

# Resolution chain (in order):
# 1. Check %APPDATA%\cryptoscope\config.json → ghidra.install_dir
# 2. Check GHIDRA_INSTALL_DIR environment variable
# 3. Search PATH for analyzeHeadless

ghidra_path = ghidra_adapter.resolve_ghidra({})
# Returns: "C:\Users\luizt\Desktop\ghidra_11.4.2\support\analyzeHeadless.bat"
```

### 2. UI Integration

The `DetectorsPage` can call setup programmatically:

```python
# In src/pages/detectors.py
def _setup_ghidra_if_needed(self):
    """Check if Ghidra is configured, offer to set up if not."""
    from auditor.detectors.static_detection import ghidra_adapter
    
    if not ghidra_adapter.resolve_ghidra({}):
        # Ghidra not found
        response = messagebox.askyesno(
            "Ghidra Not Found",
            "Ghidra is not configured. Would you like to set it up now?\n\n"
            "This will search for existing Ghidra installations on your system."
        )
        
        if response:
            # Run setup script
            subprocess.run([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", "installation/setup-ghidra.ps1", "-AutoDetect"
            ])
            
            # Re-check
            if ghidra_adapter.resolve_ghidra({}):
                messagebox.showinfo("Success", "Ghidra configured successfully!")
            else:
                messagebox.showwarning("Setup Failed", "Could not configure Ghidra automatically.")
```

### 3. First-Run Experience

Add to app startup (`src/app.py`):

```python
def check_dependencies_on_startup():
    """Check critical dependencies on first run."""
    from auditor.detectors.static_detection import ghidra_adapter
    
    # Check Ghidra
    if not ghidra_adapter.resolve_ghidra({}):
        print("⚠️  Ghidra not configured")
        print("Run: .\\installation\\setup-ghidra.ps1")
        print("Or: .\\installation\\install-all.ps1")
    else:
        print("✓ Ghidra configured")
```

---

## Recommended Actions

### For You (Immediate)

```powershell
# Configure your existing Ghidra
cd "C:\!Everything Programming\Github Projects\FYP\Identifying-Cryptographic-Function-in-Blockchain"
.\installation\setup-ghidra.ps1 -AutoDetect
```

Expected result:
- Finds your Desktop Ghidra
- Configures automatically
- ~2 seconds total
- Static detection works immediately

### For Users (Documentation)

**Add to README.md:**

```markdown
## Quick Setup

### 1. Install Dependencies

One command to set up everything:

```powershell
.\installation\install-all.ps1
```

This will:
- ✓ Auto-detect existing Ghidra installations
- ✓ Offer to download if not found
- ✓ Configure automatically
- ✓ Verify setup works

**Already have Ghidra?** Just run `.\installation\setup-ghidra.ps1 -AutoDetect`

### 2. Verify Setup

```powershell
python tools\verify_static_detection.py
```

Should show:
```
✓ PASS: GHIDRA - Found at C:\path\to\ghidra
```

### 3. Run Application

```powershell
python src\app.py
```

Static detection will now use Ghidra for deep binary analysis!
```

---

## Testing Plan

### Test 1: Your Case (Existing Ghidra)

```powershell
# Test auto-detection
.\installation\setup-ghidra.ps1 -AutoDetect

# Verify
python tools\verify_static_detection.py

# Should show:
# ✓ PASS: GHIDRA
```

### Test 2: Fresh Install Simulation

```powershell
# Remove config
Remove-Item "$env:APPDATA\cryptoscope\config.json" -Force

# Run setup
.\installation\setup-ghidra.ps1

# Should find your Desktop Ghidra and configure it
```

### Test 3: No Ghidra Scenario

```powershell
# Move Ghidra temporarily
Move-Item "C:\Users\luizt\Desktop\ghidra_11.4.2_PUBLIC_20250826" "C:\Temp\ghidra_backup"

# Run setup
.\installation\setup-ghidra.ps1 -SkipDownload

# Should report not found, show manual instructions

# Restore
Move-Item "C:\Temp\ghidra_backup" "C:\Users\luizt\Desktop\ghidra_11.4.2_PUBLIC_20250826"
```

### Test 4: Static Detection Integration

```powershell
# After setup, test from Python
python -c "from auditor.detectors.static_detection import ghidra_adapter; print(ghidra_adapter.resolve_ghidra({}))"

# Should output path to analyzeHeadless.bat
```

### Test 5: End-to-End Workflow

```powershell
# 1. Setup Ghidra
.\installation\setup-ghidra.ps1 -AutoDetect

# 2. Run application
python src\app.py

# 3. Load a case with preprocessed binary
# 4. Run static detection
# 5. Check ghidra-export/ folder - should have <hash>-functions.json

# 6. Check static_results.json - should have findings!
```

---

## Future Enhancements

### Phase 2: In-App Setup
- Add "Setup Ghidra" button to Static Detection page
- Show status indicator (✓ Configured / ✗ Not Found)
- One-click setup from UI

### Phase 3: Update Detection
- Check for newer Ghidra versions
- Offer to download updates
- Migrate configuration automatically

### Phase 4: Other Dependencies
- Create `setup-frida.ps1` with same pattern
- Add to `install-all.ps1`
- Unified dependency management

---

## Summary

### What's Ready NOW ✅

1. **Smart Setup Script** (`setup-ghidra.ps1`)
   - Auto-detects your Desktop Ghidra
   - Configures with one command
   - Zero user effort with `-AutoDetect`

2. **Existing Installer** (`install-ghidra.ps1`)
   - Downloads if needed
   - Secure (checksum verification)
   - Tested and working

3. **Verification Tool** (`tools/verify_static_detection.py`)
   - Confirms setup worked
   - Shows Ghidra path and version

### What You Should Do NOW 🎯

```powershell
cd "C:\!Everything Programming\Github Projects\FYP\Identifying-Cryptographic-Function-in-Blockchain"
.\installation\setup-ghidra.ps1 -AutoDetect
```

This will:
- Find your `Desktop\ghidra_11.4.2_PUBLIC_20250826`
- Configure it automatically
- Take ~2 seconds
- Enable full static detection immediately

### For End Users 📚

**Add to your README:**
```markdown
## Setup (One Command)

```powershell
.\installation\install-all.ps1
```

Auto-detects and configures all dependencies. That's it!
```

**User effort: ONE command, ZERO configuration!** 🚀
