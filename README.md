# CryptoScope - Identifying Cryptographic Functions in Blockchain

A desktop application that identifies and analyzes cryptographic functions within blockchain projects using static code analysis and binary inspection.

## Quick Start

### System Requirements

- **Python:** 3.10, 3.11, or 3.13
- **OS:** Windows 10 or Windows 11
- **Disk Space:** 2GB free (for Ghidra, optional)
- **Internet:** For initial setup and cloud features

### Installation & First Run

Run this command **once** in PowerShell:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

This allows locally-created scripts (like setup.ps1) to run while maintaining security for downloaded scripts. You will not need to run this again. **Note:** If multiple users share the computer, each user must run this command once in their own session.

**Option 1: Quick Setup (Recommended)**
```powershell
.\setup.ps1
```
This runs installation and launches the app in one command.

**Option 2: Manual Steps**
```powershell
# Install dependencies
.\install.ps1

# Run the app
.\run.ps1
```

The installer will:
- Validate Python installation
- Create virtual environment
- Install all dependencies
- Optionally download Ghidra for binary analysis

### Launch Application (After Setup)

```powershell
.\run.ps1
```

## Key Features

- **Static Source Code Analysis** - Scan multiple programming languages for cryptographic patterns
- **Binary Analysis** - Deep inspection of compiled code using Ghidra integration
- **Multiple Detection Methods** - Signature matching, instruction patterns, and constant database matching
- **User-Friendly Desktop GUI** - CustomTkinter-based Windows application
- **Result Caching** - Efficient re-analysis avoidance for unchanged files
- **Export Reports** - Generate PDF reports and JSON exports

### Cloud Features (Optional)

Create `.env` file for Supabase integration:

```env
SUPABASE_URL=your-project-url
SUPABASE_ANON_KEY=your-anon-key
```

Leave blank for offline-only mode.

---

### Python version error

Ensure Python 3.10, 3.11, or 3.13 is installed and in your PATH:

```powershell
python --version
```

If this doesn't work, you may need to add Python to PATH. During Python installation on Windows, check "Add Python to PATH".

### "Running as Administrator" warning

**Do not run as Administrator.** Close the PowerShell window and run setup.ps1 or install.ps1 as your regular user.

Running as admin can cause permission issues when launching the application later.

### Virtual environment errors

If you see errors about the virtual environment or modules not found:

```powershell
.\install.ps1 -Force
```

This will delete and recreate the virtual environment fresh.

### Installation hangs or stalls

Check your antivirus software. It may be blocking Python package downloads or Ghidra installation. You can either:
- Add the project folder to antivirus exclusions
- Temporarily disable antivirus scanning during setup
- Use `.\install.ps1 -SkipGhidra` to skip Ghidra and install Python dependencies only

### Files missing or corrupted

If setup.ps1 fails with "Missing required files" errors:
1. Download the complete project again from GitHub
2. Extract it to a new folder
3. Run `.\setup.ps1`

Do not delete or move files from the project folder after extraction.

### "Cannot find venv or Python module" when running app

Make sure you ran the setup process completely and didn't move the project folder:
1. Close any running Python processes or IDE terminals
2. Run: `.\install.ps1 -Force`
3. Then run: `.\run.ps1`

---

## Project Structure

```
├── setup.ps1                    # First-time setup (recommended)
├── install.ps1                  # Installation script
├── run.ps1                      # Application launcher
├── src/
│   ├── app.py                   # Main application
│   ├── auditor/                 # Analysis engine
│   │   ├── setup_flow/          # File preprocessing
│   │   └── detectors/           # Detection algorithms
│   ├── pages/                   # UI pages
│   └── ui/                      # UI components
├── docs/                        # Documentation
├── requirements.txt             # Python dependencies
└── requirements-dev.txt         # Development tools
```
