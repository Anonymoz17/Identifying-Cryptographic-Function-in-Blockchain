# CryptoScope - Identifying Cryptographic Functions in Blockchain

A desktop application that identifies and analyzes cryptographic functions within blockchain projects using static code analysis and binary inspection.

## Quick Start

### System Requirements

- **Python:** 3.10, 3.11, or 3.13
- **OS:** Windows 10 or Windows 11
- **Disk Space:** 2GB free (for Ghidra, optional)
- **Internet:** For initial setup and cloud features

### Installation & First Run

**Quick Setup (Recommended)**

Simply run the setup batch file:

```cmd
setup.bat
```

This installs dependencies and launches the app in one command.

**Manual Steps** (if you prefer)

```cmd
# Just install (without launching app)
install.bat

# Launch app later
run.bat
```

The installer will:
- Validate Python 3.10+ installation
- Create a virtual environment (`.venv` folder)
- Install all Python packages from `requirements.txt`

### Launch Application (After Setup)

```cmd
run.bat
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

Ensure Python 3.10, 3.11, 3.12, or 3.13 is installed and in your PATH:

```cmd
python --version
```

If this doesn't work, you may need to add Python to PATH. During Python installation on Windows, check "Add Python to PATH".

### "Running as Administrator" warning

**Do not run as Administrator.** Close the command prompt and run `setup.bat` or `install.bat` as your regular user.

Running as admin can cause permission issues when launching the application later.

### Virtual environment errors

If you see errors about the virtual environment or modules not found:

```cmd
install.bat -Force
```

This will delete and recreate the virtual environment fresh.

### Installation hangs or stalls

Check your antivirus software. It may be blocking Python package downloads. You can either:
- Add the project folder to antivirus exclusions
- Temporarily disable antivirus scanning during setup

### Files missing or corrupted

If setup.bat fails with "Missing required files" errors:
1. Download the complete project again from GitHub
2. Extract it to a new folder
3. Run `setup.bat`

Do not delete or move files from the project folder after extraction.

### "Cannot find venv or Python module" when running app

Make sure you ran the setup process completely and didn't move the project folder:
1. Close any running Python processes or IDE terminals
2. Run: `install.bat -Force`
3. Then run: `run.bat`

---

## Project Structure

```
├── setup.bat                    # First-time setup (recommended)
├── install.bat                  # Installation script
├── run.bat                      # Application launcher
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
