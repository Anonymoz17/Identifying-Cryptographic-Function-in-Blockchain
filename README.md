# Identifying-Cryptographic-Function-in-Blockchain

## Quick Start (Windows Only)

### System Requirements

- **Python 3.10–3.13** (with pip)
- **Windows** (10 or later)
- **~2GB** free disk space (for Ghidra)

### Step 1: Install Everything

Run the unified installer (it does everything automatically):

```powershell
# From project root
.\install.ps1
```

This will:
- ✅ Validate Python installation
- ✅ Create virtual environment
- ✅ Install all dependencies
- ✅ Download and setup Ghidra (optional, skip with `-SkipGhidra`)
- ✅ Validate complete installation

### Step 2: Run the Application

```powershell
.\run.ps1
```

Or if you prefer a batch file:

```powershell
.\run.bat
```

### Setup .env (Optional)

For cloud features, create a `.env` file in the project root:

```env
SUPABASE_URL=your-project-url
SUPABASE_ANON_KEY=your-anon-key
```

---

## Advanced Setup

### Skip Ghidra Installation

If you only want Python dependencies (no binary analysis):

```powershell
.\install.ps1 -SkipGhidra
```

### Force Reinstall

To reinstall everything from scratch:

```powershell
.\install.ps1 -Force
```

### Custom Ghidra Version

```powershell
.\install.ps1 -GhidraVersion 10.0
```

---

## Developer Setup

For development with optional native integrations (AST, disassembly, YARA):

```powershell
# Install development dependencies
.\install.ps1           # Standard install first
pip install -r requirements-dev.txt
```

See `docs/optional-deps.md` for native extras installation (tree-sitter, capstone, yara-python).

---

## Documentation

- **[Static Detection Quick Start](docs/static-detection-quickstart.md)** - Complete setup guide
- **[Ghidra Policy](docs/ghidra-policy.md)** - Performance optimization guide
- **[Optional Dependencies](docs/optional-deps.md)** - Advanced features
- **[Installation Details](installation/README.md)** - Legacy installer reference

---

## Web Landing Page

A modern landing page for CryptoScope located at `src/web/landing/`

**Requirements:**

- Node.js LTS (v20+)
- Git

**Run the site:**

```bash
# From project root
npm run landing:install     # Install dependencies (first time only)
npm run landing:dev         # Start the dev server
# ctrl + left click localhost:****
```

---

## Troubleshooting

### Installation Issues

**"Python not found"**
- Ensure Python 3.10-3.13 is installed and added to PATH
- Test: `python --version`

**"Failed to download Ghidra"**
- Check internet connection
- Ensure you have ~2GB free disk space
- Try again: `.\install.ps1 -Force`

**"Can't run app"**
- Ensure installer completed successfully
- Run: `.\run.ps1` from project root, not from subdirectories

For detailed troubleshooting, see **[docs/static-detection-quickstart.md](docs/static-detection-quickstart.md)**.

---

## Project Structure

```
├── install.ps1                         # 👈 RUN THIS FIRST (one-step setup)
├── run.ps1                             # 👈 RUN THIS TO START APP
├── run.bat                             # Alternative: batch file launcher
├── src/
│   ├── app.py                          # Main application
│   ├── auditor/
│   │   └── detectors/
│   │       └── static_detection/       # Static analysis pipeline
│   ├── pages/                          # UI pages
│   └── ui/                             # UI components
├── docs/                               # Documentation
├── installation/                       # Legacy scripts (kept for reference)
├── requirements.txt                    # Python dependencies
└── requirements-dev.txt                # Development extras
```

**Key files:**
- `install.ps1` - Unified installer (Python + Ghidra + dependencies)
- `run.ps1` - App launcher (activates venv and runs src/app.py)
- `run.bat` - Alternative launcher for Command Prompt users

---

## Performance

The static detection pipeline uses intelligent filtering for optimal performance:

- **Source code files** (Python, JS, JSON): ⚡ Instant analysis
- **Binary files** (ELF, PE, Mach-O): 🔧 Full Ghidra analysis
- **Large files** (> 5MB): ⏭️ Skipped by default

**Expected speedup:** 50-100x faster for source-heavy blockchain projects

---

## License

[Your License Here]

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
