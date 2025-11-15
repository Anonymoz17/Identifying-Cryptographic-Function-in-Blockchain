# CryptoScope - Identifying Cryptographic Functions in Blockchain

A desktop application that identifies and analyzes cryptographic functions within blockchain projects using static code analysis and binary inspection.

## Quick Start

### System Requirements

- **Python:** 3.10, 3.11, or 3.13
- **OS:** Windows 10 or Windows 11
- **Disk Space:** 2GB free (for Ghidra, optional)
- **Internet:** For initial setup and cloud features

### Installation & First Run

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
