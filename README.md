# Identifying-Cryptographic-Function-in-Blockchain

## Quick Start

### Dependencies

- **Python 3.10–3.13**
- **OS**: Windows / macOS / Linux
- **Tk** (bundled with most Python installers)
- **libmagic** (macOS/Linux only; see below)

### Environment

Create a `.env` file in the project root:

```env
SUPABASE_URL=your-project-url
SUPABASE_ANON_KEY=your-anon-key
```

### Installation

#### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

#### macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
brew install libmagic  # required by python-magic
pip install -r requirements.txt
```

#### Ubuntu/Debian Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
sudo apt-get update && sudo apt-get install -y libmagic1
pip install -r requirements.txt
```

### Setup & Validation

After installation, verify everything is configured:

```powershell
# Check if static detection pipeline is ready
python -m src.auditor.detectors.static_detection.setup check

# Run interactive setup wizard (if needed)
python -m src.auditor.detectors.static_detection.setup wizard
```

This will check:

- ✅ Python version
- ✅ Required packages
- ✅ Workspace structure
- ✅ Configuration files
- ✅ Ghidra setup (optional)

### Run Application

```powershell
python src/app.py
```

---

## Documentation

- **[Static Detection Quick Start](docs/static-detection-quickstart.md)** - Complete setup guide
- **[Ghidra Policy](docs/ghidra-policy.md)** - Performance optimization guide
- **[Optional Dependencies](docs/optional-deps.md)** - Advanced features
- **[Ghidra Installation](installation/README.md)** - Ghidra setup details

---

## Developer Setup

For development with optional native integrations (AST, disassembly, YARA):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

See `docs/optional-deps.md` for native extras installation (tree-sitter, capstone, yara-python).

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

## Quick Reference

### Setup Commands

```powershell
# Validate setup
python -m src.auditor.detectors.static_detection.setup check

# Interactive configuration
python -m src.auditor.detectors.static_detection.setup wizard

# Check Ghidra policy
python -m src.auditor.detectors.static_detection.setup policy
```

### Configuration Options

**Ghidra Execution Policy:**

```python
from src.auditor.detectors.static_detection import config

# Smart filtering (default, recommended)
config.set_ghidra_run_policy('auto')

# Skip Ghidra entirely (fast, source-only)
config.set_ghidra_run_policy('never')

# Force on all files (slow, binary-only)
config.set_ghidra_run_policy('always')
```

---

## Troubleshooting

### Common Issues

**"Ghidra not configured"**

```powershell
# Option 1: Run setup wizard
python -m src.auditor.detectors.static_detection.setup wizard

# Option 2: Skip Ghidra (source-only mode)
python -c "from src.auditor.detectors.static_detection import config; config.set_ghidra_run_policy('never')"
```

**"Analysis is slow"**

```python
# Use auto policy for 50-100x speedup on source-heavy projects
from src.auditor.detectors.static_detection import config
config.set_ghidra_run_policy('auto')
```

See **[docs/static-detection-quickstart.md](docs/static-detection-quickstart.md)** for complete troubleshooting guide.

---

## Project Structure

```
├── src/
│   ├── app.py                          # Main application
│   ├── auditor/
│   │   └── detectors/
│   │       └── static_detection/       # Static analysis pipeline
│   │           ├── setup.py            # Setup utility
│   │           ├── runner.py           # Main orchestrator
│   │           ├── ghidra_adapter.py   # Ghidra integration
│   │           ├── ghidra_policy.py    # Smart filtering
│   │           └── heuristics/         # Detection heuristics
│   └── web/
│       └── landing/                    # React landing page
├── docs/
│   ├── static-detection-quickstart.md  # Setup guide
│   ├── ghidra-policy.md                # Performance guide
│   └── optional-deps.md                # Advanced features
├── installation/
│   ├── README.md                       # Ghidra installer docs
│   └── install-ghidra.ps1             # PowerShell installer
├── requirements.txt                    # Core dependencies
└── requirements-dev.txt               # Dev dependencies
```

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
