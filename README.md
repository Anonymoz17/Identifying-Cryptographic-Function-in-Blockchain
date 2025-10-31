# Identifying-Cryptographic-Function-in-Blockchain

Dependencies

Python 3.10–3.12

OS: Windows / macOS / Linux

Tk (bundled with most Python installers)

libmagic (macOS/Linux only; see below)

Environment

Create a .env file next to loginTest.py:

SUPABASE_URL=your-project-url
SUPABASE_ANON_KEY=your-anon-key

Install (Windows)

python -m venv .venv
.venv\Scripts\activate
pip install customtkinter supabase python-dotenv tkinterdnd2 python-magic-bin

Install (macOS)

python3 -m venv .venv
source .venv/bin/activate
brew install libmagic # required by python-magic
pip install customtkinter supabase python-dotenv tkinterdnd2 python-magic

Install (Ubuntu/Debian Linux)

python3 -m venv .venv
source .venv/bin/activate
sudo apt-get update && sudo apt-get install -y libmagic1
pip install customtkinter supabase python-dotenv tkinterdnd2 python-magic

Run

python loginTest.py

Developer optional dependencies

For developer-only optional native integrations (AST, disassembly, YARA) and test helpers, see `docs/optional-deps.md` and install the dev requirements:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

If you need the native extras (tree-sitter, capstone, yara-python) install them after activating the venv as described in `docs/optional-deps.md`.

## Ghidra (optional, headless analysis)

This project can optionally run Ghidra in headless mode to produce function
exports. See `docs/ghidra.md` for detailed installation steps and how to set
`GHIDRA_INSTALL_DIR` or add `analyzeHeadless` to your PATH.

## Features added in the `results-page` branch

- Policy baseline editor in the Setup page: auditors can now pick from
  templates (Whitelist, Rule Overrides, Scoring, Combined), edit JSON in a
  modal, Insert (write a temp JSON and use it for the engagement) or Save As
  to persist. The policy file is copied into the case workspace as
  `policy.baseline.json` and a SHA256 sidecar is written.
- Results page: a dedicated Results UI reads `detector_results.summary.json`
  (placed under `<case>/detector_output/`) and renders three charts (top-rule
  bar chart, engine breakdown, confidence histogram). Chart rendering is
  optional (matplotlib). The page includes case selection, browse, and a
  Run Detectors button that launches the helper script `tools/open_results.py`.
- UI responsiveness improvements: file/folder dialogs are now attached to the
  application window and heavy summary parsing is performed in a background
  thread so the GUI remains responsive after closing native file dialogs.

See `docs/audit-roadmap.md` for a prioritized product roadmap and next steps
aimed at security-auditor workflows.
