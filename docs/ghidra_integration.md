Ghidra integration test — local run guide
======================================

This repository includes a gated integration test that will run a real
Ghidra headless export using `analyzeHeadless`. The test is intentionally
skipped unless you provide the required environment variables.

Prerequisites
-------------
- A local Ghidra installation (tested with Ghidra 10.x+). Note the install
  directory path (the folder that contains `support/analyzeHeadless`).
- A small binary that Ghidra can import (ELF/PE/MACH-O). This can be any
  small compiled executable you have available.

Environment variables
---------------------
Set the following environment variables (PowerShell example):

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\path\to\ghidra'
$env:GHIDRA_SAMPLE_BIN = 'C:\path\to\sample.exe'
```

Running the integration test
----------------------------
From the repository root run (PowerShell):

```powershell
# run only the integration test file
pytest -q tests/test_ghidra_integration.py

# or run by name
pytest -q -k ghidra_integration
```

Notes
-----
- The test will invoke `analyzeHeadless` and may be slow (tens of seconds to minutes
  depending on the binary and system). A longer timeout is used by default.
- The test will write exporter outputs into a temporary `out_dir` created by pytest.
- If you want to reproduce the exact `analyzeHeadless` invocation the adapter uses,
  see `docs/ghidra_adapter.md` — it shows the `-postScript`/`-scriptPath` usage and how
  the adapter forwards the output path to the exporter script.
