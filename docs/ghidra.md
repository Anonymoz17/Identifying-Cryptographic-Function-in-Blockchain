# Ghidra (headless) setup

This project can optionally run Ghidra in headless mode to produce function
exports consumed by the `GhidraAdapter`. The project does not bundle Ghidra —
you must install it separately.

## Requirements

- Ghidra 10.x or later
- Java (matching Ghidra requirements)

## Options to install

1. Manual download

   - Visit: https://github.com/NationalSecurityAgency/ghidra/releases
   - Download the appropriate `ghidra_<version>_PUBLIC_<platform>.zip` asset
   - Extract it to a folder, e.g. `C:\tools\ghidra_10.1.5` or `/opt/ghidra_10.1.5`

2. Use the helper script (best-effort)

   - Run the included helper script (requires outbound HTTP):

     ```powershell
     $env:PYTHONPATH='.'; python tools\install_ghidra.py --version 10.1.5 --dest tools/ghidra
     ```

   - The helper will attempt to download and extract Ghidra under `tools/ghidra`.
     If it fails, download manually and extract to the same destination.

## Make `analyzeHeadless` available

Either:

- Add the `support` directory from the extracted Ghidra install to your PATH. On
  Windows, the executable is `analyzeHeadless.bat`; on Unix-like systems it's
  `analyzeHeadless`.

  Example (PowerShell, temporary):

  ```powershell
  $ghroot = 'C:\tools\ghidra_10.1.5'
  $env:GHIDRA_INSTALL_DIR = $ghroot
  $env:PATH = $env:PATH + ";$ghroot\support"
  ```

- Or set `GHIDRA_INSTALL_DIR` to the Ghidra root and ensure the `support` dir
  contains the `analyzeHeadless` entry.

  Example (PowerShell, persistent):

  ```powershell
  [Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR', 'C:\tools\ghidra_10.1.5', 'User')
  ```

## Running headless from the repo

- Dry-run (prints commands):

  ```powershell
  python tools\run_ghidra_headless.py --case tools\case_demo\CASE-001
  ```

- Execute (actually runs analyzeHeadless):

  ```powershell
  python tools\run_ghidra_headless.py --case tools\case_demo\CASE-001 --run
  ```

If you see `analyzeHeadless not found. Set GHIDRA_INSTALL_DIR or add analyzeHeadless to PATH.` follow the steps above to set `GHIDRA_INSTALL_DIR` or add the `support` directory to your PATH.

## Notes for CI / headless environments

- CI runners must have Ghidra and Java installed or you should mock Ghidra runs in tests (the repo includes `tools/ghidra/mock_exports` for this purpose).
