# installation/

This folder contains Windows installer scripts and a small Python helper used by the PowerShell installers.

Files of interest

- `install-ghidra.ps1` — canonical per-user Ghidra installer (download, verify, extract, persist install path).
- `install-all.ps1` — wrapper to run component installers found under this directory.
- `test-install-fallback.ps1` — smoke test that forces the PowerShell fallback for persisting config and verifies uninstall.
- `set_ghidra_config.py` — Python helper that atomically writes or removes the `ghidra.install_dir` key in the per-user config; preferred persistence mechanism if Python is available.

Quick notes and prerequisites

- These scripts are written for Windows PowerShell. They also work from PowerShell Core (`pwsh`) but the test harness was exercised using standard Windows PowerShell.
- You DO NOT need administrator privileges for a per-user install. The scripts install to `%LOCALAPPDATA%\Ghidra\ghidra_<version>` and write config to `%APPDATA%\cryptoscope\config.json`.
- Python is optional. When present the installer will try the Python helper (`set_ghidra_config.py`) first to persist the install directory. If Python is missing the installer falls back to a native PowerShell atomic write. Use `-ForceFallback` to force the native path.
- For security: always prefer providing a `-Sha256` checksum when downloading an archive. Without a checksum the installer attempts to auto-fetch one but that is less reliable.

Common usage examples

1. Install from a local archive (interactive license prompt, preferred for manual installs):

```powershell
.\installation\install-ghidra.ps1 -ArchivePath C:\path\to\ghidra_10.1.5.zip -Version 10.1.5 -Sha256 <hex>
```

2. Non-interactive (CI) install from a URL — must provide `-AcceptLicense` and `-Sha256`:

```powershell
.\installation\install-ghidra.ps1 -DownloadUrl https://example/ghidra_10.1.5.zip -Sha256 <hex> -AcceptLicense
```

3. Force PowerShell fallback for persisting config (skip Python helper):

```powershell
.\installation\install-ghidra.ps1 -ArchivePath .\ghidra_test.zip -Sha256 <hex> -AcceptLicense -ForceFallback
```

4. Uninstall a previously installed version (per-user):

```powershell
.\installation\install-ghidra.ps1 -Uninstall -Version 10.1.5
```

5. Run the wrapper for multiple components (dry-run):

```powershell
.\installation\install-all.ps1 -Components ghidra -DryRun
```

Running the smoke test (what I ran locally)

```powershell
# from the repository root (no admin required)
powershell -NoProfile -ExecutionPolicy Bypass -File .\installation\test-install-fallback.ps1
```

What the test does

- Builds a minimal test ZIP containing `support\analyzeHeadless.bat`.
- Temporarily disables the Python helper (if present) so the installer must use the PowerShell fallback.
- Invokes `installation/install-ghidra.ps1` with `-ForceFallback -AcceptLicense` and a unique `-Version` so it won't touch real installs.
- Verifies that `%APPDATA%\cryptoscope\config.json` contains `ghidra.install_dir` after install, then calls uninstall which removes the key.
- Cleans up temporary files and restores the Python helper.

Recommendations and troubleshooting

- Always provide `-Sha256` unless you have a controlled offline archive.
- If the installer fails while downloading, check network/proxy settings and try downloading the file manually then use `-ArchivePath`.
- If the Python helper is present but the installer still falls back, confirm that `python`, `python3` or `py` is on PATH and callable from the same shell that runs the installer.
- If you need system-wide Ghidra installations or service accounts, adapt the target path and run the script with appropriate privileges — the current scripts intentionally target per-user locations to avoid elevated operations.

Contact / notes

- The `tools/` directory contains small shim scripts that forward to these canonical installers so old invocations still work.

If you'd like, I can add a CI workflow that runs the smoke test on a Windows runner so future PRs are guarded automatically.
