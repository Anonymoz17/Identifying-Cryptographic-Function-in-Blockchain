# Ghidra installer (Windows)

This document describes the Windows per-user installer shipped in `tools/install-ghidra.ps1`.

Overview
--------

The installer aims to make it easy for users to obtain a working Ghidra headless environment for use with this project. It:

- Installs Ghidra to a per-user location: `%LOCALAPPDATA%\Ghidra\ghidra_<version>` (no admin privileges required).
- Verifies the downloaded archive using SHA256 when available.
- Extracts the archive safely to a temporary directory and atomically moves it into place.
- Persists the install location into the app's per-user config so the static detector can auto-discover Ghidra.
- Provides uninstall and backup behavior.

Usage
-----

Interactive install (prompts for license acceptance):

```powershell
# Install from a local archive
.\tools\install-ghidra.ps1 -ArchivePath C:\downloads\ghidra_10.1.5.zip -Version 10.1.5 -Sha256 <hex>

# Download and install (interactive license)
.\tools\install-ghidra.ps1 -DownloadUrl https://ghidra-sre.org/ghidra_10.1.5_PUBLIC.zip -Sha256 <hex>
```

Non-interactive install (CI or scripted):

```powershell
.\tools\install-ghidra.ps1 -DownloadUrl https://ghidra-sre.org/ghidra_10.1.5_PUBLIC.zip -Sha256 <hex> -AcceptLicense
```

Uninstall and clear persisted config:

```powershell
.\tools\install-ghidra.ps1 -Uninstall
```

Automatic URL and checksum lookup
--------------------------------

If you do not provide `-ArchivePath` or `-DownloadUrl`, the script will automatically attempt to download the canonical Ghidra release for the specified `-Version` using:

```
https://ghidra-sre.org/ghidra_<Version>_PUBLIC.zip
```

If you do not provide `-Sha256`, the script will attempt to fetch a checksum from a few likely locations (best-effort). If it cannot fetch a checksum, it will warn and continue (not recommended). For security, prefer providing a verified SHA256 yourself.

Persisted config
----------------

After a successful install, the script will call `tools/set_ghidra_config.py --set <install_dir>` to persist the install directory to the app's per-user config. The static detector code reads this config with `src/auditor/detectors/static_detection/config.py`.

Security and license
--------------------

- You must accept the Ghidra NCSA license before installing. Use `-AcceptLicense` for non-interactive installs.
- Always prefer installing with a known-good SHA256 checksum. The script will verify the archive and abort on checksum mismatch.

Troubleshooting
---------------

- If the script cannot find `python` on PATH, it will still install Ghidra but will not persist the install path. Run `python tools/set_ghidra_config.py --set "<install_dir>"` manually to persist.
 - If the script cannot find `python` on PATH, it will still install Ghidra but will not persist the install path. Run `python tools/set_ghidra_config.py --set "<install_dir>"` manually to persist.
 - New: the installer includes a native PowerShell fallback that can persist the install directory into the per-user config (`%APPDATA%\cryptoscope\config.json`) when Python is not available. The script will try the bundled Python helper first; if that fails it uses the fallback.
	 - You can force the fallback (useful for testing) with the `-ForceFallback` switch when running `install-ghidra.ps1`.
	 - The fallback writes a `ghidra.install_dir` entry and performs an atomic write (tmp file then move) so it is safe against partial writes.
	 - Uninstall now uses the same native logic to remove the `ghidra` key from the config, so uninstall works even without Python.
- If the script cannot find `analyzeHeadless` after installation, inspect the extracted install directory — the headless script lives under the `support` subdirectory or root depending on the Ghidra version.

Next steps
----------

- After installation, we will update the Ghidra adapter to reliably invoke `analyzeHeadless.bat` on Windows (use `cmd.exe /c` wrapper) and accept exporter output even on non-zero exit codes. These fixes will make the headless integration robust on Windows.
