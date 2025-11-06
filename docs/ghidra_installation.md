## Developer helper script (quick)

For local development and testing we provide a small PowerShell helper that sets `GHIDRA_INSTALL_DIR` for your current session and runs a quick verification using the repository helper. This is intended for contributors and CI debugging — it does not perform a full install or change system-wide environment variables unless you explicitly request that.
File: `tools/ghidra-dev-setup.ps1`

Usage (PowerShell in the repository root):
```powershell
# point the current session at a local Ghidra folder and run the quick verify
.\tools\ghidra-dev-setup.ps1 -InstallDir 'C:\Users\You\Desktop\ghidra_11.4.2_PUBLIC' -RunVerify

# persist into the project's per-user config (app will read it on next run)
.\tools\ghidra-dev-setup.ps1 -InstallDir 'C:\Users\You\Desktop\ghidra_11.4.2_PUBLIC' -Save
```
The script will:
- confirm `support\analyzeHeadless.bat` exists under the path you supplied (Windows)
- set `GHIDRA_INSTALL_DIR` in the current PowerShell session
- run the repo's verification helper which prints `ANALYZE_PATH` and `VERIFY` output
- optionally persist the path into the project's per-user config when `-Save` is supplied

If verification shows a resolved `ANALYZE_PATH` but `VERIFY` is empty on Windows, try running the script without saving first and then run a full headless export test (documented elsewhere) — Windows `.bat` wrappers occasionally require CMD context or Java on PATH.
# Installing Ghidra for use with this project

This document explains recommended ways to make Ghidra available so the
static detection runner can call `analyzeHeadless` to export per-function
artifacts. There are three recommended options (A, B and C). Option B is a
convenience installer script included in this repository and Option C is a
Docker image useful for CI and reproducible runs.

IMPORTANT: Ghidra is distributed separately from this repository. Users must
accept Ghidra's license before downloading or installing it.

Quick summary
- Option A: Manual install (user downloads and sets `GHIDRA_INSTALL_DIR`) — simplest.
- Option B: Convenience installer scripts (`tools/install-ghidra.ps1` & `tools/install-ghidra.sh`) — recommended for developers.
- Option C: Docker image (`docker/ghidra.Dockerfile`) — recommended for CI and reproducible environments.

Option B — Convenience installer scripts (recommended)
----------------------------------------------------

We include two helper installer scripts in the `tools/` folder:

- `tools/install-ghidra.ps1` — PowerShell script for Windows
- `tools/install-ghidra.sh` — Bash script for Linux/macOS

These scripts:
- require explicit acceptance of the Ghidra license (you must pass `-AcceptLicense` in PowerShell or `--accept-license` for the bash script).
- download a pinned Ghidra release (update the script to change version/checksum).
- verify checksum when available (scripts include a placeholder for the expected SHA256 — fill with the official checksum when releasing).
- extract Ghidra to a destination folder and print instructions to set `GHIDRA_INSTALL_DIR`.

Usage examples

PowerShell (Windows)

```powershell
# Run as: accept the license and install
.\n+tools\install-ghidra.ps1 -Version "10.2.3" -Dest "C:\tools\ghidra" -AcceptLicense

# Then set the environment variable for your shell / system
$env:GHIDRA_INSTALL_DIR = 'C:\tools\ghidra\ghidra_10.2.3'
```

Bash (Linux/macOS)

```bash
./tools/install-ghidra.sh --version 10.2.3 --dest "$HOME/ghidra-10.2.3" --accept-license
export GHIDRA_INSTALL_DIR="$HOME/ghidra-10.2.3/ghidra_10.2.3"
```

Notes
- Update the scripts' URL and expected SHA256 before publishing a release.
- The scripts intentionally require explicit license acceptance to avoid accidental license violation.

In-app installer flow (recommended UX)
-------------------------------------

For an improved user experience the application can offer an "Install Ghidra"
action which runs the repository installer script for the user's platform.
Important guidelines for implementing this flow safely and legally:

- Always require explicit license acceptance before downloading or installing.
- Show the Ghidra license (or link to it) and require the user to click a
	checkbox or accept button. Do not proceed without clear consent.
- Stream installer output to the UI so users can inspect progress and errors.
- After a successful install, prompt the user to save the detected
	installation path into the app's persistent configuration (opt-in).

High-level install flow inside the app:

1. User clicks "Install Ghidra" in Settings.
2. Present license text/link and require explicit acceptance.
3. Detect platform and run the appropriate script:
	 - Windows: run PowerShell script `tools/install-ghidra.ps1` with `-AcceptLicense`.
	 - macOS/Linux: run Bash script `tools/install-ghidra.sh` with `--accept-license`.
4. Capture stdout/stderr and show live logs in the UI.
5. On success, read or detect the installed path and ask the user whether to
	 persist it in the application's configuration store.
6. Optionally run a short verification (`analyzeHeadless -version` or `-help`)
	 to confirm `analyzeHeadless` works and show the version/help output.

Example subprocess calls (Python)

PowerShell (Windows):

```python
import subprocess
subprocess.run([
		"powershell",
		"-NoProfile",
		"-ExecutionPolicy",
		"Bypass",
		"-File",
		"tools\\install-ghidra.ps1",
		"-Version",
		"10.2.3",
		"-Dest",
		"C:\\tools\\ghidra",
		"-AcceptLicense",
], check=True)
```

POSIX (bash):

```python
import subprocess
subprocess.run([
		"/bin/bash",
		"tools/install-ghidra.sh",
		"--version",
		"10.2.3",
		"--dest",
		"/home/user/ghidra-10.2.3",
		"--accept-license",
], check=True)
```

Persisting the install path
---------------------------

After the installer completes successfully, ask the user if they'd like to
save the install directory to the app configuration. The codebase includes a
small helper (`src/auditor/detectors/static_detection/config.py`) to read and
write a per-user config file. Use `set_ghidra_install_dir(path)` to persist the
value. The runner will automatically pick up the saved path on subsequent runs.

Verification and diagnostics
----------------------------

After installation (or when the user provides a path), the app should verify
that `analyzeHeadless` is reachable and functioning. A short verification
attempt (5s timeout) running `analyzeHeadless -version` or `-help` is
usually sufficient. Capture output and display a small summary to the user
(`Ghidra found: <path> — version: <x>`), and persist the path only with user
consent.

Safety and consent
------------------

- Never run installer scripts without the user's explicit consent and license
	acceptance.
- Verify downloaded archives via SHA256 (scripts include placeholders for
	checksums) and fail the install if verification does not match.
- Write install paths only to per-user config (do not silently modify system
	environment variables). Let users opt to make system-level changes themselves.

If the installation or verification fails, show the `ghidra-export.log` and
the install script output to help users debug or retry.


Option C — Docker image (CI & reproducible runs)
------------------------------------------------

We provide a Dockerfile skeleton at `docker/ghidra.Dockerfile` that:
- installs OpenJDK and required packages
- downloads and unpacks a pinned Ghidra release
- sets `GHIDRA_INSTALL_DIR` and makes `analyzeHeadless` available on PATH
- copies the repository into `/workspace` and installs Python deps

Usage (build locally)

```bash
docker build -t myorg/yourtool:ghidra -f docker/ghidra.Dockerfile .
docker run --rm -it -e GHIDRA_SAMPLE_BIN=/workspace/tests/sample_binary --workdir /workspace myorg/yourtool:ghidra
```

CI usage
- For CI we recommend either building a similar image as part of your pipeline or downloading Ghidra in a job step and setting `GHIDRA_INSTALL_DIR` for the integration job.
- Gate the integration job (don't run it by default). Use a workflow_dispatch or repository secret to enable it.

Option A — Manual install
-------------------------

1) Download Ghidra from https://ghidra-sre.org/
2) Extract it to a folder you control
3) Set the environment variable `GHIDRA_INSTALL_DIR` to the folder that contains `support/analyzeHeadless` (or add that `support` folder to PATH)

Example (PowerShell):

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\tools\ghidra\ghidra_10.2.3'
```

Security and license
- Always verify the SHA256 checksum of the downloaded archive before extracting it. The installer scripts include placeholders for the official checksum — populate those values as part of your release process.
- Ensure users explicitly accept the Ghidra license before installation (the scripts require this).

Integration testing notes
- Integration tests that rely on a real Ghidra run should be gated and skipped by default. See `docs/ghidra_integration.md` for how to run the gated tests locally.

Next steps for release
- Pin a Ghidra version for the release and update the URL and SHA256 checksum in `tools/install-ghidra.*` and `docker/ghidra.Dockerfile`.
- Optionally provide a released Docker image (ghcr.io or Docker Hub) that includes Ghidra and the detection tool; document how users can pull and run it.
