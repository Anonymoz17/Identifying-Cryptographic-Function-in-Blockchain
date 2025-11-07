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

## Option B — Convenience installer scripts (recommended)

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

## In-app installer flow (recommended UX)

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

## Persisting the install path

After the installer completes successfully, ask the user if they'd like to
save the install directory to the app configuration. The codebase includes a
small helper (`src/auditor/detectors/static_detection/config.py`) to read and
write a per-user config file. Use `set_ghidra_install_dir(path)` to persist the
value. The runner will automatically pick up the saved path on subsequent runs.

## Verification and diagnostics

After installation (or when the user provides a path), the app should verify
that `analyzeHeadless` is reachable and functioning. A short verification
attempt (5s timeout) running `analyzeHeadless -version` or `-help` is
usually sufficient. Capture output and display a small summary to the user
(`Ghidra found: <path> — version: <x>`), and persist the path only with user
consent.

## Safety and consent

- Never run installer scripts without the user's explicit consent and license
  acceptance.
- Verify downloaded archives via SHA256 (scripts include placeholders for
  checksums) and fail the install if verification does not match.
- Write install paths only to per-user config (do not silently modify system
  environment variables). Let users opt to make system-level changes themselves.

If the installation or verification fails, show the `ghidra-export.log` and
the install script output to help users debug or retry.

## Option C — Docker image (CI & reproducible runs)

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

## Option A — Manual install

1. Download Ghidra from https://ghidra-sre.org/
2. Extract it to a folder you control
3. Set the environment variable `GHIDRA_INSTALL_DIR` to the folder that contains `support/analyzeHeadless` (or add that `support` folder to PATH)

Example (PowerShell):

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\tools\ghidra\ghidra_10.2.3'
```

Security and license

- Always verify the SHA256 checksum of the downloaded archive before extracting it. The installer scripts include placeholders for the official checksum — populate those values as part of your release process.
- Ensure users explicitly accept the Ghidra license before installation (the scripts require this).

Integration testing notes

- Integration tests that rely on a real Ghidra run should be gated and skipped by default. See `docs/ghidra_integration.md` for how to run the gated tests locally.


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

---

## Installing Ghidra and auxiliary tools (recommended design)

This section lays out a production-ready, cross-platform design for how the
application should install and manage optional heavyweight dependencies like
Ghidra and Frida. It covers recommended install locations, installer UX,
verification and security, dependency management, CI patterns, and a concrete
implementation roadmap.

Goals and contract

- Inputs: operating system, whether the user has admin privileges, explicit
	consent for third-party licenses, options to auto-install Ghidra/Frida or
	use existing installs.
- Outputs: a working application install where the app can invoke `analyzeHeadless`
	and Frida tooling; the install paths and consent flags persisted in per-user
	config; verified checksums and short verification logs available for
	debugging.
- Success criteria: the app can discover and run `analyzeHeadless` (headless
	exporter), Frida Python APIs are usable where required, and the user has
	explicitly accepted third‑party licenses.

Top-level recommendations

1. Keep the app lightweight; do not bundle large third‑party binaries in the
	 main distribution. Offer optional automated install flows and a Docker image
	 for CI.
2. Default to per-user installs (safer, no admin privileges). Provide an
	 opt-in system-wide install for administrators.
3. Persist discovered/installed tool locations in a per-user config file (not
	 only via environment variables). Use platform config dirs (XDG / %APPDATA%).
4. Always display license text and require explicit consent before downloading
	 or installing Ghidra or other licensed tools.
5. Verify downloads using SHA256 (and PGP where available). Maintain a
	 recommended/known-good list of versions.
6. Make installer actions idempotent and reversible (support uninstall/repair).

Where to install (paths)

- Application code & binaries:
	- Per-user: Windows: `%LOCALAPPDATA%\\<AppName>\\`; macOS/Linux: `~/.local/share/<app>/`.
	- System-wide (opt-in): Windows: `C:\Program Files\\<AppName>\\`; Linux/macOS: `/opt/<app>/`.
- Per-user config & manifests: use platform conventions, for example:
	- Windows: `%APPDATA%\\<AppName>\\config.json` or `%LOCALAPPDATA%\\<AppName>\\`.
	- macOS: `~/Library/Application Support/<AppName>/config.json`.
	- Linux: `$XDG_CONFIG_HOME/<app>/config.json` (fallback: `~/.config/<app>/`).
- Ghidra (recommended default locations):
	- Per-user Windows: `%LOCALAPPDATA%\\\\Ghidra\\\\ghidra_<version>\\`
	- System Windows (admin opt-in): `C:\Program Files\\Ghidra\\ghidra_<version>\\`
	- macOS/Linux: `~/.local/share/ghidra/<version>/` or `/opt/ghidra/<version>/` for system installs.
- Frida:
	- Python bindings should be installed in the app's Python virtualenv: e.g., `%LOCALAPPDATA%\\<app>\\venv\\`.
	- `frida-server` artifacts kept under: `%LOCALAPPDATA%\\<app>\\runtimes\\frida\\<version>\\`.

Installer UX and flows

Two main flows:

- Developer/local flow (lightweight): developer helper scripts (PowerShell/Bash) to point the app at an existing Ghidra install or to persist a path in per-user config. (Already implemented: `tools/ghidra-dev-setup.ps1`.)
- End-user interactive installer (production): a GUI or CLI installer that offers checkboxes to auto-install optional tools and requires license acceptance.

Interactive installer (key steps):

1. Present options: install app (required), install Ghidra (optional), install
	 Frida (optional), choose install scope (user/system), accept licenses.
2. If auto-installing Ghidra/Frida: show version and checksum; require user to
	 accept license(s) explicitly.
3. Download over HTTPS, verify checksum/PGP, extract to chosen location.
4. Run verification probes (e.g., `analyzeHeadless -version`) and report
	 status and any missing prerequisites (Java). Save path in app config on
	 user's confirmation.

Unattended/CI installation flags should be available (e.g., `--with-ghidra`,
`--accept-ghidra-license`, `--system`) for automation.

Security, verification and consent

- Always download from official GHIDRA sites/URLs and show license text ahead
	of download.
- Verify downloaded archives with SHA256 (and PGP if available). Abort on
	mismatch and remove partial files.
- Record license acceptance (timestamped) in per-user config for auditability.
- Prefer per-user installs to avoid escalated privileges; only perform
	system-wide installs when the user explicitly requests and the installer
	runs with appropriate elevation.

Dependency management

- Java (JDK): Ghidra requires a supported JDK. Options:
	- Recommend users install OpenJDK (detect via `JAVA_HOME` or `java -version`).
	- Optionally bundle a compatible JRE in the installer where licensing permits.
- Python & frida bindings:
	- Use a dedicated virtual environment for the app and `pip install` pinned
		wheels (including `frida`/`frida-tools`) into that venv.
	- Keep `requirements.txt` and lockfiles for reproducible installs.
- Native artifacts (frida-server): download and keep under app data dirs and
	document device-specific steps to push/start `frida-server` on target devices.

Runtime detection and persistence

Detection precedence (recommended):
1. Explicit install path passed by the user for that run.
2. Per-user app config (persisted path).
3. Environment variables (`GHIDRA_INSTALL_DIR`, `JAVA_HOME`).
4. PATH lookup (`shutil.which`).

Write a small `.tool_manifest.json` in the config dir containing installed
tools, versions, paths, and checksums for diagnostics and reproducibility.

Error modes and edge cases

- Java missing or incompatible: detect and display an actionable message with
	either instructions to install OpenJDK or an option to bundle a JRE.
- analyzeHeadless present but returns non-zero for help: on Windows use a
	`cmd /c` probe to capture output (we already do this in verification).
- Antivirus/quarantine: capture errors and recommend excluding the installed
	folder if necessary.
- Checksum mismatch: abort and remove the bad download; offer alternative
	mirrors or manual install.

CI and reproducible builds

- Provide a Docker image with OpenJDK + Ghidra + app dependencies for CI.
- Gate integration tests that require Ghidra behind a manual flag or secret.
- For GitHub Actions, provide a job template that either pulls a prepared image
	or downloads Ghidra during the job and sets `GHIDRA_INSTALL_DIR`.

Monitoring, updates and maintenance

- Keep a tested list of recommended Ghidra versions. Warn users if a
	provided Ghidra is untested.
- Provide a repair/uninstall action in the UI and the ability to re-run
	verification.
- Avoid auto-updating Ghidra without explicit consent.

Implementation roadmap (concrete tasks)

Short-term (low-risk)
- Add `.tool_manifest.json` schema and implement per-user config helpers (read/write).
- Add CLI flags to save a provided `--ghidra-install-dir` into per-user config.
- Add automated verify helpers for Java and frida-python.

Medium-term
- Implement interactive installer UI or CLI wrapper that runs the provided
	scripts (PowerShell/Bash) with license acceptance and checksum verification.
- Create a Docker image with OpenJDK, Ghidra, and frida for CI usage.

Long-term (optional)
- Build native OS installers (MSI/.pkg/.deb/.rpm) and package managers (winget,
	brew tap) for easier distribution.
- Consider bundling a compatible JRE for a single-click install where licensing permits.

Helpful example commands & artifacts

- Verify analyzeHeadless on Windows (works well with `cmd /c`):
```powershell
cmd /c "\\"C:\Users\\you\\Desktop\\ghidra_11.4.2_PUBLIC\\support\\analyzeHeadless.bat\\" -version"
```

- Persist a detected path into per-user config (Python helper):
```powershell
python -c "import sys; sys.path.insert(0,'src'); from auditor.detectors.static_detection import config; config.set_ghidra_install_dir(r'C:\\path\\to\\ghidra'); print('saved')"
```

- Install frida into the app venv:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install frida==<pinned-version> frida-tools
```

Testing & verification

- Unit tests: mock `run_headless_export`, test `resolve_ghidra` and `verify_ghidra`.
- Integration: use Docker image to run `ensure_ghidra_export` against a small
	test binary (gate this test so it only runs when the image/ghidra is
	available).

Privacy and compliance

- Record license acceptances in the per-user config (timestamp). Do not
	upload disassembly or function metadata unless the user explicitly opts in.
- If telemetry is added, make it opt-in and document exactly what is sent.

Next steps

I can implement any of the following next:
- create the `.tool_manifest.schema.json` and per-user config helpers (small change)
- add a `appctl tool install ghidra --version ..` CLI helper that downloads and verifies
- prepare a Dockerfile and CI job example that bundles Ghidra and runs the gated tests

Pick one and I'll implement it.
