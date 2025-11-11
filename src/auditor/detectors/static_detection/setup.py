"""Setup and validation utilities for static detection pipeline.

This module provides user-friendly setup, validation, and diagnostic tools
for ensuring the static detection pipeline is properly configured.
"""
import os
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json

from . import config, ghidra_adapter


class SetupStatus:
    """Container for setup validation results."""
    def __init__(self):
        self.checks: List[Tuple[str, bool, str]] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []
    
    def add_check(self, name: str, passed: bool, message: str):
        """Add a validation check result."""
        self.checks.append((name, passed, message))
        if not passed:
            self.errors.append(f"{name}: {message}")
    
    def add_warning(self, message: str):
        """Add a warning message."""
        self.warnings.append(message)
    
    def is_ready(self) -> bool:
        """Check if all required components are ready."""
        return len(self.errors) == 0
    
    def print_report(self):
        """Print a formatted status report."""
        print("=" * 70)
        print("STATIC DETECTION SETUP STATUS")
        print("=" * 70)
        
        for name, passed, message in self.checks:
            icon = "✅" if passed else "❌"
            print(f"\n{icon} {name}")
            print(f"   {message}")
        
        if self.warnings:
            print("\n⚠️  WARNINGS:")
            for warning in self.warnings:
                print(f"   - {warning}")
        
        print("\n" + "=" * 70)
        if self.is_ready():
            print("✅ READY: All required components are configured")
        else:
            print("❌ NOT READY: Please fix the errors above")
            print("\nRun: python -m src.auditor.detectors.static_detection.setup --help")
        print("=" * 70)


def check_python_version() -> Tuple[bool, str]:
    """Verify Python version is compatible."""
    version = sys.version_info
    if version.major == 3 and 10 <= version.minor <= 13:
        return True, f"Python {version.major}.{version.minor}.{version.micro} ✓"
    return False, f"Python {version.major}.{version.minor} (requires 3.10-3.13)"


def check_required_packages() -> Tuple[bool, str]:
    """Verify required Python packages are installed."""
    required = ["jsonschema"]
    optional = ["tree_sitter", "capstone", "yara"]
    
    missing_required = []
    missing_optional = []
    
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing_required.append(pkg)
    
    for pkg in optional:
        try:
            __import__(pkg)
        except ImportError:
            missing_optional.append(pkg)
    
    if missing_required:
        return False, f"Missing required packages: {', '.join(missing_required)}"
    
    msg = "All required packages installed"
    if missing_optional:
        msg += f" (optional: {', '.join(missing_optional)} not found)"
    return True, msg


def check_ghidra_setup() -> Tuple[bool, str]:
    """Verify Ghidra is configured and accessible."""
    # Check config
    install_dir = config.get_ghidra_install_dir()
    
    # Try to resolve Ghidra
    ghidra_exe = ghidra_adapter.resolve_ghidra()
    
    if not ghidra_exe:
        if install_dir:
            return False, f"Ghidra configured at {install_dir} but executable not found"
        return False, "Ghidra not configured (run setup or set GHIDRA_INSTALL_DIR)"
    
    # Verify executable exists
    if not os.path.isfile(ghidra_exe):
        return False, f"Ghidra executable not found: {ghidra_exe}"
    
    # Try to get version
    try:
        version = ghidra_adapter.verify_ghidra(ghidra_exe)
        if version:
            return True, f"Ghidra {version} at {ghidra_exe}"
        return True, f"Ghidra found at {ghidra_exe} (version unknown)"
    except Exception as e:
        return False, f"Ghidra found but verification failed: {e}"


def check_ghidra_policy() -> Tuple[bool, str]:
    """Verify Ghidra execution policy is configured."""
    try:
        policy = config.get_ghidra_run_policy()
        policies = {
            'auto': 'Smart filtering (skip source code, run on binaries)',
            'always': 'Run on all files (slow but comprehensive)',
            'never': 'Skip Ghidra entirely (fast, source-only mode)'
        }
        description = policies.get(policy, 'Unknown policy')
        return True, f"Policy: {policy} - {description}"
    except Exception as e:
        return False, f"Failed to read policy: {e}"


def check_config_file() -> Tuple[bool, str]:
    """Verify config file location and permissions."""
    try:
        # Get config path
        if os.name == "nt":
            base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        
        config_path = base / "cryptoscope" / "config.json"
        
        if config_path.exists():
            # Check if readable
            try:
                with open(config_path, 'r') as f:
                    cfg = json.load(f)
                return True, f"Config file exists at {config_path} ({len(cfg)} keys)"
            except Exception as e:
                return False, f"Config file exists but not readable: {e}"
        else:
            # Config doesn't exist yet (will be created on first use)
            return True, f"Config will be created at {config_path}"
    except Exception as e:
        return False, f"Failed to check config: {e}"


def check_workspace_structure() -> Tuple[bool, str]:
    """Verify workspace has expected structure."""
    required_dirs = [
        "src/auditor/detectors/static_detection",
        "src/auditor/detectors/static_detection/heuristics",
        "src/auditor/detectors/static_detection/schemas",
    ]
    
    root = Path(__file__).parent.parent.parent.parent.parent
    missing = []
    
    for dir_path in required_dirs:
        if not (root / dir_path).is_dir():
            missing.append(dir_path)
    
    if missing:
        return False, f"Missing directories: {', '.join(missing)}"
    return True, "Workspace structure looks good"


def validate_setup() -> SetupStatus:
    """Run all validation checks and return status."""
    status = SetupStatus()
    
    # Critical checks
    passed, msg = check_python_version()
    status.add_check("Python Version", passed, msg)
    
    passed, msg = check_required_packages()
    status.add_check("Required Packages", passed, msg)
    
    passed, msg = check_workspace_structure()
    status.add_check("Workspace Structure", passed, msg)
    
    passed, msg = check_config_file()
    status.add_check("Config File", passed, msg)
    
    # Ghidra checks (warnings only for 'never' policy)
    policy_passed, policy_msg = check_ghidra_policy()
    status.add_check("Ghidra Policy", policy_passed, policy_msg)
    
    ghidra_passed, ghidra_msg = check_ghidra_setup()
    
    # Get current policy
    try:
        current_policy = config.get_ghidra_run_policy()
    except:
        current_policy = 'auto'
    
    if current_policy == 'never':
        # Ghidra not required
        status.add_check("Ghidra Setup", True, "Skipped (policy='never')")
        if not ghidra_passed:
            status.add_warning(f"Ghidra not configured: {ghidra_msg}")
    else:
        # Ghidra required
        status.add_check("Ghidra Setup", ghidra_passed, ghidra_msg)
    
    return status


def setup_ghidra_interactive():
    """Interactive Ghidra setup wizard."""
    print("=" * 70)
    print("GHIDRA SETUP WIZARD")
    print("=" * 70)
    
    # Check if already configured
    current = ghidra_adapter.resolve_ghidra()
    if current:
        print(f"\n✅ Ghidra is already configured:")
        print(f"   {current}")
        response = input("\nReconfigure? (y/N): ").strip().lower()
        if response != 'y':
            print("Setup cancelled.")
            return
    
    print("\nGhidra can be configured in several ways:")
    print("1. Set GHIDRA_INSTALL_DIR environment variable")
    print("2. Use automatic installer (installation/install-ghidra.ps1)")
    print("3. Manually specify path to Ghidra installation")
    print("4. Skip Ghidra (source-code-only mode)")
    
    choice = input("\nChoose option (1-4): ").strip()
    
    if choice == '1':
        print("\nSet the GHIDRA_INSTALL_DIR environment variable to your Ghidra")
        print("installation directory (e.g., C:\\ghidra_10.1.5)")
        print("Then restart your terminal and run setup again.")
    
    elif choice == '2':
        print("\nRun the following command to install Ghidra:")
        if os.name == "nt":
            print("   powershell -File .\\installation\\install-ghidra.ps1")
        else:
            print("   See installation/README.md for Unix instructions")
    
    elif choice == '3':
        install_dir = input("\nEnter Ghidra installation directory: ").strip()
        if os.path.isdir(install_dir):
            try:
                config.set_ghidra_install_dir(install_dir)
                print(f"\n✅ Ghidra configured: {install_dir}")
                
                # Verify it works
                ghidra_exe = ghidra_adapter.resolve_ghidra()
                if ghidra_exe:
                    print(f"✅ Found executable: {ghidra_exe}")
                else:
                    print("⚠️  Warning: Could not find analyzeHeadless executable")
            except Exception as e:
                print(f"❌ Error: {e}")
        else:
            print(f"❌ Directory not found: {install_dir}")
    
    elif choice == '4':
        config.set_ghidra_run_policy('never')
        print("\n✅ Ghidra disabled (source-code-only mode)")
        print("   You can enable it later with:")
        print("   from src.auditor.detectors.static_detection import config")
        print("   config.set_ghidra_run_policy('auto')")
    
    else:
        print("Invalid choice. Setup cancelled.")


def print_usage():
    """Print usage information."""
    print("""
Static Detection Setup Utility

Usage:
  python -m src.auditor.detectors.static_detection.setup [command]

Commands:
  check       Run validation checks and show status (default)
  wizard      Run interactive Ghidra setup wizard
  policy      Show current Ghidra policy
  help        Show this help message

Examples:
  # Check if everything is configured
  python -m src.auditor.detectors.static_detection.setup

  # Run setup wizard
  python -m src.auditor.detectors.static_detection.setup wizard

  # Check current policy
  python -m src.auditor.detectors.static_detection.setup policy

Configuration:
  Config file: %APPDATA%\\cryptoscope\\config.json (Windows)
              ~/.config/cryptoscope/config.json (Linux/Mac)

  Ghidra policy options:
    auto    - Smart filtering (default, recommended)
    always  - Force Ghidra on all files (slow)
    never   - Skip Ghidra entirely (fast, source-only)

For more information, see:
  - docs/ghidra-policy.md
  - installation/README.md
""")


def main():
    """Main entry point for setup utility."""
    args = sys.argv[1:]
    
    if not args or args[0] == 'check':
        # Run validation
        status = validate_setup()
        status.print_report()
        sys.exit(0 if status.is_ready() else 1)
    
    elif args[0] == 'wizard':
        setup_ghidra_interactive()
    
    elif args[0] == 'policy':
        try:
            policy = config.get_ghidra_run_policy()
            print(f"Current Ghidra policy: {policy}")
            print("\nTo change:")
            print("  from src.auditor.detectors.static_detection import config")
            print(f"  config.set_ghidra_run_policy('auto')  # or 'always' or 'never'")
        except Exception as e:
            print(f"Error reading policy: {e}")
            sys.exit(1)
    
    elif args[0] in ('help', '--help', '-h'):
        print_usage()
    
    else:
        print(f"Unknown command: {args[0]}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
