#!/usr/bin/env python3
"""Helper to persist Ghidra install dir into the per-user app config.

This script is intended to be called from installer scripts (PowerShell) to
set or unset the persisted ghidra.install_dir used by the static_detection
config helper.

Usage:
  python tools/set_ghidra_config.py --set "C:\Path\to\ghidra"
  python tools/set_ghidra_config.py --unset
"""
import argparse
import sys
from pathlib import Path

try:
    from src.auditor.detectors.static_detection import config
except Exception:
    # allow running from repo root by adding src to sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    try:
        from auditor.detectors.static_detection import config
    except Exception:
        # best-effort import fallback
        try:
            from src.auditor.detectors.static_detection import config
        except Exception as exc:
            print("failed to import config helper:", exc, file=sys.stderr)
            sys.exit(2)


def main():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--set", dest="set_path", help="Set the ghidra install path")
    g.add_argument("--unset", dest="unset", action="store_true", help="Unset persisted ghidra install path")
    args = p.parse_args()

    if args.unset:
        # clear config
        try:
            cfg = config.load_config()
            if isinstance(cfg, dict) and cfg.get("ghidra"):
                cfg.pop("ghidra", None)
                config.save_config(cfg)
            print("ok: unset")
            return 0
        except Exception as exc:
            print("error: failed to unset config:", exc, file=sys.stderr)
            return 1

    set_path = args.set_path
    if set_path:
        try:
            p = str(Path(set_path).resolve())
            config.set_ghidra_install_dir(p)
            print(f"ok: set {p}")
            return 0
        except Exception as exc:
            print("error: failed to set config:", exc, file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
