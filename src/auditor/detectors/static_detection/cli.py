"""CLI entrypoints for static detection (skeleton).

Usage (future):
  static-detect run <preproc_dir> [--force] [--profile quick|full]
  static-detect export-raw <file_hash>
"""
import argparse
from .context import RunContext


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="static-detect")
    sp = p.add_subparsers(dest="cmd")

    run = sp.add_parser("run")
    run.add_argument("preproc_dir")
    run.add_argument("--force", action="store_true")
    run.add_argument("--profile", choices=("quick", "full"), default="quick")

    sp.add_parser("export-raw")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    if ns.cmd == "run":
        ctx = RunContext(file_hash="", preproc_dir=ns.preproc_dir, analysis_base=".")
        # In the real implementation we would instantiate StaticRunner and call run(ctx)
        print("Running static detection (stub)")
        return 0
    print("No command specified")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
