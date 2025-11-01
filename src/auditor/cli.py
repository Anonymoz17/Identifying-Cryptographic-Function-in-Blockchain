"""CLI runner for the Auditor pipeline (stages 0-1).

Usage (from repo root):
    python -m auditor.cli --workdir ./case_demo --case-id CASE-001 --client "ACME" --scope . --policy ./policy.json

This script creates engagement metadata, copies policy baseline (if given),
appends to auditlog.ndjson, enumerates inputs and writes inputs.manifest.json.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from auditor.auditlog import AuditLog
from auditor.case import Engagement
from auditor.intake import enumerate_inputs, write_manifest
from auditor.preproc import preprocess_items
from auditor.workspace import Workspace


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--workdir", default="./case_demo")
    p.add_argument("--case-id", default="CASE-001")
    p.add_argument("--client", default="ACME Corp")
    p.add_argument("--scope", default=".")
    p.add_argument(
        "--include",
        default=None,
        help="Comma-separated include glob patterns (e.g. '*.sol,src/**')",
    )
    p.add_argument(
        "--exclude",
        default=None,
        help="Comma-separated exclude glob patterns (e.g. 'node_modules,build/**')",
    )
    p.add_argument(
        "--max-size-kb",
        default=0,
        type=int,
        help="Skip files larger than this size in KB (0 = no limit)",
    )
    p.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symbolic links when scanning",
    )
    p.add_argument("--policy", default=None)
    args = p.parse_args(argv)

    base = Path(args.workdir).resolve()
    ws = Workspace(base, args.case_id)
    ws.ensure()

    eng = Engagement(
        workdir=str(ws.root), case_id=args.case_id, client=args.client, scope=args.scope
    )
    eng.write_metadata()
    if args.policy:
        eng.import_policy_baseline(args.policy)

    al = AuditLog(str(ws.paths()["auditlog"]))
    al.append(
        "engagement.created",
        {
            "case_id": args.case_id,
            "client": args.client,
            "scope": args.scope,
            "airgapped": False,
        },
    )

    # parse filters
    include_globs = [
        g.strip() for g in (args.include or "").split(",") if g.strip()
    ] or None
    exclude_globs = [
        g.strip() for g in (args.exclude or "").split(",") if g.strip()
    ] or None
    max_bytes = (
        (args.max_size_kb * 1024) if args.max_size_kb and args.max_size_kb > 0 else None
    )

    items = enumerate_inputs(
        [args.scope],
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        max_file_size_bytes=max_bytes,
        follow_symlinks=bool(args.follow_symlinks),
    )
    manifest_path = ws.paths()["inputs_manifest"]
    write_manifest(str(manifest_path), items)
    al.append("inputs.ingested", {"manifest": manifest_path.name, "count": len(items)})

    # run preprocessing scaffold
    try:
        preproc_res = preprocess_items(items, str(ws.root))
        stats = preproc_res.get("stats", {})
        al.append("preproc.completed", {"index_lines": stats.get("index_lines")})
    except Exception as e:
        al.append("preproc.failed", {"error": str(e)})

    print(f"Wrote engagement to {ws.root}; {len(items)} inputs recorded")


if __name__ == "__main__":
    main()
