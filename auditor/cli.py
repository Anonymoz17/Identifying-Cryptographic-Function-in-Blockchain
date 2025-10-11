"""CLI runner for the Auditor pipeline (stages 0-1).

Usage (from repo root):
    python -m auditor.cli --workdir ./case_demo --case-id CASE-001 --client "ACME" --scope . --policy ./policy.json

This script creates engagement metadata, copies policy baseline (if given),
appends to auditlog.ndjson, enumerates inputs and writes inputs.manifest.json.
"""
from __future__ import annotations

import argparse
import os
from auditor.case import Engagement
from auditor.auditlog import AuditLog
from auditor.intake import enumerate_inputs, write_manifest


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--workdir", default="./case_demo")
    p.add_argument("--case-id", default="CASE-001")
    p.add_argument("--client", default="ACME Corp")
    p.add_argument("--scope", default=".")
    p.add_argument("--policy", default=None)
    args = p.parse_args(argv)

    wd = os.path.abspath(args.workdir)
    os.makedirs(wd, exist_ok=True)

    eng = Engagement(workdir=wd, case_id=args.case_id, client=args.client, scope=args.scope)
    eng.write_metadata()
    if args.policy:
        eng.import_policy_baseline(args.policy)

    al = AuditLog(os.path.join(wd, 'auditlog.ndjson'))
    al.append('engagement.created', {'case_id': args.case_id, 'client': args.client, 'scope': args.scope, 'airgapped': False})

    items = enumerate_inputs([args.scope])
    manifest_path = os.path.join(wd, 'inputs.manifest.json')
    write_manifest(manifest_path, items)
    al.append('inputs.ingested', {'manifest': os.path.basename(manifest_path), 'count': len(items)})

    print(f"Wrote engagement to {wd}; {len(items)} inputs recorded")


if __name__ == '__main__':
    main()
