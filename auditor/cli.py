"""CLI runner for the Auditor pipeline (stages 0-1).

Usage (from repo root):
    python -m auditor.cli --workdir ./case_demo --case-id CASE-001 --client "ACME" --scope . --policy ./policy.json

This script creates engagement metadata, copies policy baseline (if given),
appends to auditlog.ndjson, enumerates inputs and writes inputs.manifest.json.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from auditor.case import Engagement
from auditor.auditlog import AuditLog
from auditor.intake import enumerate_inputs, write_manifest
from auditor.preproc import preprocess_items
from auditor.workspace import Workspace


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--workdir", default="./case_demo")
    p.add_argument("--case-id", default="CASE-001")
    p.add_argument("--client", default="ACME Corp")
    p.add_argument("--scope", default=".")
    p.add_argument("--policy", default=None)
    args = p.parse_args(argv)

    base = Path(args.workdir).resolve()
    ws = Workspace(base, args.case_id)
    ws.ensure()

    eng = Engagement(workdir=str(ws.root), case_id=args.case_id, client=args.client, scope=args.scope)
    eng.write_metadata()
    if args.policy:
        eng.import_policy_baseline(args.policy)

    al = AuditLog(str(ws.paths()['auditlog']))
    al.append('engagement.created', {'case_id': args.case_id, 'client': args.client, 'scope': args.scope, 'airgapped': False})

    items = enumerate_inputs([args.scope])
    manifest_path = ws.paths()['inputs_manifest']
    write_manifest(str(manifest_path), items)
    al.append('inputs.ingested', {'manifest': manifest_path.name, 'count': len(items)})

    # run preprocessing scaffold
    try:
        preproc_index = preprocess_items(items, str(ws.root))
        al.append('preproc.completed', {'index_lines': len(preproc_index)})
    except Exception as e:
        al.append('preproc.failed', {'error': str(e)})

    print(f"Wrote engagement to {ws.root}; {len(items)} inputs recorded")


if __name__ == '__main__':
    main()
