"""Small helper to run the preprocessing scaffold from the command line.

Usage:
    python tools\run_preproc.py --workdir ./case_demo
    python tools\run_preproc.py --manifest ./case_demo/inputs.manifest.json --workdir ./case_demo

The script will read inputs.manifest.json (if provided) and call
`auditor.preproc.preprocess_items` with a progress callback that prints counts.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.abspath('.'))

from auditor.preproc import preprocess_items


def load_manifest(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f).get('items', [])


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--workdir', default='./case_demo')
    p.add_argument('--manifest', default=None)
    args = p.parse_args(argv)

    wd = os.path.abspath(args.workdir)
    os.makedirs(wd, exist_ok=True)

    if args.manifest:
        manifest_path = os.path.abspath(args.manifest)
    else:
        manifest_path = os.path.join(wd, 'inputs.manifest.json')

    if not os.path.exists(manifest_path):
        print(f'Manifest not found at {manifest_path}. Run intake first (UI or auditor.cli).')
        return 2

    items = load_manifest(manifest_path)
    total = len(items)
    print(f'Loaded manifest with {total} items from {manifest_path}')

    cancel_event = threading.Event()

    def progress_cb(processed, total):
        print(f'Preproc: {processed}/{total}', end='\r', flush=True)

    try:
        idx = preprocess_items(items, wd, progress_cb=progress_cb, cancel_event=cancel_event)
        print('\nPreprocessing finished, index lines:', len(idx))
        print('Check', os.path.join(wd, 'preproc'))
        return 0
    except KeyboardInterrupt:
        cancel_event.set()
        print('\nPreprocessing cancelled by user')
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
