"""auditor.auditlog

A simple append-only NDJSON audit log with hash-chaining.
Each line is a JSON object with the following fields:
  - seq: sequence number
  - ts: ISO timestamp
  - event: event type string
  - payload: arbitrary JSON-serializable object
  - prev: hex digest of previous record (or null for first)
  - digest: hex digest of this record's canonical bytes

The canonical bytes used for digest are the UTF-8 encoded JSON of the
`seq, ts, event, payload, prev` object with keys sorted. This keeps the
chain deterministic and easy to audit.
"""
from __future__ import annotations

import os
import json
import datetime
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import timezone


def _atomic_append(path: Path, text: str) -> None:
    """Append text to a file atomically by opening in append mode.

    On POSIX this is already atomic for single write() calls; we ensure
    encoding is set and flush+fsync if available.
    """
    with path.open('a', encoding='utf-8') as f:
        f.write(text)
        try:
            f.flush()
            os.fsync(f.fileno())
        except Exception:
            pass


class AuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # ensure file exists
        if not self.path.exists():
            self.path.write_text('', encoding='utf-8')

    def _last_record(self) -> Optional[Dict[str, Any]]:
        try:
            # read last non-empty line
            with self.path.open('r', encoding='utf-8') as f:
                last = None
                for line in f:
                    if line.strip():
                        last = line
                if not last:
                    return None
                return json.loads(last)
        except Exception:
            return None

    def append(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        last = self._last_record()
        seq = (last.get('seq', 0) if last else 0) + 1
        ts = datetime.datetime.now(timezone.utc).isoformat()
        prev = last.get('digest') if last else None
        rec_obj = {"seq": seq, "ts": ts, "event": event, "payload": payload, "prev": prev}
        # canonical JSON bytes for hashing
        b = json.dumps(rec_obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        digest = hashlib.sha256(b).hexdigest()
        rec_obj['digest'] = digest
        line = json.dumps(rec_obj, sort_keys=True, ensure_ascii=False) + '\n'
        _atomic_append(self.path, line)
        return rec_obj

    def verify(self) -> bool:
        """Verify the chain integrity. Returns True if chain is valid."""
        last_digest = None
        with self.path.open('r', encoding='utf-8') as f:
            for idx, raw in enumerate(f, start=1):
                if not raw.strip():
                    continue
                rec = json.loads(raw)
                expected_prev = last_digest
                if rec.get('prev') != expected_prev:
                    return False
                # recompute digest from fields (excluding digest)
                base = {k: rec[k] for k in ('seq', 'ts', 'event', 'payload', 'prev')}
                b = json.dumps(base, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                if hashlib.sha256(b).hexdigest() != rec.get('digest'):
                    return False
                last_digest = rec.get('digest')
        return True

    def verify_with_diagnostics(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Verify chain and return (ok, None) or (False, diagnostic dict).

        Diagnostic dict includes 'line', 'seq', 'reason', and the offending record.
        """
        last_digest = None
        with self.path.open('r', encoding='utf-8') as f:
            for idx, raw in enumerate(f, start=1):
                if not raw.strip():
                    continue
                rec = json.loads(raw)
                expected_prev = last_digest
                if rec.get('prev') != expected_prev:
                    return False, {'line': idx, 'seq': rec.get('seq'), 'reason': 'prev_mismatch', 'record': rec}
                base = {k: rec[k] for k in ('seq', 'ts', 'event', 'payload', 'prev')}
                b = json.dumps(base, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                if hashlib.sha256(b).hexdigest() != rec.get('digest'):
                    return False, {'line': idx, 'seq': rec.get('seq'), 'reason': 'digest_mismatch', 'record': rec}
                last_digest = rec.get('digest')
        return True, None


if __name__ == '__main__':
    al = AuditLog('./case_demo/auditlog.ndjson')
    print(al.append('engagement.created', {'case': 'CASE-001'}))
    print('verify:', al.verify())
