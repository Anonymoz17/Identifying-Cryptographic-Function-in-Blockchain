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
from typing import Optional, Dict, Any


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        # ensure file exists
        if not os.path.exists(self.path):
            open(self.path, 'a').close()

    def _last_record(self) -> Optional[Dict[str, Any]]:
        try:
            with open(self.path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                if f.tell() == 0:
                    return None
                # read backwards a small window to find last newline
                size = min(f.tell(), 4096)
                f.seek(-size, os.SEEK_END)
                tail = f.read().decode('utf-8', errors='replace')
                lines = [l for l in tail.splitlines() if l.strip()]
                if not lines:
                    return None
                last = lines[-1]
                return json.loads(last)
        except Exception:
            return None

    def append(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        last = self._last_record()
        seq = (last.get('seq', 0) if last else 0) + 1
        ts = datetime.datetime.utcnow().isoformat() + 'Z'
        prev = last.get('digest') if last else None
        rec_obj = {"seq": seq, "ts": ts, "event": event, "payload": payload, "prev": prev}
        # canonical JSON bytes for hashing
        b = json.dumps(rec_obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        digest = hashlib.sha256(b).hexdigest()
        rec_obj['digest'] = digest
        with open(self.path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec_obj, sort_keys=True, ensure_ascii=False) + '\n')
        return rec_obj

    def verify(self) -> bool:
        """Verify the chain integrity. Returns True if chain is valid."""
        last_digest = None
        seq = 0
        with open(self.path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                seq += 1
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


if __name__ == '__main__':
    al = AuditLog('./case_demo/auditlog.ndjson')
    print(al.append('engagement.created', {'case': 'CASE-001'}))
    print('verify:', al.verify())
