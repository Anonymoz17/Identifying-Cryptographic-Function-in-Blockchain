from pathlib import Path

from auditor.setup_flow.hash_dedupe import HasherDedupe
from auditor.setup_flow.setupmessages import Notifier


class DummyNotifier(Notifier):
    def __init__(self):
        super().__init__()
        self.events = []

    def ok(self, text, path=None, details=None):
        self.events.append(("ok", text, path, details))

    def skip(self, text, path=None, details=None):
        self.events.append(("skip", text, path, details))

    def warn(self, text, path=None, details=None):
        self.events.append(("warn", text, path, details))


def test_hasher_dedupe(tmp_path):
    f1 = tmp_path / "a.bin"
    f2 = tmp_path / "b.bin"
    f1.write_bytes(b"hello")
    f2.write_bytes(b"hello")

    notifier = DummyNotifier()
    hd = HasherDedupe(notifier=notifier, skip_duplicates=True)

    items = [{"path": str(f1)}, {"path": str(f2)}]
    out = list(hd.process(iter(items)))
    # first yielded, second duplicate skipped
    assert len(out) == 1
    assert hd.stats["duplicates"] == 1
