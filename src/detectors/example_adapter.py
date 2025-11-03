# Small examples for detector authors (auditor-focused)
# These helpers are intentionally separate from `src/detectors` so they can be
# copied or modified by auditors without touching library code.

from typing import Iterable

from src.detectors.adapter import RegexAdapter


class AuditorExampleAdapter:
    """Demonstrates a minimal adapter that finds hard-coded crypto constants.

    This adapter delegates to the existing RegexAdapter for simplicity and
    yields Detection-like dicts compatible with the runner.
    """

    def __init__(self):
        rules = {
            "AES_SBOX_CONST": "(?i)0x3d|0x63|0xca",  # illustrative only
            "KNOWN_MAGIC": "\\x01\\x23\\x45",
        }
        self._impl = RegexAdapter(rules)

    def scan_files(self, files: Iterable[str]):
        for d in self._impl.scan_files(files):
            # annotate with auditor-friendly meta
            if isinstance(d.details, dict):
                d.details.setdefault("meta", {})
                d.details["meta"]["category"] = "crypto"
                d.details["meta"]["auditor_hint"] = "example"
            yield d


# If you want to run this from the command line for a quick smoke test:
if __name__ == "__main__":
    import sys

    files = sys.argv[1:] or ["preproc/dummy/input.bin"]
    a = AuditorExampleAdapter()
    for det in a.scan_files(files):
        print(det)
