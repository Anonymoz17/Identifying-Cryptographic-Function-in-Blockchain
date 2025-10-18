Detector adapters

This project includes a small adapter API in `src/detectors/adapter.py`.

Adapters implement `BaseAdapter.scan_files(files)` and yield `Detection`
objects with the fields `path`, `offset`, `rule` and `details`.

Provided adapters:

- `RegexAdapter`: rules are name->regex; yields a detection per match.
- `SimpleSemgrepAdapter`: rules are name->substring; yields the first match per file.

These adapters are intentionally pure-Python and have no native dependencies.

Example:

```py
from detectors.adapter import RegexAdapter

rules = {"has_magic": "magic_function\\("}
adapter = RegexAdapter(rules)
for det in adapter.scan_files(["path/to/file.sol"]):
    print(det)
```
