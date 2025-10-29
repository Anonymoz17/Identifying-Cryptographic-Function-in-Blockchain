import shutil
import subprocess
import tempfile
from pathlib import Path

from src.detectors.adapter import RegexAdapter
from src.detectors.ghidra_adapter import GhidraAdapter
from src.detectors.runner import load_manifest_paths, run_adapters

repo_root = Path(__file__).resolve().parents[1]
src_case = repo_root / "tools" / "case_demo" / "CASE-001"

tmp = Path(tempfile.mkdtemp())
dst_case = tmp / "CASE-001"
shutil.copytree(src_case, dst_case)

# inject mock exports
consume = repo_root / "tools" / "consume_ghidra_mock.py"
subprocess.run(["python", str(consume), "--case", str(dst_case)], check=True)

manifest = dst_case / "inputs.manifest.ndjson"
files = load_manifest_paths(str(manifest), base_dir=str(dst_case))
print("loaded", len(files), "files")

adapters = [
    RegexAdapter({"crypto_fallback": r"sha|AES|md5"}),
    GhidraAdapter(exports_root=str(dst_case / "artifacts" / "ghidra_exports")),
]

dets = list(run_adapters(adapters, files))
print("total detections:", len(dets))
engines = {}
for d in dets:
    engines.setdefault(d.engine, 0)
    engines[d.engine] += 1
print("engines:", engines)
for d in dets[:10]:
    print(d)

print("temp case at", dst_case)
print("\n--- RUN GHIDRA ADAPTER DIRECTLY ---")
g = GhidraAdapter(exports_root=str(dst_case / "artifacts" / "ghidra_exports"))
gdets = list(g.scan_files(files))
print("ghidra detections direct:", len(gdets))
for d in gdets:
    print("gdet", d)
