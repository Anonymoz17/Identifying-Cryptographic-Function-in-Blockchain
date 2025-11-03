import sys
from pathlib import Path
from pathlib import Path as P

# ensure repo root on sys.path like pytest does
sys.path.insert(0, str(P(".").resolve()))
from src.detectors.adapter import YaraAdapter  # noqa: E402

rules_dir = Path("detectors/yara")
print("cwd=", Path(".").resolve())
print("rules_dir exists?", rules_dir.exists(), "abs=", rules_dir.resolve())
try:
    adapter = YaraAdapter(rules_dir=str(rules_dir))
    print("YaraAdapter compiled:", adapter._compiled is not None)
except Exception as e:
    print("YaraAdapter init raised:", type(e), e)
    adapter = None

fp = Path().cwd().joinpath("tmp_test_yara_file.bin")
fp.write_text("this file calls sha3()")

if adapter is not None:
    dets = list(adapter.scan_files([str(fp)]))
    print("detections count:", len(dets))
    for d in dets:
        print("DETECTION:", d.engine, d.rule, d.offset, d.details)
else:
    print("no adapter")
print("\nAdditional debug:")
print("yara module present?", adapter._yara is not None if adapter else "no adapter")
try:
    import yara

    print("yara version:", getattr(yara, "__version__", "unknown"))
except Exception as e:
    print("cannot import yara:", e)

print("files under src/detectors/yara:")

for p in Path("src/detectors/yara").glob("**/*.yar"):
    print(" -", p)

if adapter and adapter._compiled:
    print("compiled object repr:", repr(adapter._compiled)[:200])
    print(
        "compiled attributes:",
        [a for a in dir(adapter._compiled) if not a.startswith("_")],
    )
    try:
        # try a direct match using the compiled object
        m = adapter._compiled.match(data=fp.read_bytes())
        print("direct match returned:", m)
    except Exception as e:
        print("direct match exception:", e)
    try:
        m2 = adapter._compiled.match(filepath=str(fp))
        print("direct match(filepath) returned:", m2)
    except Exception as e:
        print("direct match(filepath) exception:", e)

print("\nTesting a minimal compiled rule directly:")
try:
    import yara

    r = yara.compile(source='rule r { strings: $s = "sha3" condition: $s }')
    print(
        "compiled minimal rule ok, match on data:",
        r.match(data=b"this file calls sha3()"),
    )
    # try file path
    print("match on filepath:", r.match(filepath=str(fp)))
except Exception as e:
    print("minimal rule test failed:", e)

print("\nNow compile explicitly from src/detectors/yara filepaths:")
try:
    import yara

    filepaths = {p.name: str(p) for p in Path("src/detectors/yara").glob("**/*.yar")}
    print("filepaths mapping keys:", list(filepaths.keys()))
    compiled2 = yara.compile(filepaths=filepaths)
    print("compiled2 match on data:", compiled2.match(data=b"this file calls sha3()"))
except Exception as e:
    print("explicit compile failed:", e)
fp.unlink()
