import hashlib, json, os
base = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tests', 'fixtures')
res = {}
for name in ['preproc_example','preproc_with_hash','preproc_mismatch_hash']:
    p = os.path.join(base, name, 'input.bin')
    with open(p, 'rb') as f:
        res[name] = hashlib.sha256(f.read()).hexdigest()
print(json.dumps(res, indent=2))
