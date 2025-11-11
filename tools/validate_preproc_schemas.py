import json, os, glob, sys
from auditor.detectors.static_detection import validator

repo_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
schema_path = os.path.join(repo_root, 'src', 'auditor', 'detectors', 'static_detection', 'schemas', 'preproc.metadata.schema.json')
if not os.path.isfile(schema_path):
    print('schema file not found:', schema_path)
    sys.exit(2)
with open(schema_path, 'r', encoding='utf-8') as fh:
    schema = json.load(fh)

fixture_dirs = glob.glob(os.path.join(repo_root, 'tests', 'fixtures', '*'))
errors = 0
for d in fixture_dirs:
    mpath = os.path.join(d, 'metadata.json')
    if not os.path.isfile(mpath):
        print('no metadata in', d)
        errors += 1
        continue
    with open(mpath, 'r', encoding='utf-8') as fh:
        meta = json.load(fh)
    try:
        # Only validate if metadata declares schema_version
        if 'schema_version' in meta:
            validator.validate_schema(meta, schema)
            print('OK', os.path.basename(d))
        else:
            print('SKIP (no schema_version)', os.path.basename(d))
    except Exception as e:
        print('ERROR', os.path.basename(d), e)
        errors += 1

if errors:
    print('schema validation errors:', errors)
    sys.exit(1)
print('all validated')
