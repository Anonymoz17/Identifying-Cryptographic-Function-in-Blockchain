import sys

import yara

rules = "src/detectors/yara/crypto.yar"
try:
    compiled = yara.compile(filepath=rules)
    print("compiled ok:", compiled)
except Exception as e:
    print("compile failed:", e)
    sys.exit(2)
