import sys
sys.path.insert(0, r'C:\!Everything Programming\Github Projects\FYP\Identifying-Cryptographic-Function-in-Blockchain\src')

from auditor.detectors.static_detection.ghidra_adapter import ensure_ghidra_export
import os
import json

result = ensure_ghidra_export(
    r'C:\temp\test_crypto.exe',
    r'C:\temp\ghidra_test',
    'abc123',
    {
        'install_dir': r'C:\Users\luizt\Desktop\ghidra_11.4.2_PUBLIC_20250826\ghidra_11.4.2_PUBLIC',
        'timeout': 90,
        'force': True
    }
)

print(f'Result: {result}')

if result and os.path.isfile(result):
    with open(result) as f:
        data = json.load(f)
    print(f'Found {len(data)} functions')
    print('First 5:', [func.get('name') for func in data[:5]])
    print('\nCrypto-related functions:')
    for func in data:
        name = func.get('name', '').lower()
        if any(keyword in name for keyword in ['xor', 'encrypt', 'hash', 'aes', 'crypto']):
            print(f"  - {func.get('name')} at {func.get('address')}")
else:
    print('No result file created!')
