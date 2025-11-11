#!/usr/bin/env python3
"""
Diagnostic script to check hook generation from hints.

Tests whether frida_scripter properly converts hints into JavaScript hooks.
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from auditor.detectors.dynamic_detection import frida_scripter, config

def diagnose_hook_generation():
    """Diagnose hook generation from hints."""
    
    # Path to the hints file from caseOK
    case_root = Path(__file__).parent / "test_case" / "caseOK"
    
    # Get first hints file
    hints_files = list(case_root.glob("analysis/static/*/hints.json"))
    if not hints_files:
        print("ERROR: No hints files found in test_case/caseOK/analysis/static/")
        return False
    
    hints_path = hints_files[0]
    print(f"Using hints file: {hints_path}")
    
    # Load hints
    try:
        with open(hints_path, 'r') as f:
            hints_data = json.load(f)
        print(f"✓ Loaded hints: {len(hints_data.get('hints', []))} hints found")
        
        # Show hint structure
        if hints_data.get('hints'):
            first_hint = hints_data['hints'][0]
            print(f"\nFirst hint structure:")
            print(f"  - id: {first_hint.get('id')}")
            print(f"  - type: {first_hint.get('type')}")
            print(f"  - name: {first_hint.get('name')}")
            print(f"  - confidence: {first_hint.get('confidence')}")
    except Exception as e:
        print(f"ERROR: Failed to load hints: {e}")
        return False
    
    # Load config
    cfg = config.Config.load()
    print(f"\n✓ Loaded config")
    print(f"  - Instrumenters enabled:")
    instrumenters = cfg.get('instrumenters')
    for inst, enabled in instrumenters.items():
        print(f"    - {inst}: {enabled}")
    
    bcrypt_apis = cfg.get('crypto_apis', 'bcrypt')
    crypt32_apis = cfg.get('crypto_apis', 'crypt32')
    print(f"  - Default bcrypt APIs: {len(bcrypt_apis) if bcrypt_apis else 0} APIs")
    print(f"  - Default crypt32 APIs: {len(crypt32_apis) if crypt32_apis else 0} APIs")
    
    # Generate hooks
    try:
        hooks = frida_scripter.generate_hooks(hints_data, cfg)
        print(f"\n✓ Generated {len(hooks)} hook scripts")
        
        total_lines = sum(len(h.split('\n')) for h in hooks)
        total_size = sum(len(h) for h in hooks)
        print(f"  - Total lines: {total_lines}")
        print(f"  - Total size: {total_size} bytes")
        
        # Analyze hooks
        for i, hook in enumerate(hooks):
            lines = hook.split('\n')
            print(f"\n  Hook {i+1}:")
            print(f"    - Lines: {len(lines)}")
            print(f"    - Size: {len(hook)} bytes")
            
            # First few lines (header)
            print(f"    - Header: {lines[0][:60] if lines else '(empty)'}")
            
            # Look for specific patterns
            if 'BCrypt' in hook:
                bcrypt_count = hook.count('BCrypt')
                print(f"    - BCrypt function mentions: {bcrypt_count}")
            
            if 'CryptEncrypt' in hook or 'CryptDecrypt' in hook or 'CryptHash' in hook:
                crypt32_count = hook.count('Crypt')
                print(f"    - Crypt32 function mentions: {crypt32_count}")
            
            if 'crypto_call' in hook:
                print(f"    - Contains crypto_call events: Yes")
            else:
                print(f"    - Contains crypto_call events: No")
            
            if 'send(' in hook:
                send_count = hook.count('send(')
                print(f"    - send() calls: {send_count}")
    
    except Exception as e:
        print(f"ERROR: Failed to generate hooks: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "="*60)
    print("DIAGNOSIS SUMMARY")
    print("="*60)
    
    # Show sample hook content (first 500 chars of crypto_ops hook)
    if hooks:
        crypto_script = None
        for hook in hooks:
            if 'BCryptEncrypt' in hook:
                crypto_script = hook
                break
        
        if crypto_script:
            print("\nSample crypto_ops hook (first 1000 chars):")
            print("-" * 60)
            print(crypto_script[:1000])
            print("-" * 60)
        
        # Check if hooks actually use hints
        print("\nHook content analysis:")
        all_hooks_text = '\n'.join(hooks)
        
        if 'hint_id' in all_hooks_text:
            print("✓ Hooks reference hint IDs")
            hint_id_count = all_hooks_text.count('hint_id')
            print(f"  - hint_id references: {hint_id_count}")
        else:
            print("✗ Hooks DO NOT reference hint IDs")
        
        # Count actual crypto API hooks
        bcrypt_hooked = all_hooks_text.count('Hooked: BCrypt')
        crypt32_hooked = all_hooks_text.count('Hooked: Crypt')
        print(f"\n✓ Crypto API hooks installed:")
        print(f"  - BCrypt functions hooked: ~{bcrypt_hooked}")
        print(f"  - Crypt32 functions hooked: ~{crypt32_hooked}")
    
    print("\n" + "="*60)
    print("NEXT STEPS")
    print("="*60)
    print("1. If hint_id is found -> hints ARE being used")
    print("2. If hook size is reasonable -> hooks are being generated")
    print("3. If crypto_call events are present -> Frida can capture them")
    print("4. Next: Check if Frida is actually RUNNING these hooks")
    
    return True


if __name__ == '__main__':
    try:
        success = diagnose_hook_generation()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(130)
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
