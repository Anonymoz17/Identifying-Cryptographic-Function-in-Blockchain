#!/usr/bin/env python3
"""
Test if Frida can spawn and hook processes on Windows.

This is a simple test to verify Frida installation and functionality.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def test_frida_installation():
    """Test if Frida is installed and working."""
    print("=" * 60)
    print("FRIDA INSTALLATION TEST")
    print("=" * 60)
    
    # Step 1: Import Frida
    try:
        import frida
        print(f"✓ Frida imported successfully")
        print(f"  - Version: {frida.__version__}")
    except ImportError as e:
        print(f"✗ Failed to import Frida: {e}")
        return False
    
    # Step 2: Check device
    try:
        device = frida.get_local_device()
        print(f"✓ Local device accessed: {device}")
    except Exception as e:
        print(f"✗ Failed to get local device: {e}")
        return False
    
    # Step 3: Try to spawn a simple process
    try:
        print(f"\nTesting process spawn...")
        # Try to spawn a Windows command that does nothing and exits quickly
        # Use full path to cmd.exe
        cmd_path = r'C:\Windows\System32\cmd.exe'
        if not os.path.exists(cmd_path):
            print(f"✗ cmd.exe not found at {cmd_path}")
            return False
        
        pid = frida.spawn([cmd_path, '/c', 'exit'], stdio='inherit')
        print(f"✓ Process spawned successfully: PID {pid}")
        
        # Immediately resume and let it exit
        frida.resume(pid)
        print(f"✓ Process resumed")
        
        import time
        time.sleep(0.5)
        
        print(f"✓ Frida spawning/resuming works")
        
    except Exception as e:
        print(f"✗ Failed to spawn process: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 4: Try to attach to a process and load a script
    try:
        print(f"\nTesting script loading...")
        
        # Spawn a process that stays alive
        notepad_path = r'C:\Windows\System32\notepad.exe'
        if not os.path.exists(notepad_path):
            print(f"✗ notepad.exe not found at {notepad_path}")
            return False
            
        pid = frida.spawn([notepad_path], stdio='inherit')
        print(f"✓ Spawned notepad: PID {pid}")
        
        # Attach
        session = frida.attach(pid)
        print(f"✓ Attached to process")
        
        # Create a simple script
        script_code = """
console.log("[Test] Script loaded successfully");
send({type: "test_message", data: "Hello from Frida"});
"""
        
        script = session.create_script(script_code)
        
        # Set message handler
        messages_received = []
        def on_message(message, data):
            messages_received.append(message)
            print(f"  - Received: {message}")
        
        script.on('message', on_message)
        
        # Load script
        script.load()
        print(f"✓ Script loaded")
        
        # Wait a bit for messages
        import time
        time.sleep(1)
        
        if messages_received:
            print(f"✓ {len(messages_received)} message(s) received from Frida")
        else:
            print(f"✗ No messages received (but script loaded without error)")
        
        # Cleanup
        script.unload()
        session.detach()
        frida.kill(pid)
        print(f"✓ Cleanup completed")
        
    except Exception as e:
        print(f"✗ Failed during script test: {e}")
        import traceback
        traceback.print_exc()
        try:
            frida.kill(pid)
        except:
            pass
        return False
    
    print("\n" + "=" * 60)
    print("RESULT: Frida is working properly!")
    print("=" * 60)
    return True


if __name__ == '__main__':
    try:
        success = test_frida_installation()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(130)
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
