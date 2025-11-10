"""
Windows sandbox for dynamic analysis.

Provides isolation and resource limits for executing binaries
during Frida instrumentation.
"""

import os
import tempfile
import shutil
import time
from typing import Dict, Any, Optional
from pathlib import Path


class Sandbox:
    """
    Windows sandbox for dynamic analysis.

    Provides:
    - Isolated temporary directory
    - Minimal environment variables
    - Resource tracking
    - Cleanup on exit

    Note: Network blocking is implemented via Frida hooks (see frida_scripter.py)
    since Windows firewall rules require admin privileges.

    Usage:
        sandbox = Sandbox(timeout=500, memory_limit=512)
        sandbox.setup()
        try:
            # Run analysis with sandbox.temp_dir and sandbox.env
            pass
        finally:
            sandbox.cleanup()
    """

    def __init__(self, timeout: int = 500, memory_limit: int = 512):
        """
        Initialize sandbox configuration.

        Args:
            timeout: Wall-clock timeout in seconds
            memory_limit: Memory limit in MB (monitoring only, not enforced)
        """
        self.timeout = timeout
        self.memory_limit = memory_limit * 1024 * 1024  # Convert to bytes
        self.temp_dir: Optional[str] = None
        self.env: Optional[Dict[str, str]] = None
        self.start_time: Optional[float] = None

    def setup(self) -> str:
        """
        Create isolated sandbox environment.

        Returns:
            Path to temporary directory

        Raises:
            OSError: If sandbox setup fails
        """
        # Create temp folder with unique prefix
        self.temp_dir = tempfile.mkdtemp(prefix="frida_sandbox_", suffix=f"_{os.getpid()}")

        # Setup minimal environment variables
        # Only include essential Windows paths
        self.env = {
            'TEMP': self.temp_dir,
            'TMP': self.temp_dir,
            'TMPDIR': self.temp_dir,
            # Windows system paths
            'SystemRoot': os.environ.get('SystemRoot', r'C:\Windows'),
            'SystemDrive': os.environ.get('SystemDrive', 'C:'),
            'windir': os.environ.get('windir', r'C:\Windows'),
            # Minimal PATH (only system directories)
            'PATH': r'C:\Windows\System32;C:\Windows',
            # Prevent network stack initialization (may not be effective for all apps)
            'NO_PROXY': '*',
        }

        # Record start time
        self.start_time = time.time()

        return self.temp_dir

    def cleanup(self):
        """
        Remove temporary directory and cleanup resources.

        Always call this, even on error. Safe to call multiple times.
        """
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                # Use onerror to handle permission issues
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception as e:
                # Log but don't fail
                print(f"Warning: Failed to cleanup sandbox: {e}")
            finally:
                self.temp_dir = None

    def get_elapsed_time(self) -> float:
        """
        Get elapsed time since sandbox setup.

        Returns:
            Elapsed time in seconds
        """
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time

    def is_timeout_exceeded(self) -> bool:
        """
        Check if timeout has been exceeded.

        Returns:
            True if timeout exceeded
        """
        return self.get_elapsed_time() >= self.timeout

    def get_remaining_time(self) -> float:
        """
        Get remaining time before timeout.

        Returns:
            Remaining time in seconds (0 if exceeded)
        """
        remaining = self.timeout - self.get_elapsed_time()
        return max(0.0, remaining)

    def get_spawn_options(self, binary_path: str, args: list = None) -> Dict[str, Any]:
        """
        Get Frida spawn options for sandboxed execution.

        Args:
            binary_path: Path to binary to execute
            args: Command-line arguments

        Returns:
            Dictionary of spawn options for frida.spawn()
        """
        spawn_args = [binary_path]
        if args:
            spawn_args.extend(args)

        return {
            'argv': spawn_args,
            'env': self.env,
            'cwd': self.temp_dir,
            'stdio': 'pipe',  # Capture stdout/stderr
        }

    def get_network_blocking_script(self) -> str:
        """
        Get Frida JavaScript to block network operations.

        Returns network blocking script as string.

        Note: This hooks Windows socket APIs to prevent network access.
        More effective than environment variables.
        """
        return """
// Network blocking via Frida hooks
// Hooks Windows socket APIs (ws2_32.dll) to block network access

console.log("[Sandbox] Installing network blocking hooks...");

var networkBlocked = 0;

// Socket creation APIs
var socketApis = [
    "socket",
    "WSASocketA",
    "WSASocketW"
];

socketApis.forEach(function(apiName) {
    try {
        var addr = Module.findExportByName("ws2_32.dll", apiName);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    networkBlocked++;
                    send({
                        type: "network_blocked",
                        api: apiName,
                        count: networkBlocked
                    });
                },
                onLeave: function(retval) {
                    // Return INVALID_SOCKET (-1)
                    retval.replace(ptr("-1"));
                }
            });
            console.log("[Sandbox] Hooked: " + apiName);
        }
    } catch(e) {
        console.log("[Sandbox] Failed to hook " + apiName + ": " + e);
    }
});

// Connection APIs
var connectApis = ["connect", "WSAConnect"];

connectApis.forEach(function(apiName) {
    try {
        var addr = Module.findExportByName("ws2_32.dll", apiName);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    networkBlocked++;
                    send({
                        type: "network_blocked",
                        api: apiName,
                        count: networkBlocked
                    });
                },
                onLeave: function(retval) {
                    // Return SOCKET_ERROR (-1)
                    retval.replace(ptr("-1"));
                }
            });
            console.log("[Sandbox] Hooked: " + apiName);
        }
    } catch(e) {
        console.log("[Sandbox] Failed to hook " + apiName + ": " + e);
    }
});

console.log("[Sandbox] Network blocking installed");
"""

    def __enter__(self):
        """Context manager entry."""
        self.setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - always cleanup."""
        self.cleanup()
        return False  # Don't suppress exceptions

    def __del__(self):
        """Destructor - ensure cleanup."""
        self.cleanup()


def create_sandbox(timeout: int = 500, memory_limit: int = 512) -> Sandbox:
    """
    Convenience function to create and setup sandbox.

    Args:
        timeout: Wall-clock timeout in seconds
        memory_limit: Memory limit in MB

    Returns:
        Configured Sandbox instance
    """
    sandbox = Sandbox(timeout=timeout, memory_limit=memory_limit)
    sandbox.setup()
    return sandbox


def get_sandbox_info(sandbox: Sandbox) -> Dict[str, Any]:
    """
    Get sandbox information for logging/debugging.

    Args:
        sandbox: Sandbox instance

    Returns:
        Dictionary with sandbox info
    """
    return {
        'temp_dir': sandbox.temp_dir,
        'timeout': sandbox.timeout,
        'memory_limit_mb': sandbox.memory_limit // (1024 * 1024),
        'elapsed_time': sandbox.get_elapsed_time(),
        'remaining_time': sandbox.get_remaining_time(),
        'timeout_exceeded': sandbox.is_timeout_exceeded()
    }
