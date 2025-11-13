"""
Frida harness for dynamic instrumentation.

Manages Frida lifecycle: spawn/attach, script loading, message handling,
timeout management, and graceful cleanup.
"""

import time
import threading
import os
import sys
import platform
import traceback
from typing import List, Dict, Any, Optional, Callable
from .sandbox import Sandbox
from .input_feeder import InputConfig


class FridaHarnessError(Exception):
    """Raised when Frida harness encounters an error."""
    pass


class TraceCollection:
    """
    Collection of trace events captured during instrumentation.

    Thread-safe collection that accumulates events from Frida scripts.
    """

    def __init__(self):
        """Initialize empty trace collection."""
        self.events: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self._lock = threading.Lock()
        self._incomplete = False
        self._incomplete_reason: Optional[str] = None

    def add_event(self, event: Dict[str, Any]):
        """
        Add an event to the collection (thread-safe).

        Args:
            event: Event dictionary from Frida script
        """
        with self._lock:
            self.events.append(event)

    def add_error(self, error: str):
        """
        Add an error message (thread-safe).

        Args:
            error: Error message
        """
        with self._lock:
            self.errors.append(error)

    def mark_incomplete(self, reason: str):
        """
        Mark collection as incomplete.

        Args:
            reason: Reason for incomplete collection
        """
        with self._lock:
            self._incomplete = True
            self._incomplete_reason = reason

    def is_incomplete(self) -> bool:
        """Check if collection is incomplete."""
        with self._lock:
            return self._incomplete

    def get_incomplete_reason(self) -> Optional[str]:
        """Get reason for incomplete collection."""
        with self._lock:
            return self._incomplete_reason

    def get_event_count(self) -> int:
        """Get number of events collected."""
        with self._lock:
            return len(self.events)

    def get_events(self) -> List[Dict[str, Any]]:
        """Get all events (creates a copy)."""
        with self._lock:
            return self.events.copy()

    def get_errors(self) -> List[str]:
        """Get all errors (creates a copy)."""
        with self._lock:
            return self.errors.copy()


class FridaHarness:
    """
    Frida harness for managing instrumentation lifecycle.

    Supports both spawn and attach modes with timeout handling
    and graceful cleanup.

    Usage:
        harness = FridaHarness(
            mode='spawn',
            timeout=500,
            on_message=lambda msg: print(msg)
        )

        traces = harness.run(
            target='/path/to/binary',
            scripts=['console.log("hooked");'],
            sandbox=sandbox_instance
        )
    """

    def __init__(
        self,
        mode: str = 'spawn',
        timeout: int = 500,
        attach_pid: Optional[int] = None,
        on_message: Optional[Callable] = None
    ):
        """
        Initialize Frida harness.

        Args:
            mode: 'spawn' or 'attach'
            timeout: Timeout in seconds
            attach_pid: Process ID for attach mode
            on_message: Optional callback for messages
        """
        self.mode = mode
        self.timeout = timeout
        self.attach_pid = attach_pid
        self.on_message_callback = on_message

        self.session = None
        self.scripts = []
        self.traces = TraceCollection()
        self._timeout_timer: Optional[threading.Timer] = None
        self._frida = None

    def _import_frida(self):
        """Import Frida (lazy import)."""
        if self._frida is None:
            try:
                import frida
                self._frida = frida
            except ImportError:
                raise FridaHarnessError("Frida not installed. Install with: pip install frida-tools")
        return self._frida

    def run(
        self,
        target: str,
        scripts: List[str],
        sandbox: Sandbox,
        input_config: InputConfig = None
    ) -> TraceCollection:
        """
        Run Frida instrumentation.

        Args:
            target: Binary path (spawn) or process name (attach)
            scripts: List of JavaScript code strings
            sandbox: Sandbox instance
            input_config: Optional input configuration

        Returns:
            TraceCollection with captured events

        Raises:
            FridaHarnessError: If instrumentation fails
        """
        # DEBUG: Log system information and prerequisites
        self._log_debug_info(target, scripts)

        frida = self._import_frida()

        try:
            if self.mode == 'spawn':
                return self._run_spawn_mode(target, scripts, sandbox, input_config)
            elif self.mode == 'attach':
                return self._run_attach_mode(scripts, sandbox)
            else:
                raise FridaHarnessError(f"Invalid mode: {self.mode}")

        except Exception as e:
            # DEBUG: Capture detailed error information
            self._log_exception_details(e)
            self.traces.add_error(f"Harness error: {e}")
            self.traces.mark_incomplete("error")
            raise FridaHarnessError(f"Instrumentation failed: {e}")

        finally:
            self._cleanup()

    def _run_spawn_mode(
        self,
        binary_path: str,
        scripts: List[str],
        sandbox: Sandbox,
        input_config: InputConfig
    ) -> TraceCollection:
        """
        Run in spawn mode (launch binary with Frida).

        Args:
            binary_path: Path to binary
            scripts: List of JS scripts
            sandbox: Sandbox instance
            input_config: Input configuration

        Returns:
            TraceCollection
        """
        frida = self._frida

        # Build spawn arguments
        from .input_feeder import build_spawn_args
        spawn_args = build_spawn_args(binary_path, input_config) if input_config else [binary_path]

        # Spawn options from sandbox
        spawn_options = sandbox.get_spawn_options(binary_path, spawn_args[1:] if len(spawn_args) > 1 else [])

        try:
            # DEBUG: Validate binary before spawn
            self._validate_binary_path(binary_path)

            # Spawn process (suspended)
            # Frida spawn() signature: spawn(program, args=[], **options)
            # Extract program from argv and pass separately
            program = spawn_options.pop('argv')[0] if 'argv' in spawn_options else binary_path
            argv = spawn_options.pop('argv', [])

            print(f"[Harness] Spawning: {' '.join([program] + argv)}")
            print(f"[Harness] Spawn options: {spawn_options}")

            # DEBUG: Log before spawn attempt
            print(f"[Harness] DEBUG: Attempting spawn...")
            pid = frida.spawn(program, argv=argv, **spawn_options)
            print(f"[Harness] Spawned PID: {pid}")
            print(f"[Harness] DEBUG: Spawn successful")

            # Attach to spawned process
            print(f"[Harness] DEBUG: Attempting attach to PID {pid}...")
            self.session = frida.attach(pid)
            print(f"[Harness] Attached to PID: {pid}")
            print(f"[Harness] DEBUG: Attach successful")

            # Load scripts
            print(f"[Harness] DEBUG: Loading {len(scripts)} scripts...")
            self._load_scripts(scripts)
            print(f"[Harness] DEBUG: All scripts loaded")

            # Start timeout timer
            self._start_timeout_timer(pid)

            # Resume process
            print(f"[Harness] DEBUG: Resuming PID {pid}...")
            frida.resume(pid)
            print(f"[Harness] Resumed PID: {pid}")
            print(f"[Harness] DEBUG: Process resumed, waiting for execution...")

            # Wait for completion or timeout
            remaining_time = sandbox.get_remaining_time()
            if remaining_time > 0:
                print(f"[Harness] DEBUG: Waiting up to {remaining_time}s for execution...")
                time.sleep(min(remaining_time, self.timeout))

            # Check if timeout occurred
            if sandbox.is_timeout_exceeded():
                print(f"[Harness] Timeout exceeded ({self.timeout}s)")
                self.traces.mark_incomplete("timeout")
            else:
                print(f"[Harness] DEBUG: Execution completed normally")

        except Exception as e:
            # DEBUG: Enhanced error logging
            print(f"[Harness] Spawn mode error: {e}")
            print(f"[Harness] ERROR TYPE: {type(e).__name__}")
            print(f"[Harness] TRACEBACK:\n{traceback.format_exc()}")

            self.traces.add_error(f"Spawn mode error ({type(e).__name__}): {e}")
            self.traces.mark_incomplete("error")

        return self.traces

    def _run_attach_mode(
        self,
        scripts: List[str],
        sandbox: Sandbox
    ) -> TraceCollection:
        """
        Run in attach mode (hook running process).

        Args:
            scripts: List of JS scripts
            sandbox: Sandbox instance

        Returns:
            TraceCollection
        """
        frida = self._frida

        if self.attach_pid is None:
            raise FridaHarnessError("attach_pid required for attach mode")

        try:
            # Attach to process
            print(f"[Harness] Attaching to PID: {self.attach_pid}")
            self.session = frida.attach(self.attach_pid)
            print(f"[Harness] Attached successfully")

            # Load scripts
            self._load_scripts(scripts)

            # Start timeout timer (for attach mode, just monitors)
            self._start_timeout_timer(self.attach_pid)

            # Wait for timeout
            remaining_time = sandbox.get_remaining_time()
            if remaining_time > 0:
                time.sleep(min(remaining_time, self.timeout))

            # Check if timeout occurred
            if sandbox.is_timeout_exceeded():
                print(f"[Harness] Monitoring timeout ({self.timeout}s)")
                self.traces.mark_incomplete("timeout")

        except Exception as e:
            print(f"[Harness] Attach mode error: {e}")
            self.traces.add_error(f"Attach mode error: {e}")
            self.traces.mark_incomplete("error")

        return self.traces

    def _load_scripts(self, scripts: List[str]):
        """
        Load Frida scripts into session.

        Args:
            scripts: List of JavaScript code strings
        """
        for i, script_code in enumerate(scripts):
            try:
                print(f"[Harness] Loading script {i+1}/{len(scripts)}")
                script = self.session.create_script(script_code)
                script.on('message', self._on_message)
                script.load()
                self.scripts.append(script)
                print(f"[Harness] Script {i+1} loaded")
            except Exception as e:
                error_msg = f"Failed to load script {i+1}: {e}"
                print(f"[Harness] {error_msg}")
                self.traces.add_error(error_msg)

    def _on_message(self, message: Dict[str, Any], data: Any):
        """
        Handle messages from Frida scripts.

        Args:
            message: Message dictionary from Frida
            data: Optional binary data
        """
        msg_type = message.get('type')

        if msg_type == 'send':
            # Trace event from script
            payload = message.get('payload', {})
            self.traces.add_event(payload)

            # Call user callback if provided
            if self.on_message_callback:
                try:
                    self.on_message_callback(payload)
                except Exception as e:
                    print(f"[Harness] Callback error: {e}")

        elif msg_type == 'error':
            # Script error
            error_msg = message.get('description', 'Unknown error')
            print(f"[Harness] Script error: {error_msg}")
            self.traces.add_error(error_msg)

        else:
            # Unknown message type
            print(f"[Harness] Unknown message type: {msg_type}")

    def _start_timeout_timer(self, pid: int):
        """
        Start timeout timer.

        Args:
            pid: Process ID to kill on timeout
        """
        def on_timeout():
            print(f"[Harness] Timeout reached, terminating PID {pid}")
            try:
                # Try to kill process
                import os
                import signal
                os.kill(pid, signal.SIGTERM)
            except Exception as e:
                print(f"[Harness] Failed to kill process: {e}")

            # Mark traces as incomplete
            self.traces.mark_incomplete("timeout")

        self._timeout_timer = threading.Timer(self.timeout, on_timeout)
        self._timeout_timer.daemon = True
        self._timeout_timer.start()

    def _log_debug_info(self, target: str, scripts: List[str]):
        """Log debug information at start of run."""
        print("\n" + "=" * 80)
        print("[DEBUG] FRIDA HARNESS DEBUG MODE - START")
        print("=" * 80)
        print(f"[DEBUG] Python: {sys.version}")
        print(f"[DEBUG] Platform: {platform.system()} {platform.release()}")
        print(f"[DEBUG] Architecture: {platform.architecture()}")
        print(f"[DEBUG] Mode: {self.mode}")
        print(f"[DEBUG] Timeout: {self.timeout}s")
        print(f"[DEBUG] Target: {target}")
        print(f"[DEBUG] Target exists: {os.path.exists(target)}")
        if os.path.exists(target):
            print(f"[DEBUG] Target is_file: {os.path.isfile(target)}")
            print(f"[DEBUG] Target size: {os.path.getsize(target)} bytes")
            print(f"[DEBUG] Target permissions: {oct(os.stat(target).st_mode)}")
        print(f"[DEBUG] Scripts count: {len(scripts)}")
        print("=" * 80 + "\n")

    def _validate_binary_path(self, binary_path: str):
        """Validate binary path before spawn attempt."""
        print(f"[Harness] DEBUG: Validating binary path...")

        if not binary_path:
            raise FridaHarnessError("Binary path is empty")

        # Check if file exists
        if not os.path.exists(binary_path):
            raise FridaHarnessError(f"Binary not found: {binary_path}")

        # Check if it's a file
        if not os.path.isfile(binary_path):
            raise FridaHarnessError(f"Path is not a file: {binary_path}")

        # Check if it's readable
        if not os.access(binary_path, os.R_OK):
            raise FridaHarnessError(f"Binary is not readable: {binary_path}")

        # Check file size
        size = os.path.getsize(binary_path)
        if size == 0:
            raise FridaHarnessError(f"Binary is empty: {binary_path}")

        # Try to detect file type
        try:
            with open(binary_path, 'rb') as f:
                magic = f.read(4)
                if magic.startswith(b'MZ'):
                    print(f"[Harness] DEBUG: Detected PE executable (size: {size} bytes)")
                elif magic.startswith(b'\x7fELF'):
                    print(f"[Harness] DEBUG: Detected ELF executable (size: {size} bytes)")
                else:
                    print(f"[Harness] DEBUG: Unknown binary format (magic: {magic.hex()}, size: {size} bytes)")
        except Exception as e:
            print(f"[Harness] DEBUG: Could not read binary header: {e}")

        print(f"[Harness] DEBUG: Binary validation passed")

    def _log_exception_details(self, exc: Exception):
        """Log detailed exception information."""
        print("\n" + "=" * 80)
        print("[DEBUG] EXCEPTION DETAILS")
        print("=" * 80)
        print(f"Exception Type: {type(exc).__name__}")
        print(f"Exception Message: {exc}")
        print(f"Exception Args: {exc.args}")
        print("Full Traceback:")
        print(traceback.format_exc())
        print("=" * 80 + "\n")

    def _cleanup(self):
        """Cleanup Frida session and scripts."""
        # Cancel timeout timer
        if self._timeout_timer:
            self._timeout_timer.cancel()
            self._timeout_timer = None

        # Unload scripts
        for script in self.scripts:
            try:
                script.unload()
            except Exception:
                pass
        self.scripts.clear()

        # Detach session
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None

        print(f"[Harness] Cleanup complete")


def run_spawn_mode(
    binary_path: str,
    scripts: List[str],
    sandbox: Sandbox,
    input_config: InputConfig = None,
    timeout: int = 500,
    on_message: Optional[Callable] = None
) -> TraceCollection:
    """
    Convenience function to run spawn mode.

    Args:
        binary_path: Path to binary
        scripts: List of JS scripts
        sandbox: Sandbox instance
        input_config: Input configuration
        timeout: Timeout in seconds
        on_message: Message callback

    Returns:
        TraceCollection
    """
    harness = FridaHarness(
        mode='spawn',
        timeout=timeout,
        on_message=on_message
    )

    return harness.run(binary_path, scripts, sandbox, input_config)


def run_attach_mode(
    pid: int,
    scripts: List[str],
    sandbox: Sandbox,
    timeout: int = 500,
    on_message: Optional[Callable] = None
) -> TraceCollection:
    """
    Convenience function to run attach mode.

    Args:
        pid: Process ID to attach
        scripts: List of JS scripts
        sandbox: Sandbox instance
        timeout: Timeout in seconds
        on_message: Message callback

    Returns:
        TraceCollection
    """
    harness = FridaHarness(
        mode='attach',
        timeout=timeout,
        attach_pid=pid,
        on_message=on_message
    )

    return harness.run(str(pid), scripts, sandbox)
