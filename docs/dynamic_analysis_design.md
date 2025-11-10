# Dynamic Analysis Design Specification

**Version:** 1.0
**Date:** 2025-11-10
**Status:** Implementation in Progress

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [Component Design](#component-design)
5. [Data Structures](#data-structures)
6. [Workflow](#workflow)
7. [Security & Sandboxing](#security--sandboxing)
8. [Storage Layout](#storage-layout)
9. [Error Handling](#error-handling)
10. [Testing Strategy](#testing-strategy)

---

## Overview

### Purpose
Implement Frida-based dynamic analysis to detect cryptographic operations at runtime by instrumenting Windows PE binaries and crypto libraries.

### Scope
- **Platform:** Windows only
- **Target Binaries:** PE executables, crypto libraries (bcrypt.dll, crypt32.dll)
- **Analysis Type:** Self-contained local binaries
- **Premium Feature:** Requires license validation

### Key Goals
1. Hook crypto API calls during execution
2. Capture sanitized traces (no raw keys/secrets)
3. Correlate with static analysis hints
4. Support both spawn and attach modes
5. Run in sandboxed environment

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    PREPROCESSING STAGE                       │
│               (Already implemented)                          │
│  Input → Intake → Archives → Hash → Preproc → Output       │
│  Produces: preproc/<file_hash>/                             │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    STATIC DETECTION                          │
│               (Already implemented)                          │
│  Load binary → Ghidra → Heuristics → Generate hints.json    │
│  Produces: analysis/static/<file_hash>/hints.json           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              DYNAMIC DETECTION (This Design)                 │
│                                                               │
│  1. License Check → Validate premium feature                │
│  2. Load Hints → Read hints.json from static stage          │
│  3. Check Cache → Validate .cache_meta.json                 │
│  4. Setup Sandbox → Isolated temp folder, no network        │
│  5. Configure Input → Load args/input from config           │
│  6. Generate Hooks → Create Frida scripts from hints        │
│  7. Instrument Binary:                                       │
│     a) Spawn mode: Launch binary with Frida                 │
│     b) Attach mode: Hook running process                    │
│  8. Collect Traces:                                          │
│     • Crypto API calls (bcrypt.dll, crypt32.dll)           │
│     • Memory scans (high-entropy buffers)                   │
│     • Call graph (crypto call relationships)                │
│  9. Sanitize → Hash all buffers (sha256), redact secrets   │
│  10. Package Results → dynamic_results.json + trace.ndjson  │
│  11. Update Cache → Write .cache_meta.json                  │
│                                                               │
│  Produces:                                                   │
│    analysis/dynamic/<file_hash>/dynamic_results.json        │
│    analysis/dynamic/<file_hash>/trace.ndjson                │
│    analysis/dynamic/<file_hash>/.cache_meta.json            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    MERGE STAGE (Future)                      │
│  Correlate static + dynamic findings                        │
└─────────────────────────────────────────────────────────────┘
```

### Module Structure

```
dynamic_detection/
├── __init__.py              # Public API: DynamicRunner
├── runner.py                # Main orchestrator (follows StaticRunner pattern)
├── context.py               # DynamicContext, DynamicResult dataclasses
├── config.py                # Configuration management
├── cache.py                 # Cache validation (TTL, tool versions)
├── hints_adapter.py         # Load hints.json from static stage
├── validator.py             # Schema validation
│
├── frida_harness.py         # Frida lifecycle: spawn/attach/detach
├── frida_scripter.py        # Generate JavaScript hooks from hints
├── sandbox.py               # Windows sandbox: temp folder, no network
├── input_feeder.py          # Handle args/input_file from config
│
├── trace_manager.py         # Collect & limit traces (10k events, 10MB)
├── traces_sanitizer.py      # Hash buffers, redact secrets
├── results_packager.py      # Package dynamic_results.json
│
├── instrumenters/           # Pluggable instrumentation strategies
│   ├── __init__.py
│   ├── crypto_ops.py        # Hook bcrypt.dll, crypt32.dll
│   ├── memory_scan.py       # High-entropy buffer detection
│   └── call_graph.py        # Collect call relationships
│
└── schemas/                 # JSON schemas
    ├── dynamic_results.schema.json
    ├── trace_event.schema.json
    └── dynamic_config.schema.json
```

---

## Requirements

### Functional Requirements

#### FR1: Execution Modes
- **FR1.1:** Support **spawn mode** - launch binary with Frida
- **FR1.2:** Support **attach mode** - hook into running process by PID
- **FR1.3:** Support optional JSON config per binary for `args` and `input_file`

#### FR2: Target Binary Support
- **FR2.1:** Analyze Windows PE files (`.exe`, `.dll`)
- **FR2.2:** Focus on crypto libraries: `bcrypt.dll`, `crypt32.dll`
- **FR2.3:** Handle self-contained local binaries (no network dependencies)

#### FR3: Instrumentation
- **FR3.1:** Hook Windows crypto APIs (CryptEncrypt, BCryptEncrypt, etc.)
- **FR3.2:** Optional memory scan for high-entropy buffers (keys)
- **FR3.3:** Build call graph from crypto function calls
- **FR3.4:** Capture **first 100 crypto calls only** (performance)

#### FR4: Trace Management
- **FR4.1:** Store traces as NDJSON: `analysis/dynamic/<hash>/trace.ndjson`
- **FR4.2:** Limit: **10,000 events OR 10 MB max**
- **FR4.3:** Summarize essential findings in `dynamic_results.json`
- **FR4.4:** Save partial traces on timeout/crash

#### FR5: Timeout & Error Handling
- **FR5.1:** Default timeout: **500 seconds** (configurable)
- **FR5.2:** Abort gracefully on timeout
- **FR5.3:** Mark incomplete runs: `"incomplete": true, "reason": "timeout"`
- **FR5.4:** Always save partial results

#### FR6: Input Feeding
- **FR6.1:** Support binaries needing command-line args
- **FR6.2:** Support binaries reading from input files
- **FR6.3:** Load config from optional `dynamic_config.json`

### Non-Functional Requirements

#### NFR1: Security & Sandboxing
- **NFR1.1:** Run in isolated temp folder
- **NFR1.2:** No network access (disable sockets/firewall block)
- **NFR1.3:** Limited memory (OS-level limits)
- **NFR1.4:** Read-only working directory
- **NFR1.5:** Hash all buffers (sha256) before storage
- **NFR1.6:** Never store raw keys or sensitive data

#### NFR2: Premium Feature Gating
- **NFR2.1:** Check license: `license.has_feature('dynamic')`
- **NFR2.2:** Show "Premium feature" message if not licensed
- **NFR2.3:** No profile-based tiers (quick/full) for now

#### NFR3: Platform Support
- **NFR3.1:** Windows only (Windows 10/11)
- **NFR3.2:** Frida must be installed (frida-tools)

#### NFR4: Performance
- **NFR4.1:** Limit traces to avoid memory exhaustion
- **NFR4.2:** Lightweight memory scans (no full dumps)
- **NFR4.3:** Capture only first N crypto calls

#### NFR5: Integration
- **NFR5.1:** Follow StaticRunner patterns (modular, testable)
- **NFR5.2:** Use dataclasses for context passing
- **NFR5.3:** Schema-first validation
- **NFR5.4:** Cache-aware (TTL, tool versions)

---

## Component Design

### 1. DynamicRunner (runner.py)

**Responsibility:** Main orchestrator for dynamic analysis runs.

**Pattern:** Pipeline orchestration (same as StaticRunner)

**Interface:**
```python
class DynamicRunner:
    def run(self, ctx: DynamicContext) -> DynamicResult:
        """
        Run Frida-based dynamic analysis.

        Args:
            ctx: Dynamic analysis context (file_hash, hints_path, mode, etc.)

        Returns:
            DynamicResult with paths, summary, errors (never throws)
        """
```

**Workflow:**
1. Validate license (`license.has_feature('dynamic')`)
2. Load hints from static stage (`hints_adapter`)
3. Check cache (`cache.should_use_cache()`)
4. Setup sandbox (`sandbox.create_sandbox()`)
5. Configure input (`input_feeder.prepare_input()`)
6. Generate hooks (`frida_scripter.generate_hooks()`)
7. Run harness (`frida_harness.run()`)
8. Collect traces (`trace_manager.collect()`)
9. Sanitize (`traces_sanitizer.sanitize()`)
10. Package results (`results_packager.package()`)
11. Update cache (`cache.write_meta()`)

**Error Handling:** Return `DynamicResult` with `errors` list (never throws)

---

### 2. Context & Result (context.py)

**Dataclasses for type-safe context passing:**

```python
@dataclass
class DynamicContext:
    """Context for dynamic analysis run."""
    file_hash: str                      # Binary identifier
    preproc_dir: str                    # Path to preproc/<hash>/
    hints_path: str                     # Path to hints.json
    analysis_base: str                  # Base analysis directory
    mode: str = "spawn"                 # 'spawn' | 'attach'
    attach_pid: Optional[int] = None    # PID for attach mode
    timeout: int = 500                  # Wall-clock timeout (seconds)
    memory_limit: int = 512             # Memory limit (MB)
    force: bool = False                 # Bypass cache
    config_path: Optional[str] = None   # Optional dynamic_config.json
    tool_versions: ToolVersions = field(default_factory=ToolVersions)

@dataclass
class DynamicResult:
    """Result from dynamic analysis."""
    file_hash: str
    dynamic_results_path: Optional[str]  # Path to dynamic_results.json
    trace_path: Optional[str]            # Path to trace.ndjson
    cached: bool
    incomplete: bool                     # True if timeout/crash
    incomplete_reason: Optional[str]     # "timeout" | "crash" | etc.
    summary: Dict[str, Any]              # High-level findings
    errors: Optional[List[str]]          # Error messages

@dataclass
class ToolVersions:
    frida: str = ""                      # Frida version
    python: str = ""                     # Python version
    detector_version: str = "dynamic-detect/0.1.0"
```

---

### 3. Frida Harness (frida_harness.py)

**Responsibility:** Manage Frida instrumentation lifecycle.

**Modes:**

**A. Spawn Mode** (Launch binary with Frida)
```python
def run_spawn_mode(
    target_path: str,
    scripts: List[str],
    sandbox: Sandbox,
    timeout: int,
    args: List[str] = None,
    input_file: str = None
) -> TraceCollection:
    """
    Spawn binary with Frida instrumentation.

    Workflow:
    1. Spawn process (not resumed yet)
    2. Attach session
    3. Load scripts
    4. Setup message handler
    5. Resume process
    6. Wait for completion or timeout
    7. Detach and cleanup

    Returns:
        TraceCollection with captured events
    """
```

**B. Attach Mode** (Hook running process)
```python
def run_attach_mode(
    pid: int,
    scripts: List[str],
    timeout: int
) -> TraceCollection:
    """
    Attach to running process and instrument.

    Workflow:
    1. Attach to PID
    2. Load scripts
    3. Setup message handler
    4. Wait for timeout
    5. Detach and cleanup

    Returns:
        TraceCollection with captured events
    """
```

**Message Handler:**
```python
def _on_message(self, message, data):
    """
    Handle messages from Frida scripts.

    Message types:
    - 'send': Trace event (add to collection)
    - 'error': Script error (log but don't fail)
    """
```

**Timeout Handling:**
- Use `threading.Timer` for wall-clock timeout
- On timeout: Detach gracefully, return partial traces
- Mark result as incomplete

---

### 4. Frida Script Generator (frida_scripter.py)

**Responsibility:** Generate JavaScript hooks from static hints.

**Interface:**
```python
def generate_hooks(hints: List[Dict], config: Dict) -> List[str]:
    """
    Generate Frida JavaScript hooks from hints.

    Args:
        hints: List of hints from static analysis
        config: Configuration (instrumenters to enable, limits, etc.)

    Returns:
        List of JavaScript code strings to load into Frida
    """
```

**Hook Types:**

**A. Crypto API Hooks** (from hints)
```javascript
// Hook bcrypt.dll!BCryptEncrypt
Interceptor.attach(Module.getExportByName("bcrypt.dll", "BCryptEncrypt"), {
    onEnter: function(args) {
        send({
            type: "crypto_call",
            hint_id: "crypto_1",
            function: "BCryptEncrypt",
            module: "bcrypt.dll",
            timestamp: Date.now(),
            args_hashes: {
                hKey: hashPointer(args[0]),
                pbInput: hashBuffer(args[1], args[2].toInt32())
            }
        });
    },
    onLeave: function(retval) {
        send({
            type: "crypto_return",
            function: "BCryptEncrypt",
            retval: retval.toInt32()
        });
    }
});
```

**B. Address-Based Hooks** (from hints with addresses)
```javascript
// Hook address 0x401000 from static hint
Interceptor.attach(ptr("0x401000"), {
    onEnter: function(args) {
        send({
            type: "hint_address",
            hint_id: "crypto_2",
            address: "0x401000",
            timestamp: Date.now(),
            backtrace: Thread.backtrace().map(DebugSymbol.fromAddress)
        });
    }
});
```

**C. Memory Scan** (optional, lightweight)
```javascript
// Scan for high-entropy buffers (potential keys)
function scanMemory() {
    Process.enumerateRanges('r--', {
        onMatch: function(range) {
            try {
                let buf = Memory.readByteArray(range.base, Math.min(range.size, 4096));
                let entropy = calculateEntropy(buf);
                if (entropy > 7.5) {  // High entropy threshold
                    send({
                        type: "memory_scan",
                        range: range.base + "-" + range.base.add(range.size),
                        entropy: entropy,
                        hash: sha256(buf)
                    });
                }
            } catch(e) {}
        },
        onComplete: function() {}
    });
}
```

**D. Call Graph Tracking**
```javascript
// Track calls to crypto functions
let callGraph = {};

Interceptor.attach(targetAddress, {
    onEnter: function(args) {
        let caller = Thread.backtrace()[1];  // Caller address
        let callee = this.context.pc;       // Current address

        if (!callGraph[caller]) {
            callGraph[caller] = [];
        }
        callGraph[caller].push(callee);

        send({
            type: "call_graph",
            caller: caller,
            callee: callee,
            timestamp: Date.now()
        });
    }
});
```

**Helper Functions:**
```javascript
function hashBuffer(ptr, size) {
    try {
        let buf = Memory.readByteArray(ptr, Math.min(size, 256));  // Limit to 256 bytes
        return sha256(buf);
    } catch(e) {
        return "error";
    }
}

function calculateEntropy(buffer) {
    let freq = {};
    for (let i = 0; i < buffer.length; i++) {
        freq[buffer[i]] = (freq[buffer[i]] || 0) + 1;
    }

    let entropy = 0;
    for (let byte in freq) {
        let p = freq[byte] / buffer.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
```

---

### 5. Sandbox (sandbox.py)

**Responsibility:** Enforce security constraints on Windows.

**Implementation:**
```python
class Sandbox:
    """Windows sandbox for dynamic analysis."""

    def __init__(self, timeout: int, memory_limit: int):
        self.timeout = timeout
        self.memory_limit = memory_limit * 1024 * 1024  # MB to bytes
        self.temp_dir = None
        self.env = None

    def setup(self) -> str:
        """
        Create isolated environment.

        Returns:
            Path to temp directory
        """
        # Create temp folder
        self.temp_dir = tempfile.mkdtemp(prefix="frida_sandbox_")

        # Setup environment variables
        self.env = {
            'TEMP': self.temp_dir,
            'TMP': self.temp_dir,
            'PATH': r'C:\Windows\System32',  # Minimal PATH
            'SystemRoot': r'C:\Windows'
        }

        return self.temp_dir

    def cleanup(self):
        """Remove temp directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def apply_limits(self):
        """
        Apply resource limits (Windows-specific).

        Note: Windows doesn't have direct equivalents to Unix rlimit.
        Use Frida's spawn options and process monitor.
        """
        # Memory limit: Monitor via Frida or Windows Job Objects
        # For MVP: Log warning if exceeded, don't enforce hard limit
        pass

    def disable_network(self):
        """
        Block network access (Windows firewall).

        Note: Requires admin privileges. For MVP: Document requirement.
        """
        # Option 1: Windows Firewall rule (requires admin)
        # Option 2: Process-level socket hooks via Frida
        # For MVP: Use Frida to intercept socket APIs
        pass
```

**Network Blocking via Frida:**
```javascript
// Block socket operations
["ws2_32.dll!socket", "ws2_32.dll!connect", "ws2_32.dll!send"].forEach(name => {
    let parts = name.split("!");
    Interceptor.attach(Module.getExportByName(parts[0], parts[1]), {
        onEnter: function(args) {
            send({type: "network_blocked", function: parts[1]});
            this.blocked = true;
        },
        onLeave: function(retval) {
            if (this.blocked) {
                retval.replace(-1);  // Return error
            }
        }
    });
});
```

---

### 6. Trace Manager (trace_manager.py)

**Responsibility:** Collect and limit trace events.

**Limits:**
- Max 10,000 events
- Max 10 MB file size
- Capture first 100 crypto calls only

**Implementation:**
```python
class TraceManager:
    """Manages trace collection with limits."""

    def __init__(self, max_events: int = 10000, max_size_mb: int = 10):
        self.max_events = max_events
        self.max_size = max_size_mb * 1024 * 1024
        self.events = []
        self.crypto_call_count = 0
        self.total_size = 0

    def add_event(self, event: Dict) -> bool:
        """
        Add event if limits not exceeded.

        Returns:
            True if added, False if limit reached
        """
        # Check event limit
        if len(self.events) >= self.max_events:
            return False

        # Check crypto call limit (first 100 only)
        if event.get('type') == 'crypto_call':
            self.crypto_call_count += 1
            if self.crypto_call_count > 100:
                return False  # Skip this crypto call

        # Estimate size
        event_size = len(json.dumps(event))
        if self.total_size + event_size > self.max_size:
            return False

        # Add event
        self.events.append(event)
        self.total_size += event_size
        return True

    def get_summary(self) -> Dict:
        """Get trace summary statistics."""
        return {
            'total_events': len(self.events),
            'crypto_calls': self.crypto_call_count,
            'size_bytes': self.total_size,
            'limits_reached': {
                'max_events': len(self.events) >= self.max_events,
                'max_crypto_calls': self.crypto_call_count >= 100,
                'max_size': self.total_size >= self.max_size
            }
        }

    def to_ndjson(self, output_path: str):
        """Write events as NDJSON (one JSON per line)."""
        with open(output_path, 'w') as f:
            for event in self.events:
                f.write(json.dumps(event) + '\n')
```

---

### 7. Trace Sanitizer (traces_sanitizer.py)

**Responsibility:** Hash buffers and redact sensitive data.

**Rules:**
1. Hash all buffer pointers (sha256)
2. Never store raw keys/secrets
3. Limit buffer samples to 256 bytes
4. Redact PII if present

**Implementation:**
```python
import hashlib

class TraceSanitizer:
    """Sanitizes traces to remove sensitive data."""

    @staticmethod
    def sanitize_event(event: Dict) -> Dict:
        """Sanitize a single trace event."""
        sanitized = event.copy()

        # Hash any 'buffer' or 'data' fields
        if 'buffer' in sanitized:
            sanitized['buffer_hash'] = TraceSanitizer._hash_bytes(sanitized['buffer'])
            del sanitized['buffer']

        if 'args_hashes' in sanitized:
            # Already hashed by Frida script, keep as-is
            pass

        # Redact any raw pointers (replace with "REDACTED")
        if 'raw_pointer' in sanitized:
            sanitized['raw_pointer'] = "REDACTED"

        return sanitized

    @staticmethod
    def sanitize_all(events: List[Dict]) -> List[Dict]:
        """Sanitize all events."""
        return [TraceSanitizer.sanitize_event(e) for e in events]

    @staticmethod
    def _hash_bytes(data: bytes) -> str:
        """SHA256 hash of bytes."""
        return hashlib.sha256(data).hexdigest()
```

---

### 8. Results Packager (results_packager.py)

**Responsibility:** Package `dynamic_results.json` with summary.

**Schema:**
```json
{
  "file_hash": "<sha256>",
  "schema_version": "1.0",
  "timestamp": "2025-11-10T12:00:00Z",
  "mode": "spawn",
  "incomplete": false,
  "incomplete_reason": null,
  "summary": {
    "total_crypto_calls": 42,
    "unique_functions": ["BCryptEncrypt", "CryptEncrypt"],
    "high_entropy_regions": 3,
    "call_graph_nodes": 15,
    "execution_time_seconds": 12.5
  },
  "findings": [
    {
      "id": "dynamic_1",
      "type": "crypto_call",
      "function": "BCryptEncrypt",
      "module": "bcrypt.dll",
      "count": 20,
      "confidence": 1.0,
      "evidence": "Hooked 20 calls to BCryptEncrypt"
    }
  ],
  "trace_summary": {
    "total_events": 156,
    "crypto_calls": 42,
    "memory_scans": 3,
    "call_graph_edges": 15,
    "size_bytes": 45123,
    "limits_reached": {
      "max_events": false,
      "max_crypto_calls": false,
      "max_size": false
    }
  },
  "meta": {
    "tool_versions": {
      "frida": "16.0.0",
      "python": "3.11.0",
      "detector_version": "dynamic-detect/0.1.0"
    },
    "config": {
      "timeout": 500,
      "memory_limit": 512
    }
  }
}
```

---

### 9. Cache (cache.py)

**Responsibility:** Validate cached results.

**Cache Metadata:**
```json
{
  "file_hash": "<sha256>",
  "timestamp": "2025-11-10T12:00:00Z",
  "ttl_hours": 24,
  "tool_versions": {
    "frida": "16.0.0",
    "python": "3.11.0",
    "detector_version": "dynamic-detect/0.1.0"
  },
  "config_hash": "<sha256 of DynamicContext>",
  "incomplete": false
}
```

**Validation Rules:**
1. Check TTL (default 24 hours)
2. Check tool versions match
3. Check config hash matches (mode, timeout, etc.)
4. If force=True, always bypass cache
5. Don't cache incomplete results (or use shorter TTL)

---

## Data Structures

### Hints (from Static Analysis)

**Input:** `analysis/static/<file_hash>/hints.json`

```json
{
  "file_hash": "abc123...",
  "hints": [
    {
      "id": "crypto_1",
      "type": "crypto_function",
      "name": "BCryptEncrypt",
      "module": "bcrypt.dll",
      "address_or_range": null,
      "confidence": 0.95,
      "reason_tags": ["signature_match", "bcrypt_api"]
    },
    {
      "id": "crypto_2",
      "type": "instruction_pattern",
      "address_or_range": "0x401000-0x401050",
      "confidence": 0.75,
      "reason_tags": ["aes_pattern", "sbox_access"]
    }
  ]
}
```

### Trace Events (NDJSON)

**Output:** `analysis/dynamic/<file_hash>/trace.ndjson`

Each line is a JSON object:
```json
{"type": "crypto_call", "hint_id": "crypto_1", "function": "BCryptEncrypt", "module": "bcrypt.dll", "timestamp": 1699610000, "args_hashes": {"hKey": "abc...", "pbInput": "def..."}}
{"type": "crypto_return", "function": "BCryptEncrypt", "retval": 0}
{"type": "memory_scan", "range": "0x1000-0x2000", "entropy": 7.8, "hash": "ghi..."}
{"type": "call_graph", "caller": "0x403000", "callee": "0x401000", "timestamp": 1699610001}
```

### Dynamic Config (Optional)

**Input:** `preproc/<file_hash>/dynamic_config.json`

```json
{
  "args": ["--verbose", "--config=config.ini"],
  "input_file": "test_input.dat",
  "timeout": 600,
  "instrumenters": {
    "crypto_ops": true,
    "memory_scan": true,
    "call_graph": false
  }
}
```

---

## Workflow

### End-to-End Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User clicks "Run Dynamic Analysis" in UI                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. UI creates DynamicContext:                               │
│    - file_hash from selected binary                         │
│    - hints_path from static stage                           │
│    - mode from UI (spawn/attach)                            │
│    - timeout from UI slider                                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. UI calls DynamicRunner.run(ctx) in background thread    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. DynamicRunner.run():                                     │
│    a. License check (license.has_feature('dynamic'))        │
│    b. Load hints (hints_adapter.load())                     │
│    c. Check cache (cache.should_use())                      │
│    d. Setup sandbox (sandbox.setup())                       │
│    e. Configure input (input_feeder.prepare())              │
│    f. Generate hooks (frida_scripter.generate())            │
│    g. Run harness (frida_harness.run())                     │
│    h. Collect traces (trace_manager.collect())              │
│    i. Sanitize (traces_sanitizer.sanitize())                │
│    j. Package results (results_packager.package())          │
│    k. Update cache (cache.write_meta())                     │
│    l. Cleanup sandbox (sandbox.cleanup())                   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. Return DynamicResult to UI                               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. UI displays results:                                     │
│    - Summary tab (crypto calls, findings)                   │
│    - Traces tab (NDJSON viewer)                            │
│    - Call Graph tab (visual graph)                         │
│    - Console tab (logs)                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Security & Sandboxing

### Threat Model

**Threats:**
1. Malicious binary executing arbitrary code
2. Network exfiltration of analysis data
3. File system access outside sandbox
4. Memory exhaustion (DoS)
5. Escape from Frida instrumentation

### Mitigations

#### 1. Sandboxed Execution
- **Temp Folder:** Create isolated temp directory
- **Environment:** Minimal PATH, no user directories
- **Cleanup:** Always cleanup temp folder (even on crash)

#### 2. Network Isolation
- **Frida Hooks:** Block socket APIs (ws2_32.dll)
- **Firewall (optional):** Windows Firewall rule (requires admin)
- **Detection:** Log any network attempts

#### 3. File System Protection
- **Read-Only:** Mount working directory as read-only (if supported)
- **Temp Only:** Binary can only write to temp folder
- **No Overwrite:** Never overwrite preproc/ or analysis/ directories

#### 4. Memory Limits
- **Monitor:** Track memory usage via Frida
- **Abort:** Kill process if exceeds limit
- **Logs:** Log memory exhaustion events

#### 5. Data Sanitization
- **Hash Buffers:** sha256() all captured data
- **No Raw Keys:** Never store raw crypto keys
- **Redact PII:** Remove any personal information

### Security Checklist

- [ ] Sandbox enforced before execution
- [ ] Network blocked (Frida hooks)
- [ ] Temp folder cleanup on exit
- [ ] Memory limits applied
- [ ] All buffers hashed
- [ ] No raw secrets stored
- [ ] Read-only working directory
- [ ] Timeout enforced
- [ ] Crash handling (no data leaks)

---

## Storage Layout

```
workdir/
├── preproc/<file_hash>/                # Immutable inputs (from preprocessing)
│   ├── input.bin
│   ├── metadata.json
│   └── dynamic_config.json             # (Optional) per-binary config
│
└── analysis/
    ├── static/<file_hash>/             # Static detection outputs
    │   ├── static_results.json
    │   ├── hints.json                  # Input for dynamic stage
    │   └── .cache_meta.json
    │
    └── dynamic/<file_hash>/            # Dynamic detection outputs
        ├── dynamic_results.json        # Summary & findings
        ├── trace.ndjson                # Full trace (NDJSON format)
        └── .cache_meta.json            # Cache metadata
```

### File Formats

**dynamic_results.json** (see schema above)
- Summary of findings
- Aggregated statistics
- Metadata (tool versions, config)

**trace.ndjson** (Newline-Delimited JSON)
- One JSON object per line
- Chronological event stream
- Types: crypto_call, crypto_return, memory_scan, call_graph

**.cache_meta.json**
- Timestamp, TTL
- Tool versions
- Config hash
- Incomplete flag

---

## Error Handling

### Error Categories

#### 1. License Errors
- **Error:** License check fails
- **Handling:** Return DynamicResult with error, show premium message in UI
- **Partial Results:** No

#### 2. Missing Hints
- **Error:** hints.json not found
- **Handling:** Return error, suggest running static detection first
- **Partial Results:** No

#### 3. Frida Not Installed
- **Error:** Frida not available
- **Handling:** Return error with installation instructions
- **Partial Results:** No

#### 4. Binary Not Found
- **Error:** input.bin missing
- **Handling:** Return error with path
- **Partial Results:** No

#### 5. Timeout
- **Error:** Execution exceeds timeout
- **Handling:** Detach Frida, save partial traces, mark incomplete
- **Partial Results:** Yes (incomplete=true)

#### 6. Crash
- **Error:** Binary crashes during execution
- **Handling:** Catch exception, save partial traces, mark incomplete
- **Partial Results:** Yes (incomplete=true, reason="crash")

#### 7. Memory Limit
- **Error:** Process exceeds memory limit
- **Handling:** Kill process, save partial traces, mark incomplete
- **Partial Results:** Yes (incomplete=true, reason="memory_limit")

#### 8. Script Error
- **Error:** Frida script throws exception
- **Handling:** Log error, continue with other scripts
- **Partial Results:** Yes (continue execution)

### Error Response Format

```python
DynamicResult(
    file_hash="abc123",
    dynamic_results_path=None,
    trace_path=None,
    cached=False,
    incomplete=True,
    incomplete_reason="timeout",
    summary={},
    errors=[
        "Execution timed out after 500 seconds",
        "Partial traces saved to analysis/dynamic/abc123/trace.ndjson"
    ]
)
```

---

## Testing Strategy

### Unit Tests

**test_context.py**
- Test DynamicContext/DynamicResult dataclasses
- Test serialization/deserialization

**test_hints_adapter.py**
- Test loading valid hints.json
- Test error handling (missing file, invalid JSON)

**test_frida_scripter.py**
- Test hook generation from hints
- Test different hint types (crypto_function, address, etc.)

**test_trace_manager.py**
- Test event limits (10k events, 10MB, 100 crypto calls)
- Test summary generation

**test_traces_sanitizer.py**
- Test buffer hashing
- Test redaction rules

**test_cache.py**
- Test cache validation (TTL, versions, config)
- Test cache bypass (force=True)

### Integration Tests

**test_dynamic_detection_workflow.py**
- Test full pipeline with mock Frida
- Test spawn mode with sample binary
- Test attach mode with running process
- Test timeout handling
- Test crash handling
- Test cache hit/miss

**test_frida_harness.py**
- Test Frida spawn (with real Frida)
- Test Frida attach (with real Frida)
- Test message handling
- Test detach on timeout

**test_sandbox.py**
- Test temp folder creation/cleanup
- Test network blocking (Frida hooks)
- Test memory limits (if implemented)

### End-to-End Tests

**test_e2e_crypto_detection.py**
- Test with real crypto binary (bcrypt.dll usage)
- Verify hints → hooks → traces → results
- Verify sanitization (no raw keys)
- Verify trace limits

**test_e2e_ui_integration.py**
- Test UI → DynamicRunner → Results
- Test batch processing
- Test progress updates
- Test error display

### Test Fixtures

**fixtures/sample_crypto_binary.exe**
- Small Windows binary using bcrypt.dll
- Calls BCryptEncrypt/BCryptDecrypt
- Self-contained (no network/files)
- Source code included for reference

**fixtures/hints_sample.json**
- Sample hints for test binary
- Covers different hint types

**fixtures/dynamic_config_sample.json**
- Sample config with args/input

---

## Appendix

### Frida Resources
- [Frida Documentation](https://frida.re/docs/home/)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [Windows API Hooking](https://frida.re/docs/examples/windows/)

### Windows Crypto APIs
- **bcrypt.dll:** Modern CNG (Cryptography Next Generation)
  - BCryptEncrypt, BCryptDecrypt, BCryptGenRandom, etc.
- **crypt32.dll:** Legacy CryptoAPI
  - CryptEncrypt, CryptDecrypt, CryptHashData, etc.

### Entropy Calculation
- **Formula:** H = -Σ(p(x) * log₂(p(x)))
- **High Entropy:** > 7.5 bits/byte (potential key material)
- **Low Entropy:** < 5.0 bits/byte (unlikely to be crypto)

### JSON Schema References
- [JSON Schema Specification](https://json-schema.org/)
- [NDJSON Format](http://ndjson.org/)

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-10 | Initial | Initial design specification |

---

**End of Document**
