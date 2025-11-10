"""
Frida script generator - generates JavaScript hooks from hints.

Orchestrates instrumentation strategies and generates Frida scripts
based on static analysis hints and configuration.
"""

from typing import List, Dict, Any
from .config import Config


def generate_hooks(hints_data: Dict[str, Any], config: Config) -> List[str]:
    """
    Generate Frida JavaScript hooks from hints.

    This is the main entry point for script generation. It coordinates
    multiple instrumenters based on configuration.

    Args:
        hints_data: Hints from static analysis (from hints_adapter.load_hints)
        config: Configuration instance

    Returns:
        List of JavaScript code strings to load into Frida

    Example:
        hints = load_hints('/path/to/hints.json')
        config = Config.load()
        scripts = generate_hooks(hints, config)
        # scripts = ['...crypto hooks...', '...memory scan...', '...helpers...']
    """
    scripts = []

    # Always include helper functions (first, so other scripts can use them)
    scripts.append(generate_helper_functions())

    # Get enabled instrumenters
    instrumenters_config = config.get('instrumenters', default={})

    # 1. Crypto operations (priority - always enabled by default)
    if instrumenters_config.get('crypto_ops', True):
        from .instrumenters.crypto_ops import generate_crypto_hooks
        crypto_script = generate_crypto_hooks(hints_data, config)
        if crypto_script:
            scripts.append(crypto_script)

    # 2. Memory scan (optional, lightweight)
    if instrumenters_config.get('memory_scan', False):
        from .instrumenters.memory_scan import generate_memory_scan_script
        memory_script = generate_memory_scan_script(config)
        if memory_script:
            scripts.append(memory_script)

    # 3. Call graph (optional)
    if instrumenters_config.get('call_graph', False):
        from .instrumenters.call_graph import generate_call_graph_script
        call_graph_script = generate_call_graph_script(hints_data, config)
        if call_graph_script:
            scripts.append(call_graph_script)

    return scripts


def generate_helper_functions() -> str:
    """
    Generate JavaScript helper functions used by all instrumenters.

    Includes:
    - Buffer hashing (SHA256)
    - Entropy calculation
    - Safe memory reading
    - Timestamp utilities

    Returns:
        JavaScript code string
    """
    return """
// ============================================================================
// Helper Functions for Dynamic Analysis
// ============================================================================

console.log("[Helpers] Loading helper functions...");

// Global state
var _cryptoCallCount = 0;
var _maxCryptoCallsReached = false;
var MAX_CRYPTO_CALLS = 100;  // Configurable limit

// ============================================================================
// Buffer Hashing
// ============================================================================

/**
 * Hash a buffer using SHA256 (simplified - uses first N bytes).
 * For production, should use proper crypto library.
 */
function hashBuffer(ptr, size) {
    if (ptr.isNull()) {
        return "null_pointer";
    }

    try {
        // Limit to max 256 bytes for performance
        var actualSize = Math.min(size, 256);
        var data = Memory.readByteArray(ptr, actualSize);

        // Simple hash: convert to hex string (fallback)
        // In production, use CryptoJS or native crypto
        var bytes = new Uint8Array(data);
        var hex = '';
        for (var i = 0; i < Math.min(bytes.length, 32); i++) {
            var b = bytes[i].toString(16);
            hex += b.length === 1 ? '0' + b : b;
        }
        return 'hash_' + hex + '...' + actualSize;

    } catch (e) {
        return "error_reading_memory";
    }
}

/**
 * Hash a pointer value (address).
 */
function hashPointer(ptr) {
    if (ptr.isNull()) {
        return "null_pointer";
    }
    return ptr.toString();
}

// ============================================================================
// Entropy Calculation
// ============================================================================

/**
 * Calculate Shannon entropy of a buffer.
 * Returns value between 0 (no entropy) and 8 (maximum entropy).
 */
function calculateEntropy(buffer) {
    if (!buffer || buffer.byteLength === 0) {
        return 0.0;
    }

    try {
        var bytes = new Uint8Array(buffer);
        var freq = {};

        // Count byte frequencies
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i];
            freq[b] = (freq[b] || 0) + 1;
        }

        // Calculate entropy
        var entropy = 0.0;
        var len = bytes.length;

        for (var byte in freq) {
            var p = freq[byte] / len;
            entropy -= p * Math.log2(p);
        }

        return entropy;

    } catch (e) {
        return 0.0;
    }
}

// ============================================================================
// Safe Memory Reading
// ============================================================================

/**
 * Safely read memory with error handling.
 */
function safeReadMemory(ptr, size) {
    try {
        if (ptr.isNull() || size <= 0) {
            return null;
        }
        return Memory.readByteArray(ptr, Math.min(size, 4096));
    } catch (e) {
        return null;
    }
}

/**
 * Safely read a UTF-8 string.
 */
function safeReadUtf8String(ptr, maxLen) {
    try {
        if (ptr.isNull()) {
            return null;
        }
        return Memory.readUtf8String(ptr, maxLen || 256);
    } catch (e) {
        return null;
    }
}

/**
 * Safely read a UTF-16 string (Windows).
 */
function safeReadUtf16String(ptr, maxLen) {
    try {
        if (ptr.isNull()) {
            return null;
        }
        return Memory.readUtf16String(ptr, maxLen || 256);
    } catch (e) {
        return null;
    }
}

// ============================================================================
// Timestamp Utilities
// ============================================================================

/**
 * Get current timestamp in milliseconds.
 */
function getTimestamp() {
    return Date.now();
}

// ============================================================================
// Crypto Call Limiting
// ============================================================================

/**
 * Check if we should continue capturing crypto calls.
 */
function shouldCaptureCryptoCall() {
    if (_maxCryptoCallsReached) {
        return false;
    }

    _cryptoCallCount++;

    if (_cryptoCallCount >= MAX_CRYPTO_CALLS) {
        _maxCryptoCallsReached = true;
        send({
            type: "limit_reached",
            limit_type: "max_crypto_calls",
            count: _cryptoCallCount
        });
        console.log("[Helpers] Max crypto calls limit reached: " + MAX_CRYPTO_CALLS);
        return false;
    }

    return true;
}

/**
 * Get current crypto call count.
 */
function getCryptoCallCount() {
    return _cryptoCallCount;
}

// ============================================================================
// Debug Utilities
// ============================================================================

/**
 * Get call backtrace (limited depth).
 */
function getBacktrace(maxDepth) {
    try {
        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        var result = [];
        var depth = Math.min(bt.length, maxDepth || 5);

        for (var i = 0; i < depth; i++) {
            var symbol = DebugSymbol.fromAddress(bt[i]);
            result.push(symbol.toString());
        }

        return result;
    } catch (e) {
        return ["backtrace_error"];
    }
}

/**
 * Safe JSON stringify with error handling.
 */
function safeStringify(obj) {
    try {
        return JSON.stringify(obj);
    } catch (e) {
        return String(obj);
    }
}

// ============================================================================
// Module Resolution
// ============================================================================

/**
 * Find exported function in a module.
 */
function findExport(moduleName, functionName) {
    try {
        return Module.findExportByName(moduleName, functionName);
    } catch (e) {
        return null;
    }
}

/**
 * Check if a module is loaded.
 */
function isModuleLoaded(moduleName) {
    try {
        return Process.findModuleByName(moduleName) !== null;
    } catch (e) {
        return false;
    }
}

console.log("[Helpers] Helper functions loaded successfully");
"""


def get_network_blocking_script() -> str:
    """
    Get network blocking script.

    This is a specialized script from sandbox.py that blocks network operations.
    Included here for completeness.

    Returns:
        JavaScript code string
    """
    from .sandbox import Sandbox
    sandbox = Sandbox()
    return sandbox.get_network_blocking_script()


def format_script_with_metadata(script: str, name: str, version: str = "1.0") -> str:
    """
    Wrap script with metadata header.

    Args:
        script: JavaScript code
        name: Script name
        version: Script version

    Returns:
        Formatted script with header
    """
    header = f"""
// ============================================================================
// Dynamic Analysis Script: {name}
// Version: {version}
// Generated: {__import__('datetime').datetime.now().isoformat()}
// ============================================================================

"""
    return header + script
