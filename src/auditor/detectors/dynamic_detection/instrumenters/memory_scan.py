"""
Memory scan instrumenter (optional, lightweight).

Scans process memory for high-entropy buffers that could be key material.
Uses conservative approach to avoid performance impact.
"""

from typing import Dict, Any


def generate_memory_scan_script(config) -> str:
    """
    Generate JavaScript for memory scanning.

    Scans memory regions for high-entropy buffers that might be crypto keys.
    Uses conservative approach:
    - Only scan readable memory regions
    - Limit scan to 4KB per region
    - Use entropy threshold to filter
    - Hash potential key material (never store raw)

    Args:
        config: Configuration instance

    Returns:
        JavaScript code string
    """
    entropy_threshold = config.get('entropy_threshold', default=7.5)

    return f"""
// ============================================================================
// Memory Scanner (Optional, Lightweight)
// Scans for high-entropy memory regions (potential keys)
// ============================================================================

console.log("[MemoryScan] Installing memory scanner...");

var memoryScanStats = {{
    regionsScanned: 0,
    highEntropyFound: 0,
    totalSize: 0
}};

var ENTROPY_THRESHOLD = {entropy_threshold};  // bits/byte
var MAX_SCAN_SIZE = 4096;  // 4KB per region
var MAX_HIGH_ENTROPY_REPORTS = 10;  // Limit reports

/**
 * Scan a memory region for high entropy.
 */
function scanMemoryRegion(range) {{
    try {{
        memoryScanStats.regionsScanned++;

        // Limit scan size
        var scanSize = Math.min(range.size, MAX_SCAN_SIZE);
        var buffer = safeReadMemory(range.base, scanSize);

        if (!buffer) {{
            return;
        }}

        // Calculate entropy
        var entropy = calculateEntropy(buffer);

        // Check if high entropy
        if (entropy >= ENTROPY_THRESHOLD) {{
            memoryScanStats.highEntropyFound++;

            // Only report first N findings to avoid spam
            if (memoryScanStats.highEntropyFound <= MAX_HIGH_ENTROPY_REPORTS) {{
                send({{
                    type: "memory_scan",
                    range: range.base.toString() + "-" + range.base.add(scanSize).toString(),
                    size: scanSize,
                    entropy: entropy,
                    hash: hashBuffer(range.base, scanSize),
                    protection: range.protection,
                    timestamp: getTimestamp()
                }});
            }}
        }}

        memoryScanStats.totalSize += scanSize;

    }} catch (e) {{
        // Silently skip regions with errors
    }}
}}

/**
 * Perform initial memory scan.
 */
function performMemoryScan() {{
    console.log("[MemoryScan] Starting memory scan...");

    try {{
        // Scan readable memory regions only (r--, r-x, rw-)
        // Skip executable-only and write-only regions
        Process.enumerateRanges('r--', {{
            onMatch: function(range) {{
                scanMemoryRegion(range);
            }},
            onComplete: function() {{
                console.log("[MemoryScan] Scan complete:");
                console.log("[MemoryScan]   Regions scanned: " + memoryScanStats.regionsScanned);
                console.log("[MemoryScan]   High-entropy found: " + memoryScanStats.highEntropyFound);
                console.log("[MemoryScan]   Total size scanned: " + (memoryScanStats.totalSize / 1024).toFixed(2) + " KB");
            }}
        }});

    }} catch (e) {{
        console.log("[MemoryScan] Error during scan: " + e);
    }}
}}

// Perform scan after a delay (let process initialize)
setTimeout(function() {{
    performMemoryScan();
}}, 1000);  // 1 second delay

console.log("[MemoryScan] Memory scanner installed (will run after 1s delay)");
"""


def get_scan_configuration() -> Dict[str, Any]:
    """
    Get default memory scan configuration.

    Returns:
        Dictionary with scan parameters
    """
    return {
        'entropy_threshold': 7.5,  # bits/byte
        'max_scan_size': 4096,  # bytes per region
        'max_reports': 10,  # limit high-entropy reports
        'scan_delay': 1000,  # ms delay before scanning
        'protection_filter': 'r--',  # only readable regions
    }


def estimate_scan_performance(process_memory_mb: int) -> Dict[str, Any]:
    """
    Estimate memory scan performance.

    Args:
        process_memory_mb: Process memory size in MB

    Returns:
        Performance estimates
    """
    # Rough estimates based on scan parameters
    max_scan_size = 4096
    estimated_regions = (process_memory_mb * 1024 * 1024) // (64 * 1024)  # Assume 64KB avg region
    estimated_scan_time_ms = estimated_regions * 5  # 5ms per region (conservative)

    return {
        'estimated_regions': estimated_regions,
        'estimated_scan_time_ms': estimated_scan_time_ms,
        'estimated_scan_time_seconds': estimated_scan_time_ms / 1000,
        'max_memory_scanned_mb': (estimated_regions * max_scan_size) / (1024 * 1024),
        'impact': 'low' if estimated_scan_time_ms < 5000 else 'medium'
    }
