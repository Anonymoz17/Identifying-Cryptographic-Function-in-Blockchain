"""
Crypto operations instrumenter.

Generates Frida hooks for Windows crypto APIs (bcrypt.dll, crypt32.dll).
Captures crypto function calls with sanitized parameters.
"""

from typing import Dict, Any, List


def generate_crypto_hooks(hints_data: Dict[str, Any], config) -> str:
    """
    Generate JavaScript hooks for crypto operations.

    Hooks Windows crypto APIs based on:
    1. Static analysis hints (crypto_function type)
    2. Default crypto API lists from config
    3. Additional crypto libraries (OpenSSL, CNG, etc.)

    Args:
        hints_data: Hints from static analysis
        config: Configuration instance

    Returns:
        JavaScript code string
    """
    # Get crypto APIs from config
    bcrypt_apis = config.get('crypto_apis', 'bcrypt', default=[
        'BCryptEncrypt',
        'BCryptDecrypt',
        'BCryptGenRandom',
        'BCryptGenerateSymmetricKey',
        'BCryptDeriveKey',
        'BCryptHash',
        'BCryptHashData'
    ])

    crypt32_apis = config.get('crypto_apis', 'crypt32', default=[
        'CryptEncrypt',
        'CryptDecrypt',
        'CryptGenRandom',
        'CryptHashData',
        'CryptCreateHash',
        'CryptDeriveKey'
    ])

    # Get crypto function hints
    hints = hints_data.get('hints', [])
    crypto_hints = [h for h in hints if h.get('type') == 'crypto_function']

    # Build script
    script_parts = [
        _generate_script_header(),
        _generate_bcrypt_hooks(bcrypt_apis, crypto_hints),
        _generate_crypt32_hooks(crypt32_apis, crypto_hints),
        _generate_openssl_hooks(crypto_hints),
        _generate_ncrypt_hooks(crypto_hints),
        _generate_custom_hooks(crypto_hints),
        _generate_script_footer()
    ]

    return '\n\n'.join(script_parts)


def _generate_script_header() -> str:
    """Generate script header with local helper functions."""
    return """
// ============================================================================
// Crypto Operations Instrumenter
// Hooks Windows crypto APIs (bcrypt.dll, crypt32.dll)
// ============================================================================

console.log("[CryptoOps] Installing crypto API hooks...");

// ============================================================================
// Local Helper Functions
// Re-defined here to ensure availability in this script context
// ============================================================================

// Global state for crypto call limiting
var _cryptoCallCount = 0;
var _maxCryptoCallsReached = false;
var MAX_CRYPTO_CALLS = 100;  // Configurable limit

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
        console.log("[CryptoOps] Max crypto calls limit reached: " + MAX_CRYPTO_CALLS);
        return false;
    }

    return true;
}

/**
 * Get current timestamp in milliseconds.
 */
function getTimestamp() {
    return Date.now();
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

console.log("[CryptoOps] Helper functions loaded");

// ============================================================================
// Crypto Stats Tracking
// ============================================================================

var cryptoStats = {
    bcrypt: {},
    crypt32: {},
    custom: {}
};
"""


def _generate_bcrypt_hooks(api_names: List[str], hints: List[Dict]) -> str:
    """Generate hooks for bcrypt.dll APIs."""
    hooks = ["""
// ============================================================================
// BCrypt (Cryptography Next Generation) Hooks
// ============================================================================

if (isModuleLoaded("bcrypt.dll")) {
    console.log("[CryptoOps] bcrypt.dll loaded, installing hooks...");
"""]

    for api_name in api_names:
        # Find matching hint
        hint = _find_hint_for_function(api_name, hints)
        hint_id = hint.get('id') if hint else None

        hooks.append(_generate_api_hook('bcrypt.dll', api_name, hint_id))

    hooks.append("""
    console.log("[CryptoOps] bcrypt.dll hooks installed");
} else {
    console.log("[CryptoOps] bcrypt.dll not loaded");
}
""")

    return '\n'.join(hooks)


def _generate_crypt32_hooks(api_names: List[str], hints: List[Dict]) -> str:
    """Generate hooks for crypt32.dll APIs."""
    hooks = ["""
// ============================================================================
// Crypt32 (Legacy CryptoAPI) Hooks
// ============================================================================

if (isModuleLoaded("crypt32.dll")) {
    console.log("[CryptoOps] crypt32.dll loaded, installing hooks...");
"""]

    for api_name in api_names:
        # Find matching hint
        hint = _find_hint_for_function(api_name, hints)
        hint_id = hint.get('id') if hint else None

        hooks.append(_generate_api_hook('crypt32.dll', api_name, hint_id))

    hooks.append("""
    console.log("[CryptoOps] crypt32.dll hooks installed");
} else {
    console.log("[CryptoOps] crypt32.dll not loaded");
}
""")

    return '\n'.join(hooks)


def _generate_openssl_hooks(hints: List[Dict]) -> str:
    """Generate hooks for OpenSSL crypto library."""
    openssl_apis = [
        'EVP_EncryptInit',
        'EVP_EncryptUpdate',
        'EVP_EncryptFinal',
        'EVP_DecryptInit',
        'EVP_DecryptUpdate',
        'EVP_DecryptFinal',
        'EVP_DigestInit',
        'EVP_DigestUpdate',
        'EVP_DigestFinal',
        'EVP_PKEY_encrypt',
        'EVP_PKEY_decrypt',
        'EVP_PKEY_sign',
        'EVP_PKEY_verify',
        'HMAC_Init',
        'HMAC_Update',
        'HMAC_Final',
        'RAND_bytes',
        'BN_bin2bn',
        'EC_KEY_generate_key'
    ]

    hooks = ["""
// ============================================================================
// OpenSSL (libcrypto) Hooks
// Covers OpenSSL 1.1.x and 3.x variants
// ============================================================================

// Try common OpenSSL library names
var openssl_libs = ["libcrypto.dll", "libcrypto-1_1.dll", "libcrypto-3.dll", "libcrypto-3-x64.dll"];

for (var lib_idx = 0; lib_idx < openssl_libs.length; lib_idx++) {
    var lib_name = openssl_libs[lib_idx];
    if (isModuleLoaded(lib_name)) {
        console.log("[CryptoOps] " + lib_name + " loaded, installing hooks...");
"""]

    # Generate hooks for each OpenSSL API
    for api_name in openssl_apis:
        hint = _find_hint_for_function(api_name, hints)
        hint_id = hint.get('id') if hint else None

        # Generate hook with dynamic library name
        hook_code = f"""
    // Hook: libcrypto!{api_name}
    try {{
        var addr_{api_name}_openssl = Module.findExportByName(lib_name, "{api_name}");
        if (addr_{api_name}_openssl) {{
            Interceptor.attach(addr_{api_name}_openssl, {{
                onEnter: function(args) {{
                    if (!shouldCaptureCryptoCall()) {{
                        return;
                    }}

                    this.enterTime = getTimestamp();
                    send({{
                        type: "crypto_call",
                        hint_id: {f'"{hint_id}"' if hint_id else 'null'},
                        function: "{api_name}",
                        module: lib_name,
                        address: addr_{api_name}_openssl.toString(),
                        timestamp: this.enterTime,
                        args_count: args.length
                    }});
                }},
                onLeave: function(retval) {{
                    if (this.enterTime) {{
                        send({{
                            type: "crypto_return",
                            function: "{api_name}",
                            module: lib_name,
                            timestamp: getTimestamp()
                        }});
                    }}
                }}
            }});
            console.log("[CryptoOps]   Hooked: " + lib_name + "!{api_name}");
        }}
    }} catch (e) {{
        // Silently skip if export not found
    }}
"""
        hooks.append(hook_code)

    hooks.append("""
        console.log("[CryptoOps] " + lib_name + " hooks installed");
        break;  // Use first available OpenSSL library
    }
}
""")

    return '\n'.join(hooks)


def _generate_ncrypt_hooks(hints: List[Dict]) -> str:
    """Generate hooks for Windows CNG (Cryptography Next Generation) APIs."""
    ncrypt_apis = [
        'NCryptEncrypt',
        'NCryptDecrypt',
        'NCryptSignHash',
        'NCryptVerifySignature',
        'NCryptSecretAgreement',
        'NCryptDeriveKey',
        'NCryptGenerateKey',
        'NCryptCreatePersistedKey',
        'NCryptOpenKey',
        'NCryptDeleteKey',
        'NCryptImportKey',
        'NCryptExportKey'
    ]

    hooks = ["""
// ============================================================================
// NCrypt (CNG - Cryptography Next Generation) Hooks
// ============================================================================

if (isModuleLoaded("ncrypt.dll")) {
    console.log("[CryptoOps] ncrypt.dll loaded, installing hooks...");
"""]

    for api_name in ncrypt_apis:
        hint = _find_hint_for_function(api_name, hints)
        hint_id = hint.get('id') if hint else None
        hooks.append(_generate_api_hook('ncrypt.dll', api_name, hint_id))

    hooks.append("""
    console.log("[CryptoOps] ncrypt.dll hooks installed");
} else {
    console.log("[CryptoOps] ncrypt.dll not loaded");
}
""")

    return '\n'.join(hooks)


def _generate_custom_hooks(hints: List[Dict]) -> str:
    """Generate hooks for custom functions from hints."""
    custom_hooks = []

    # Find hints with specific addresses
    address_hints = [h for h in hints if h.get('address_or_range')]

    if not address_hints:
        return "// No custom address-based hooks"

    custom_hooks.append("""
// ============================================================================
// Custom Address-Based Hooks (from static analysis)
// ============================================================================

console.log("[CryptoOps] Installing custom address hooks...");
""")

    for hint in address_hints:
        address = hint.get('address_or_range')
        hint_id = hint.get('id')
        function_name = hint.get('name', 'unknown')

        # Parse address (might be range like "0x401000-0x401050")
        if '-' in str(address):
            # Range - hook start address only
            address = address.split('-')[0]

        custom_hooks.append(_generate_address_hook(address, hint_id, function_name))

    return '\n'.join(custom_hooks)


def _generate_api_hook(module: str, api_name: str, hint_id: str = None) -> str:
    """Generate hook for a single API function."""
    return f"""
    // Hook: {module}!{api_name}
    try {{
        var addr_{api_name} = findExport("{module}", "{api_name}");
        if (addr_{api_name}) {{
            Interceptor.attach(addr_{api_name}, {{
                onEnter: function(args) {{
                    if (!shouldCaptureCryptoCall()) {{
                        return;
                    }}

                    this.enterTime = getTimestamp();

                    // Increment stats
                    if (!cryptoStats.{module.split('.')[0]}["{api_name}"]) {{
                        cryptoStats.{module.split('.')[0]}["{api_name}"] = 0;
                    }}
                    cryptoStats.{module.split('.')[0]}["{api_name}"]++;

                    // Capture call details
                    var event = {{
                        type: "crypto_call",
                        hint_id: {f'"{hint_id}"' if hint_id else 'null'},
                        function: "{api_name}",
                        module: "{module}",
                        address: addr_{api_name}.toString(),
                        timestamp: this.enterTime,
                        args_count: args.length,
                        args_hashes: {{}}
                    }};

                    // Hash first few arguments (generic approach)
                    for (var i = 0; i < Math.min(args.length, 4); i++) {{
                        var argPtr = args[i];
                        if (!argPtr.isNull()) {{
                            // Assume args might be buffers or handles
                            event.args_hashes["arg" + i] = hashPointer(argPtr);
                        }}
                    }}

                    // Get backtrace (optional, for call graph)
                    // event.backtrace = getBacktrace(3);

                    send(event);
                }},
                onLeave: function(retval) {{
                    if (this.enterTime) {{
                        var exitTime = getTimestamp();
                        send({{
                            type: "crypto_return",
                            function: "{api_name}",
                            module: "{module}",
                            retval: retval.toInt32 ? retval.toInt32() : retval.toString(),
                            duration_ms: exitTime - this.enterTime,
                            timestamp: exitTime
                        }});
                    }}
                }}
            }});
            console.log("[CryptoOps]   Hooked: {api_name}");
        }}
    }} catch (e) {{
        console.log("[CryptoOps]   Failed to hook {api_name}: " + e);
    }}
"""


def _generate_address_hook(address: str, hint_id: str, function_name: str) -> str:
    """Generate hook for a specific address."""
    return f"""
// Hook address: {address} (hint: {hint_id}, name: {function_name})
try {{
    var addr_custom_{hint_id} = ptr("{address}");
    Interceptor.attach(addr_custom_{hint_id}, {{
        onEnter: function(args) {{
            if (!shouldCaptureCryptoCall()) {{
                return;
            }}

            this.enterTime = getTimestamp();

            send({{
                type: "crypto_call",
                hint_id: "{hint_id}",
                function: "{function_name}",
                module: "custom",
                address: "{address}",
                timestamp: this.enterTime,
                args_count: args.length,
                backtrace: getBacktrace(5)
            }});
        }},
        onLeave: function(retval) {{
            if (this.enterTime) {{
                send({{
                    type: "crypto_return",
                    function: "{function_name}",
                    address: "{address}",
                    retval: retval.toString(),
                    duration_ms: getTimestamp() - this.enterTime,
                    timestamp: getTimestamp()
                }});
            }}
        }}
    }});
    console.log("[CryptoOps]   Hooked custom address: {address}");
}} catch (e) {{
    console.log("[CryptoOps]   Failed to hook {address}: " + e);
}}
"""


def _generate_script_footer() -> str:
    """Generate script footer."""
    return """
// ============================================================================
// Crypto Operations Summary
// ============================================================================

console.log("[CryptoOps] Crypto hooks installation complete");
console.log("[CryptoOps] BCrypt APIs hooked: " + Object.keys(cryptoStats.bcrypt).length);
console.log("[CryptoOps] Crypt32 APIs hooked: " + Object.keys(cryptoStats.crypt32).length);
console.log("[CryptoOps] Custom hooks: " + Object.keys(cryptoStats.custom).length);
"""


def _find_hint_for_function(function_name: str, hints: List[Dict]) -> Dict[str, Any]:
    """
    Find hint matching a function name.

    Args:
        function_name: Function name to search for
        hints: List of hints

    Returns:
        Matching hint or empty dict
    """
    for hint in hints:
        hint_name = hint.get('name', '')
        if hint_name.lower() == function_name.lower():
            return hint
    return {}


def get_supported_apis() -> Dict[str, List[str]]:
    """
    Get list of supported crypto APIs.

    Returns:
        Dictionary mapping module names to API lists
    """
    return {
        'bcrypt.dll': [
            'BCryptOpenAlgorithmProvider',
            'BCryptCloseAlgorithmProvider',
            'BCryptGetProperty',
            'BCryptSetProperty',
            'BCryptGenerateSymmetricKey',
            'BCryptGenerateKeyPair',
            'BCryptEncrypt',
            'BCryptDecrypt',
            'BCryptExportKey',
            'BCryptImportKey',
            'BCryptDuplicateKey',
            'BCryptDestroyKey',
            'BCryptHash',
            'BCryptHashData',
            'BCryptFinishHash',
            'BCryptCreateHash',
            'BCryptDestroyHash',
            'BCryptGenRandom',
            'BCryptDeriveKey',
            'BCryptDeriveKeyPBKDF2',
            'BCryptKeyDerivation',
            'BCryptSignHash',
            'BCryptVerifySignature',
            'BCryptSecretAgreement',
        ],
        'crypt32.dll': [
            'CryptEncrypt',
            'CryptDecrypt',
            'CryptCreateHash',
            'CryptHashData',
            'CryptDeriveKey',
            'CryptGenRandom',
            'CryptAcquireContext',
            'CryptReleaseContext',
            'CryptGenKey',
            'CryptDestroyKey',
            'CryptExportKey',
            'CryptImportKey',
            'CryptGetHashParam',
            'CryptSetHashParam',
            'CryptSignHash',
            'CryptVerifySignature',
        ]
    }
