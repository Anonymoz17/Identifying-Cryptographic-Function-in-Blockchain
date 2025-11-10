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
        _generate_custom_hooks(crypto_hints),
        _generate_script_footer()
    ]

    return '\n\n'.join(script_parts)


def _generate_script_header() -> str:
    """Generate script header."""
    return """
// ============================================================================
// Crypto Operations Instrumenter
// Hooks Windows crypto APIs (bcrypt.dll, crypt32.dll)
// ============================================================================

console.log("[CryptoOps] Installing crypto API hooks...");

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
