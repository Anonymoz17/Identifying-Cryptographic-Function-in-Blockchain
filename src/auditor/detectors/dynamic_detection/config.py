"""
Configuration management for dynamic detection.

Handles loading and validation of configuration settings for
dynamic analysis runs.
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path


# Default configuration
DEFAULT_CONFIG = {
    'timeout': 500,  # seconds
    'memory_limit': 512,  # MB
    'max_trace_events': 10000,
    'max_trace_size_mb': 10,
    'max_crypto_calls': 100,
    'cache_ttl_hours': 24,
    'instrumenters': {
        'crypto_ops': True,
        'memory_scan': False,
        'call_graph': False
    },
    'crypto_apis': {
        'bcrypt': [
            'BCryptEncrypt',
            'BCryptDecrypt',
            'BCryptGenRandom',
            'BCryptGenerateSymmetricKey',
            'BCryptDeriveKey',
            'BCryptHash',
            'BCryptHashData'
        ],
        'crypt32': [
            'CryptEncrypt',
            'CryptDecrypt',
            'CryptGenRandom',
            'CryptHashData',
            'CryptCreateHash',
            'CryptDeriveKey'
        ]
    },
    'entropy_threshold': 7.5,  # bits/byte for high-entropy detection
    'max_buffer_sample_size': 256,  # bytes to hash per buffer
    'network_blocking': True
}


class Config:
    """
    Configuration manager for dynamic detection.

    Loads configuration from multiple sources with precedence:
    1. Per-binary config (dynamic_config.json in preproc dir)
    2. User config (~/.cryptoscope/dynamic_config.json)
    3. Defaults

    Usage:
        config = Config.load(preproc_dir="/path/to/preproc/abc123")
        timeout = config.get('timeout')
        apis = config.get('crypto_apis', 'bcrypt')
    """

    def __init__(self, config_dict: Dict[str, Any]):
        """
        Initialize with configuration dictionary.

        Args:
            config_dict: Configuration dictionary
        """
        self._config = config_dict

    @classmethod
    def load(cls, preproc_dir: Optional[str] = None, config_path: Optional[str] = None) -> 'Config':
        """
        Load configuration from multiple sources.

        Args:
            preproc_dir: Path to preprocessing directory (for per-binary config)
            config_path: Explicit config path (overrides per-binary config)

        Returns:
            Config instance
        """
        # Start with defaults
        config = DEFAULT_CONFIG.copy()

        # Load user config (if exists)
        user_config_path = cls._get_user_config_path()
        if user_config_path.exists():
            user_config = cls._load_json(str(user_config_path))
            config = cls._merge_config(config, user_config)

        # Load per-binary config (if exists)
        if config_path:
            # Explicit config path provided
            if os.path.exists(config_path):
                binary_config = cls._load_json(config_path)
                config = cls._merge_config(config, binary_config)
        elif preproc_dir:
            # Check for dynamic_config.json in preproc dir
            binary_config_path = os.path.join(preproc_dir, 'dynamic_config.json')
            if os.path.exists(binary_config_path):
                binary_config = cls._load_json(binary_config_path)
                config = cls._merge_config(config, binary_config)

        return cls(config)

    @staticmethod
    def _get_user_config_path() -> Path:
        """Get path to user config file."""
        home = Path.home()
        return home / '.cryptoscope' / 'dynamic_config.json'

    @staticmethod
    def _load_json(path: str) -> Dict[str, Any]:
        """Load JSON file."""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Failed to load config from {path}: {e}")
            return {}

    @staticmethod
    def _merge_config(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge two config dictionaries (deep merge).

        Args:
            base: Base configuration
            override: Override configuration

        Returns:
            Merged configuration
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._merge_config(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, *keys, default=None) -> Any:
        """
        Get configuration value by key path.

        Args:
            *keys: Key path (e.g., 'crypto_apis', 'bcrypt')
            default: Default value if key not found

        Returns:
            Configuration value

        Examples:
            config.get('timeout')  # 500
            config.get('crypto_apis', 'bcrypt')  # [...list of API names...]
            config.get('unknown', default=100)  # 100
        """
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        """
        Set configuration value.

        Args:
            key: Configuration key
            value: Configuration value
        """
        self._config[key] = value

    def to_dict(self) -> Dict[str, Any]:
        """Get full configuration as dictionary."""
        return self._config.copy()

    def save_user_config(self):
        """Save current configuration to user config file."""
        config_path = self._get_user_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, 'w') as f:
            json.dump(self._config, f, indent=2)


def load_dynamic_config(preproc_dir: Optional[str] = None, config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to load dynamic config.

    Args:
        preproc_dir: Path to preprocessing directory
        config_path: Explicit config path

    Returns:
        Configuration dictionary
    """
    config = Config.load(preproc_dir=preproc_dir, config_path=config_path)
    return config.to_dict()


def get_default_config() -> Dict[str, Any]:
    """Get default configuration."""
    return DEFAULT_CONFIG.copy()
