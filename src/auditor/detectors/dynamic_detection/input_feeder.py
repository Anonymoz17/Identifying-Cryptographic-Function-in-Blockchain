"""
Input feeder for dynamic analysis.

Handles command-line arguments and input files for binaries
that require them during execution.
"""

import os
import shutil
from typing import List, Optional, Dict, Any
from .config import Config


class InputConfig:
    """
    Configuration for binary input.

    Holds command-line arguments and input file paths
    to be used during binary execution.
    """

    def __init__(self, args: List[str] = None, input_file: Optional[str] = None):
        """
        Initialize input configuration.

        Args:
            args: Command-line arguments
            input_file: Path to input file
        """
        self.args = args or []
        self.input_file = input_file
        self.prepared_input_file: Optional[str] = None  # Path in sandbox

    def has_args(self) -> bool:
        """Check if command-line args are configured."""
        return len(self.args) > 0

    def has_input_file(self) -> bool:
        """Check if input file is configured."""
        return self.input_file is not None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            'args': self.args,
            'input_file': self.input_file,
            'has_args': self.has_args(),
            'has_input_file': self.has_input_file()
        }


def prepare_input(preproc_dir: str, config: Config, sandbox_temp_dir: str) -> InputConfig:
    """
    Prepare input configuration for binary execution.

    Loads args and input_file from config, and copies input file
    to sandbox if needed.

    Args:
        preproc_dir: Path to preprocessing directory
        config: Configuration instance
        sandbox_temp_dir: Sandbox temporary directory

    Returns:
        InputConfig instance with prepared inputs
    """
    # Get args from config
    args = config.get('args', default=[])
    if not isinstance(args, list):
        args = []

    # Get input file from config
    input_file = config.get('input_file')

    # Create input config
    input_config = InputConfig(args=args, input_file=input_file)

    # If input file specified, copy to sandbox
    if input_file:
        input_config.prepared_input_file = _copy_input_file_to_sandbox(
            preproc_dir,
            input_file,
            sandbox_temp_dir
        )

    return input_config


def _copy_input_file_to_sandbox(preproc_dir: str, input_file: str, sandbox_temp_dir: str) -> Optional[str]:
    """
    Copy input file to sandbox.

    Args:
        preproc_dir: Preprocessing directory
        input_file: Input file path (relative to preproc_dir or absolute)
        sandbox_temp_dir: Sandbox temp directory

    Returns:
        Path to copied file in sandbox, or None if failed
    """
    # Try multiple locations for input file
    possible_paths = [
        input_file,  # Absolute path
        os.path.join(preproc_dir, input_file),  # Relative to preproc
        os.path.join(os.path.dirname(preproc_dir), input_file),  # Relative to parent
    ]

    source_path = None
    for path in possible_paths:
        if os.path.exists(path) and os.path.isfile(path):
            source_path = path
            break

    if not source_path:
        print(f"Warning: Input file not found: {input_file}")
        return None

    # Copy to sandbox with same name
    filename = os.path.basename(input_file)
    dest_path = os.path.join(sandbox_temp_dir, filename)

    try:
        shutil.copy2(source_path, dest_path)
        return dest_path
    except Exception as e:
        print(f"Warning: Failed to copy input file to sandbox: {e}")
        return None


def build_spawn_args(binary_path: str, input_config: InputConfig) -> List[str]:
    """
    Build complete spawn argument list.

    Args:
        binary_path: Path to binary executable
        input_config: Input configuration

    Returns:
        List of arguments for spawn [binary_path, arg1, arg2, ...]
    """
    spawn_args = [binary_path]

    # Add configured args
    if input_config.has_args():
        spawn_args.extend(input_config.args)

    # If input file prepared, add it as argument (common pattern)
    # Note: Some binaries read from stdin, others from file arg
    # This adds it as arg; stdin feeding can be added later if needed
    if input_config.prepared_input_file:
        # Check if args already reference an input file
        has_input_arg = any(
            arg.endswith(('.dat', '.txt', '.bin', '.json', '.xml'))
            for arg in input_config.args
        )

        # Only add if not already in args
        if not has_input_arg:
            spawn_args.append(input_config.prepared_input_file)

    return spawn_args


def get_input_summary(input_config: InputConfig) -> str:
    """
    Get human-readable summary of input configuration.

    Args:
        input_config: Input configuration

    Returns:
        Summary string
    """
    parts = []

    if input_config.has_args():
        parts.append(f"{len(input_config.args)} args")

    if input_config.has_input_file():
        parts.append(f"input file: {os.path.basename(input_config.input_file)}")

    if not parts:
        return "No input configuration"

    return ", ".join(parts)


def validate_input_config(input_config: InputConfig) -> tuple[bool, Optional[str]]:
    """
    Validate input configuration.

    Args:
        input_config: Input configuration to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check args are strings
    if input_config.args:
        for i, arg in enumerate(input_config.args):
            if not isinstance(arg, str):
                return (False, f"Argument {i} is not a string: {type(arg)}")

    # Check input file exists if specified
    if input_config.has_input_file():
        if input_config.prepared_input_file:
            if not os.path.exists(input_config.prepared_input_file):
                return (False, f"Prepared input file not found: {input_config.prepared_input_file}")
        else:
            return (False, f"Input file specified but not prepared: {input_config.input_file}")

    return (True, None)


def load_input_config_from_file(config_path: str) -> InputConfig:
    """
    Load input configuration from JSON file.

    Args:
        config_path: Path to dynamic_config.json

    Returns:
        InputConfig instance

    Raises:
        FileNotFoundError: If config file not found
        json.JSONDecodeError: If config file invalid
    """
    import json

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, 'r') as f:
        config_data = json.load(f)

    args = config_data.get('args', [])
    input_file = config_data.get('input_file')

    return InputConfig(args=args, input_file=input_file)
