"""
Schema validator for dynamic detection outputs.

Validates JSON files against JSON schemas to ensure data integrity.
"""

import json
import os
from typing import Dict, Any, List, Tuple, Optional


def load_schema(schema_name: str) -> Dict[str, Any]:
    """
    Load JSON schema.

    Args:
        schema_name: Schema name (e.g., 'dynamic_results', 'trace_event')

    Returns:
        Schema dictionary

    Raises:
        FileNotFoundError: If schema file not found
    """
    schema_dir = os.path.join(os.path.dirname(__file__), 'schemas')
    schema_path = os.path.join(schema_dir, f'{schema_name}.schema.json')

    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema not found: {schema_path}")

    with open(schema_path, 'r') as f:
        return json.load(f)


def validate_dynamic_results(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate dynamic_results.json structure.

    Args:
        data: Results data to validate

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []

    # Required top-level fields
    required_fields = [
        'file_hash', 'schema_version', 'timestamp', 'mode',
        'summary', 'findings', 'trace_summary', 'meta'
    ]

    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    # Validate summary
    if 'summary' in data:
        summary = data['summary']
        required_summary = ['total_crypto_calls', 'unique_functions', 'execution_time_seconds']

        for field in required_summary:
            if field not in summary:
                errors.append(f"Missing summary field: {field}")

        # Type checks
        if 'total_crypto_calls' in summary and not isinstance(summary['total_crypto_calls'], int):
            errors.append("summary.total_crypto_calls must be an integer")

        if 'unique_functions' in summary and not isinstance(summary['unique_functions'], list):
            errors.append("summary.unique_functions must be a list")

        if 'execution_time_seconds' in summary and not isinstance(summary['execution_time_seconds'], (int, float)):
            errors.append("summary.execution_time_seconds must be a number")

    # Validate findings
    if 'findings' in data:
        if not isinstance(data['findings'], list):
            errors.append("findings must be a list")
        else:
            for i, finding in enumerate(data['findings']):
                if not isinstance(finding, dict):
                    errors.append(f"finding[{i}] must be a dictionary")
                    continue

                # Required finding fields
                if 'id' not in finding:
                    errors.append(f"finding[{i}] missing 'id'")
                if 'type' not in finding:
                    errors.append(f"finding[{i}] missing 'type'")
                if 'confidence' not in finding:
                    errors.append(f"finding[{i}] missing 'confidence'")

                # Validate confidence range
                if 'confidence' in finding:
                    conf = finding['confidence']
                    if not isinstance(conf, (int, float)) or conf < 0.0 or conf > 1.0:
                        errors.append(f"finding[{i}] confidence must be between 0.0 and 1.0")

    # Validate trace_summary
    if 'trace_summary' in data:
        trace_summary = data['trace_summary']
        required_trace = ['total_events', 'size_bytes', 'limits_reached']

        for field in required_trace:
            if field not in trace_summary:
                errors.append(f"Missing trace_summary field: {field}")

        # Type checks
        if 'total_events' in trace_summary and not isinstance(trace_summary['total_events'], int):
            errors.append("trace_summary.total_events must be an integer")

        if 'size_bytes' in trace_summary and not isinstance(trace_summary['size_bytes'], int):
            errors.append("trace_summary.size_bytes must be an integer")

        if 'limits_reached' in trace_summary and not isinstance(trace_summary['limits_reached'], dict):
            errors.append("trace_summary.limits_reached must be a dictionary")

    # Validate meta
    if 'meta' in data:
        meta = data['meta']
        if 'tool_versions' not in meta:
            errors.append("Missing meta.tool_versions")
        else:
            tool_versions = meta['tool_versions']
            required_versions = ['frida', 'python', 'detector_version']
            for field in required_versions:
                if field not in tool_versions:
                    errors.append(f"Missing meta.tool_versions.{field}")

    # Validate mode
    if 'mode' in data and data['mode'] not in ['spawn', 'attach']:
        errors.append("mode must be 'spawn' or 'attach'")

    return (len(errors) == 0, errors)


def validate_trace_event(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate a single trace event.

    Args:
        event: Event data to validate

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []

    # Required fields
    if 'type' not in event:
        errors.append("Missing required field: type")
    if 'timestamp' not in event:
        errors.append("Missing required field: timestamp")

    # Validate type
    if 'type' in event:
        valid_types = ['crypto_call', 'crypto_return', 'memory_scan', 'call_graph', 'error', 'network_blocked', 'limit_reached']
        if event['type'] not in valid_types:
            errors.append(f"Invalid event type: {event['type']}")

        # Type-specific validation
        event_type = event['type']

        if event_type == 'crypto_call':
            if 'function' not in event:
                errors.append("crypto_call event missing 'function'")
            if 'module' not in event:
                errors.append("crypto_call event missing 'module'")

        elif event_type == 'crypto_return':
            if 'function' not in event:
                errors.append("crypto_return event missing 'function'")

        elif event_type == 'memory_scan':
            required = ['range', 'entropy', 'hash']
            for field in required:
                if field not in event:
                    errors.append(f"memory_scan event missing '{field}'")

            # Validate entropy range
            if 'entropy' in event:
                entropy = event['entropy']
                if not isinstance(entropy, (int, float)) or entropy < 0 or entropy > 8:
                    errors.append("memory_scan entropy must be between 0 and 8")

        elif event_type == 'call_graph':
            if 'caller' not in event:
                errors.append("call_graph event missing 'caller'")
            if 'callee' not in event:
                errors.append("call_graph event missing 'callee'")

    # Validate timestamp
    if 'timestamp' in event:
        if not isinstance(event['timestamp'], (int, float)):
            errors.append("timestamp must be a number")

    return (len(errors) == 0, errors)


def validate_dynamic_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate dynamic_config.json structure.

    Args:
        config: Config data to validate

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []

    # Validate args
    if 'args' in config:
        if not isinstance(config['args'], list):
            errors.append("args must be a list")
        else:
            for i, arg in enumerate(config['args']):
                if not isinstance(arg, str):
                    errors.append(f"args[{i}] must be a string")

    # Validate input_file
    if 'input_file' in config:
        if not isinstance(config['input_file'], str):
            errors.append("input_file must be a string")

    # Validate timeout
    if 'timeout' in config:
        timeout = config['timeout']
        if not isinstance(timeout, int) or timeout < 10 or timeout > 3600:
            errors.append("timeout must be an integer between 10 and 3600")

    # Validate memory_limit
    if 'memory_limit' in config:
        mem = config['memory_limit']
        if not isinstance(mem, int) or mem < 128 or mem > 4096:
            errors.append("memory_limit must be an integer between 128 and 4096")

    # Validate instrumenters
    if 'instrumenters' in config:
        if not isinstance(config['instrumenters'], dict):
            errors.append("instrumenters must be a dictionary")
        else:
            valid_instrumenters = ['crypto_ops', 'memory_scan', 'call_graph']
            for key in config['instrumenters']:
                if key not in valid_instrumenters:
                    errors.append(f"Unknown instrumenter: {key}")
                if not isinstance(config['instrumenters'][key], bool):
                    errors.append(f"instrumenters.{key} must be a boolean")

    # Validate entropy_threshold
    if 'entropy_threshold' in config:
        entropy = config['entropy_threshold']
        if not isinstance(entropy, (int, float)) or entropy < 0 or entropy > 8:
            errors.append("entropy_threshold must be between 0.0 and 8.0")

    # Validate max_trace_events
    if 'max_trace_events' in config:
        events = config['max_trace_events']
        if not isinstance(events, int) or events < 100 or events > 100000:
            errors.append("max_trace_events must be between 100 and 100000")

    # Validate max_crypto_calls
    if 'max_crypto_calls' in config:
        calls = config['max_crypto_calls']
        if not isinstance(calls, int) or calls < 10 or calls > 1000:
            errors.append("max_crypto_calls must be between 10 and 1000")

    return (len(errors) == 0, errors)


def validate_file(file_path: str, schema_type: str) -> Tuple[bool, List[str]]:
    """
    Validate a JSON file against a schema.

    Args:
        file_path: Path to JSON file
        schema_type: Schema type ('dynamic_results', 'trace_event', 'dynamic_config')

    Returns:
        Tuple of (is_valid, error_messages)
    """
    try:
        # Load file
        with open(file_path, 'r') as f:
            data = json.load(f)

        # Validate based on type
        if schema_type == 'dynamic_results':
            return validate_dynamic_results(data)
        elif schema_type == 'trace_event':
            return validate_trace_event(data)
        elif schema_type == 'dynamic_config':
            return validate_dynamic_config(data)
        else:
            return (False, [f"Unknown schema type: {schema_type}"])

    except json.JSONDecodeError as e:
        return (False, [f"Invalid JSON: {e}"])
    except FileNotFoundError:
        return (False, [f"File not found: {file_path}"])
    except Exception as e:
        return (False, [f"Validation error: {e}"])


def validate_ndjson_file(file_path: str) -> Tuple[bool, List[str]]:
    """
    Validate NDJSON trace file (one JSON object per line).

    Args:
        file_path: Path to NDJSON file

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []

    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    is_valid, event_errors = validate_trace_event(event)

                    if not is_valid:
                        for error in event_errors:
                            errors.append(f"Line {line_num}: {error}")

                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_num}: Invalid JSON - {e}")

        return (len(errors) == 0, errors)

    except FileNotFoundError:
        return (False, [f"File not found: {file_path}"])
    except Exception as e:
        return (False, [f"Validation error: {e}"])


def validate_dynamic_analysis_output(analysis_dir: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Validate complete dynamic analysis output directory.

    Args:
        analysis_dir: Path to analysis/dynamic/<hash>/ directory

    Returns:
        Tuple of (is_valid, validation_report)
    """
    report = {
        'analysis_dir': analysis_dir,
        'files_checked': [],
        'errors': []
    }

    # Check dynamic_results.json
    results_path = os.path.join(analysis_dir, 'dynamic_results.json')
    if os.path.exists(results_path):
        report['files_checked'].append('dynamic_results.json')
        is_valid, errors = validate_file(results_path, 'dynamic_results')
        if not is_valid:
            report['errors'].extend([f"dynamic_results.json: {e}" for e in errors])
    else:
        report['errors'].append("dynamic_results.json not found")

    # Check trace.ndjson
    trace_path = os.path.join(analysis_dir, 'trace.ndjson')
    if os.path.exists(trace_path):
        report['files_checked'].append('trace.ndjson')
        is_valid, errors = validate_ndjson_file(trace_path)
        if not is_valid:
            # Limit errors shown (NDJSON can have many)
            for error in errors[:10]:
                report['errors'].append(f"trace.ndjson: {error}")
            if len(errors) > 10:
                report['errors'].append(f"trace.ndjson: ... and {len(errors) - 10} more errors")
    else:
        report['errors'].append("trace.ndjson not found")

    # Check .cache_meta.json (optional)
    cache_path = os.path.join(analysis_dir, '.cache_meta.json')
    if os.path.exists(cache_path):
        report['files_checked'].append('.cache_meta.json')
        try:
            with open(cache_path, 'r') as f:
                cache_meta = json.load(f)
                # Basic validation
                required = ['file_hash', 'timestamp', 'tool_versions']
                for field in required:
                    if field not in cache_meta:
                        report['errors'].append(f".cache_meta.json: Missing field '{field}'")
        except Exception as e:
            report['errors'].append(f".cache_meta.json: {e}")

    is_valid = len(report['errors']) == 0
    report['is_valid'] = is_valid

    return (is_valid, report)
