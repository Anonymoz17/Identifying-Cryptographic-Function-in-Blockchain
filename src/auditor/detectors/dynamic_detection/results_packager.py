"""
Results packager for dynamic analysis.

Packages trace data and analysis results into structured JSON output.
Generates both dynamic_results.json (summary) and trace.ndjson (full traces).
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from .context import DynamicContext, DynamicResult, TraceSummary
from .trace_manager import TraceManager


def package_results(
    ctx: DynamicContext,
    trace_manager: TraceManager,
    hints_data: Dict[str, Any],
    analysis_dir: str,
    execution_time_seconds: float,
    incomplete: bool = False,
    incomplete_reason: Optional[str] = None
) -> DynamicResult:
    """
    Package dynamic analysis results.

    Creates two files:
    1. dynamic_results.json - Summary with findings
    2. trace.ndjson - Full trace events

    Args:
        ctx: Dynamic analysis context
        trace_manager: Trace manager with collected events
        hints_data: Hints from static analysis
        analysis_dir: Output directory
        execution_time_seconds: Actual execution time
        incomplete: Whether run was incomplete
        incomplete_reason: Reason for incomplete run

    Returns:
        DynamicResult with paths to generated files
    """
    # Ensure analysis directory exists
    os.makedirs(analysis_dir, exist_ok=True)

    # Get trace summary
    trace_summary = trace_manager.get_summary()

    # Analyze events to generate findings
    events = trace_manager.get_events()
    findings = generate_findings(events, hints_data)

    # Generate summary
    summary = generate_summary(events, execution_time_seconds)

    # Create dynamic_results.json
    results = {
        'file_hash': ctx.file_hash,
        'schema_version': '1.0',
        'timestamp': datetime.now().isoformat(),
        'mode': ctx.mode,
        'incomplete': incomplete,
        'incomplete_reason': incomplete_reason,
        'summary': summary,
        'findings': findings,
        'trace_summary': {
            'total_events': trace_summary.total_events,
            'crypto_calls': trace_summary.crypto_calls,
            'memory_scans': trace_summary.memory_scans,
            'call_graph_edges': trace_summary.call_graph_edges,
            'size_bytes': trace_summary.size_bytes,
            'limits_reached': trace_summary.limits_reached
        },
        'meta': {
            'tool_versions': {
                'frida': ctx.tool_versions.frida,
                'python': ctx.tool_versions.python,
                'detector_version': ctx.tool_versions.detector_version,
                'platform': ctx.tool_versions.platform
            },
            'config': {
                'timeout': ctx.timeout,
                'memory_limit': ctx.memory_limit,
                'instrumenters': ctx.instrumenters
            }
        }
    }

    # Write dynamic_results.json
    results_path = os.path.join(analysis_dir, 'dynamic_results.json')
    write_json_atomic(results_path, results)

    # Write trace.ndjson
    trace_path = os.path.join(analysis_dir, 'trace.ndjson')
    trace_manager.write_ndjson_atomic(trace_path)

    # Create result
    result = DynamicResult(
        file_hash=ctx.file_hash,
        dynamic_results_path=results_path,
        trace_path=trace_path,
        cached=False,
        incomplete=incomplete,
        incomplete_reason=incomplete_reason,
        summary=summary
    )

    return result


def generate_findings(events: List[Dict[str, Any]], hints_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate findings from trace events.

    Analyzes events to create high-level findings about crypto usage.

    Args:
        events: List of trace events
        hints_data: Hints from static analysis

    Returns:
        List of findings
    """
    findings = []

    # Group crypto calls by function
    crypto_calls = [e for e in events if e.get('type') == 'crypto_call']
    call_counts = {}

    for call in crypto_calls:
        function = call.get('function', 'unknown')
        module = call.get('module', 'unknown')
        key = f"{module}!{function}"

        if key not in call_counts:
            call_counts[key] = {
                'function': function,
                'module': module,
                'count': 0,
                'hint_ids': set()
            }

        call_counts[key]['count'] += 1

        hint_id = call.get('hint_id')
        if hint_id:
            call_counts[key]['hint_ids'].add(hint_id)

    # Create findings from call counts
    for i, (key, data) in enumerate(call_counts.items(), 1):
        finding = {
            'id': f"dynamic_{i}",
            'type': 'crypto_call',
            'function': data['function'],
            'module': data['module'],
            'count': data['count'],
            'confidence': 1.0,  # Dynamic observation = high confidence
            'evidence': f"Observed {data['count']} calls to {data['function']}",
            'hint_ids': list(data['hint_ids']) if data['hint_ids'] else None
        }
        findings.append(finding)

    # Add high-entropy memory findings
    memory_scans = [e for e in events if e.get('type') == 'memory_scan']
    if memory_scans:
        finding = {
            'id': f"dynamic_{len(findings) + 1}",
            'type': 'high_entropy_memory',
            'count': len(memory_scans),
            'confidence': 0.7,  # Lower confidence - might not be crypto
            'evidence': f"Found {len(memory_scans)} high-entropy memory regions",
        }
        findings.append(finding)

    return findings


def generate_summary(events: List[Dict[str, Any]], execution_time_seconds: float) -> Dict[str, Any]:
    """
    Generate high-level summary.

    Args:
        events: List of trace events
        execution_time_seconds: Execution time

    Returns:
        Summary dictionary
    """
    crypto_calls = [e for e in events if e.get('type') == 'crypto_call']
    memory_scans = [e for e in events if e.get('type') == 'memory_scan']
    call_graph_edges = [e for e in events if e.get('type') == 'call_graph']

    # Get unique functions
    unique_functions = list(set(
        call.get('function', 'unknown')
        for call in crypto_calls
    ))

    return {
        'total_crypto_calls': len(crypto_calls),
        'unique_functions': unique_functions,
        'high_entropy_regions': len(memory_scans),
        'call_graph_nodes': len(call_graph_edges),
        'execution_time_seconds': execution_time_seconds
    }


def write_json_atomic(path: str, data: Dict[str, Any]):
    """
    Write JSON file atomically.

    Args:
        path: Output path
        data: Data to write
    """
    temp_path = path + '.tmp'

    with open(temp_path, 'w') as f:
        json.dump(data, f, indent=2)

    # Atomic rename
    if os.path.exists(path):
        os.remove(path)
    os.rename(temp_path, path)


def load_dynamic_results(results_path: str) -> Dict[str, Any]:
    """
    Load dynamic results from JSON.

    Args:
        results_path: Path to dynamic_results.json

    Returns:
        Results dictionary
    """
    with open(results_path, 'r') as f:
        return json.load(f)


def validate_results_structure(results: Dict[str, Any]) -> tuple[bool, List[str]]:
    """
    Validate results structure.

    Args:
        results: Results dictionary

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []

    # Required top-level fields
    required_fields = ['file_hash', 'schema_version', 'timestamp', 'mode', 'summary', 'findings', 'trace_summary', 'meta']
    for field in required_fields:
        if field not in results:
            errors.append(f"Missing required field: {field}")

    # Validate summary
    if 'summary' in results:
        required_summary_fields = ['total_crypto_calls', 'unique_functions', 'execution_time_seconds']
        for field in required_summary_fields:
            if field not in results['summary']:
                errors.append(f"Missing summary field: {field}")

    # Validate findings
    if 'findings' in results:
        if not isinstance(results['findings'], list):
            errors.append("findings must be a list")
        else:
            for i, finding in enumerate(results['findings']):
                if not isinstance(finding, dict):
                    errors.append(f"finding[{i}] must be a dict")
                elif 'id' not in finding or 'type' not in finding:
                    errors.append(f"finding[{i}] missing id or type")

    return (len(errors) == 0, errors)


def merge_with_hints(dynamic_results: Dict[str, Any], hints_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge dynamic results with static hints.

    Correlates dynamic findings with static hints by hint_id.

    Args:
        dynamic_results: Dynamic analysis results
        hints_data: Static analysis hints

    Returns:
        Merged results with correlations
    """
    # Create hint lookup
    hints_by_id = {
        hint.get('id'): hint
        for hint in hints_data.get('hints', [])
        if 'id' in hint
    }

    # Enrich findings with hint data
    findings = dynamic_results.get('findings', [])
    for finding in findings:
        hint_ids = finding.get('hint_ids', [])
        if hint_ids:
            # Add static hint information
            finding['static_hints'] = [
                hints_by_id.get(hint_id)
                for hint_id in hint_ids
                if hint_id in hints_by_id
            ]

    # Add correlation summary
    dynamic_results['correlation'] = {
        'total_hints': len(hints_by_id),
        'confirmed_hints': len([
            f for f in findings
            if f.get('hint_ids')
        ]),
        'new_findings': len([
            f for f in findings
            if not f.get('hint_ids')
        ])
    }

    return dynamic_results
