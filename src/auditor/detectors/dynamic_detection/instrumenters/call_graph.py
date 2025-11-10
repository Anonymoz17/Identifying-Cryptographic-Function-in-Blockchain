"""
Call graph instrumenter (optional).

Builds runtime call graph from crypto function calls.
Tracks caller→callee relationships for crypto operations.
"""

from typing import Dict, Any, List


def generate_call_graph_script(hints_data: Dict[str, Any], config) -> str:
    """
    Generate JavaScript for call graph tracking.

    Tracks which functions call crypto operations by analyzing backtraces.
    Useful for understanding crypto usage patterns in the binary.

    Args:
        hints_data: Hints from static analysis
        config: Configuration instance

    Returns:
        JavaScript code string
    """
    # Get crypto hints to track
    hints = hints_data.get('hints', [])
    crypto_hints = [h for h in hints if h.get('type') in ['crypto_function', 'instruction_pattern']]

    return f"""
// ============================================================================
// Call Graph Tracker (Optional)
// Tracks caller→crypto function relationships
// ============================================================================

console.log("[CallGraph] Installing call graph tracker...");

var callGraph = {{
    edges: [],
    nodes: {{}},
    stats: {{
        totalCalls: 0,
        uniqueEdges: 0,
        uniqueCallers: 0
    }}
}};

var MAX_CALL_GRAPH_EDGES = 1000;  // Limit to prevent memory issues

/**
 * Add edge to call graph.
 */
function addCallGraphEdge(caller, callee, calleeSymbol) {{
    if (callGraph.edges.length >= MAX_CALL_GRAPH_EDGES) {{
        return;  // Limit reached
    }}

    callGraph.stats.totalCalls++;

    // Create edge ID
    var edgeId = caller + "->" + callee;

    // Check if edge already exists
    if (callGraph.nodes[edgeId]) {{
        callGraph.nodes[edgeId].count++;
        return;  // Already recorded
    }}

    // New edge
    callGraph.nodes[edgeId] = {{
        count: 1,
        caller: caller,
        callee: callee,
        callee_symbol: calleeSymbol
    }};

    callGraph.stats.uniqueEdges++;

    // Send event
    send({{
        type: "call_graph",
        caller: caller,
        callee: callee,
        callee_symbol: calleeSymbol,
        timestamp: getTimestamp()
    }});
}}

/**
 * Extract caller from backtrace.
 */
function extractCaller(backtrace) {{
    if (!backtrace || backtrace.length < 2) {{
        return "unknown";
    }}

    // backtrace[0] is current function
    // backtrace[1] is immediate caller
    var callerFrame = backtrace[1];

    try {{
        var symbol = DebugSymbol.fromAddress(callerFrame);
        return symbol.address.toString();
    }} catch (e) {{
        return callerFrame.toString();
    }}
}}

/**
 * Hook crypto functions for call graph tracking.
 *
 * This piggybacks on existing crypto hooks by analyzing backtraces.
 * Alternative: install separate hooks just for call graph.
 */

// Note: Call graph tracking is integrated into crypto_ops hooks via backtrace
// This script provides additional analysis and aggregation

console.log("[CallGraph] Call graph tracker installed");
console.log("[CallGraph] Will track up to " + MAX_CALL_GRAPH_EDGES + " unique edges");

// Report call graph summary periodically
setInterval(function() {{
    if (callGraph.stats.totalCalls > 0) {{
        console.log("[CallGraph] Summary:");
        console.log("[CallGraph]   Total calls: " + callGraph.stats.totalCalls);
        console.log("[CallGraph]   Unique edges: " + callGraph.stats.uniqueEdges);
    }}
}}, 10000);  // Every 10 seconds
"""


def generate_call_graph_hooks(target_functions: List[str], module: str) -> str:
    """
    Generate dedicated call graph hooks for specific functions.

    Args:
        target_functions: List of function names to track
        module: Module name (e.g., "bcrypt.dll")

    Returns:
        JavaScript code string
    """
    hooks = [f"""
// Call graph hooks for {module}
"""]

    for func_name in target_functions:
        hooks.append(f"""
try {{
    var addr_{func_name}_cg = findExport("{module}", "{func_name}");
    if (addr_{func_name}_cg) {{
        Interceptor.attach(addr_{func_name}_cg, {{
            onEnter: function(args) {{
                try {{
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    if (bt.length >= 2) {{
                        var caller = bt[1].toString();
                        var callee = addr_{func_name}_cg.toString();
                        addCallGraphEdge(caller, callee, "{func_name}");
                    }}
                }} catch (e) {{
                    // Silently skip errors
                }}
            }}
        }});
    }}
}} catch (e) {{
    console.log("[CallGraph] Failed to hook {func_name}: " + e);
}}
""")

    return '\n'.join(hooks)


def get_call_graph_configuration() -> Dict[str, Any]:
    """
    Get default call graph configuration.

    Returns:
        Dictionary with configuration
    """
    return {
        'max_edges': 1000,  # Maximum unique edges to track
        'backtrace_depth': 5,  # How deep to analyze backtraces
        'report_interval_ms': 10000,  # Summary reporting interval
        'track_all_calls': False,  # Track all calls or just first occurrence
    }


def analyze_call_graph(edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze call graph edges to find patterns.

    Args:
        edges: List of call graph edges

    Returns:
        Analysis results
    """
    if not edges:
        return {'total_edges': 0}

    # Count unique callers
    callers = set(edge.get('caller') for edge in edges)

    # Count unique callees
    callees = set(edge.get('callee') for edge in edges)

    # Find most common callers
    caller_counts = {}
    for edge in edges:
        caller = edge.get('caller')
        caller_counts[caller] = caller_counts.get(caller, 0) + 1

    top_callers = sorted(caller_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Find most common callees
    callee_counts = {}
    for edge in edges:
        callee = edge.get('callee')
        callee_symbol = edge.get('callee_symbol', callee)
        key = f"{callee} ({callee_symbol})"
        callee_counts[key] = callee_counts.get(key, 0) + 1

    top_callees = sorted(callee_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        'total_edges': len(edges),
        'unique_callers': len(callers),
        'unique_callees': len(callees),
        'top_callers': [{'address': addr, 'count': count} for addr, count in top_callers],
        'top_callees': [{'target': target, 'count': count} for target, count in top_callees],
    }
