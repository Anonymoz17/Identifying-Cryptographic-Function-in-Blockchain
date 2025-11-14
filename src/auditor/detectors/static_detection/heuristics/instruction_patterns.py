"""Instruction pattern heuristics for detecting crypto operations.

This heuristic analyzes both Ghidra function exports (disassembly snippets) and
entropy maps to detect patterns commonly found in cryptographic implementations:
- XOR chains (stream ciphers, key mixing)
- Rotation patterns (ROL/ROR in block ciphers)
- Shift operations (bitwise manipulation)
- High-entropy code regions (obfuscation, crypto primitives)
- Tight loops with bitwise ops (cipher rounds)
"""
from typing import List, Dict, Any, Tuple
import hashlib
import json
import re


def _make_id(prefix: str, text: str) -> str:
    return f"{prefix}-{hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()[:8]}"


def _analyze_disassembly_patterns(disasm: str, function_name: str = "") -> Tuple[Dict[str, int], float]:
    """Analyze disassembly snippet for crypto-indicative instruction patterns.
    
    Returns:
        (pattern_counts, confidence_score)
    """
    if not disasm:
        return {}, 0.0
    
    disasm_lower = disasm.lower()
    patterns = {
        "xor": 0,
        "rol": 0,
        "ror": 0,
        "shl": 0,
        "shr": 0,
        "and": 0,
        "or": 0,
        "add": 0,
        "loop": 0,
        "call": 0,
    }
    
    # Count instruction patterns (case-insensitive)
    lines = disasm_lower.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # XOR operations (key mixing, stream ciphers)
        # Supports: xor (x86), eor (ARM), veor (ARM NEON)
        if 'xor' in line or 'eor' in line:
            patterns['xor'] += 1
        
        # Rotation operations (block ciphers like AES, ChaCha20)
        if 'rol' in line or 'rotate' in line:
            patterns['rol'] += 1
        if 'ror' in line:
            patterns['ror'] += 1
        
        # Shift operations (bitwise crypto)
        # x86: shl/sal, ARM: lsl, NEON: vshl
        if 'shl' in line or 'sal' in line or 'lsl' in line or 'vshl' in line:
            patterns['shl'] += 1
        # x86: shr/sar, ARM: lsr/asr, NEON: vshr
        if 'shr' in line or 'sar' in line or 'lsr' in line or 'asr' in line or 'vshr' in line:
            patterns['shr'] += 1
        
        # Bitwise AND operations
        # Match 'and' as instruction (with word boundaries)
        if re.search(r'\band\b', line) or re.search(r'\band\s', line) or re.search(r'\tand\t', line):
            patterns['and'] += 1
        
        # Bitwise OR operations
        # x86: or, ARM: orr, NEON: vorr
        if re.search(r'\b(or|orr|vorr)\b', line):
            patterns['or'] += 1
        
        # Arithmetic (mixing operations)
        if ' add ' in line or '\tadd\t' in line:
            patterns['add'] += 1
        
        # Loop indicators (round-based crypto)
        if 'loop' in line or 'jmp' in line or 'jne' in line or 'jnz' in line:
            patterns['loop'] += 1
        
        # Function calls (library crypto)
        if 'call' in line or 'bl ' in line:
            patterns['call'] += 1
    
    # Calculate confidence based on pattern density
    total_lines = max(len(lines), 1)
    
    # High XOR density is very indicative of crypto
    xor_density = patterns['xor'] / total_lines
    
    # Combined bitwise operation density
    bitwise_density = (patterns['xor'] + patterns['rol'] + patterns['ror'] + 
                       patterns['shl'] + patterns['shr'] + patterns['and']) / total_lines
    
    # Loop presence with bitwise ops suggests rounds/iterations
    has_loops = patterns['loop'] > 0
    
    confidence = 0.0
    reason_tags = []
    
    # XOR-heavy code (stream ciphers, key derivation)
    if xor_density > 0.15:
        confidence += 0.4
        reason_tags.append("high_xor_density")
    elif xor_density > 0.08:
        confidence += 0.25
        reason_tags.append("moderate_xor_density")
    
    # Rotation patterns (block ciphers)
    if patterns['rol'] + patterns['ror'] > 3:
        confidence += 0.3
        reason_tags.append("rotation_ops")
    
    # Combined bitwise complexity
    if bitwise_density > 0.25:
        confidence += 0.3
        reason_tags.append("high_bitwise_density")
    elif bitwise_density > 0.12:
        confidence += 0.15
        reason_tags.append("moderate_bitwise_density")
    
    # Loops with bitwise = likely cipher rounds
    if has_loops and bitwise_density > 0.1:
        confidence += 0.2
        reason_tags.append("bitwise_loop_pattern")
    
    return patterns, min(confidence, 1.0)


def _get_section_for_offset(sections_data: List[Dict], offset: int) -> str:
    """Determine which section contains this offset.

    Args:
        sections_data: List of section dicts with 'name', 'offset', 'size'
        offset: The offset to map to a section

    Returns:
        Section name or 'unknown'
    """
    if not sections_data:
        return "unknown"

    for section in sections_data:
        sec_start = section.get("offset", 0)
        sec_size = section.get("size", 0)
        sec_end = sec_start + sec_size

        if sec_start <= offset < sec_end:
            return section.get("name", "unknown")

    return "unknown"


def _find_containing_function(ghidra_export: List[Dict], offset: int) -> str:
    """Find the function that contains this offset.

    Args:
        ghidra_export: List of function dicts from Ghidra
        offset: The offset to locate

    Returns:
        Function name or 'unknown'
    """
    if not isinstance(ghidra_export, list):
        return "unknown"

    for fn in ghidra_export:
        address = fn.get("address") or fn.get("addr") or fn.get("entry_point")
        size = fn.get("size") or fn.get("length")

        if not address:
            continue

        try:
            # Handle various address formats
            if isinstance(address, str):
                if address.startswith("0x") or address.startswith("0X"):
                    addr_int = int(address, 16)
                else:
                    addr_int = int(address)
            else:
                addr_int = int(address)

            if size:
                size_int = int(size) if isinstance(size, str) else size
                if addr_int <= offset < addr_int + size_int:
                    return fn.get("name", "unknown")
        except (ValueError, TypeError):
            continue

    return "unknown"


def instruction_patterns_heuristic(ghidra_export: Dict, metadata: Dict, static_artifacts: Dict[str, Any] = None) -> List[Dict]:
    """Detect crypto-indicative instruction patterns.

    Primary detection sources:
    1. Ghidra function disassembly (when available) - analyzes instruction sequences
    2. Entropy analysis - detects high-entropy code regions

    Enhancements:
    - Extracts function addresses and sizes from Ghidra metadata
    - Maps entropy clusters to binary sections
    - Finds containing functions for entropy regions
    - Populates location data in additional_data field
    """
    findings: List[Dict] = []

    # Load sections data for location mapping
    sections_data = []
    if static_artifacts:
        sections_path = static_artifacts.get("sections.json")
        if sections_path:
            try:
                with open(sections_path, "r", encoding="utf-8") as fh:
                    sections_doc = json.load(fh)
                    sections_data = sections_doc.get("sections", [])
            except Exception:
                pass

    # PART 1: Analyze Ghidra function disassembly for crypto patterns
    try:
        if isinstance(ghidra_export, list) and ghidra_export:
            seen_functions = set()

            for fn in ghidra_export:
                name = str(fn.get("name", ""))
                address = fn.get("address") or fn.get("addr") or fn.get("entry_point")
                function_size = fn.get("size") or fn.get("length")
                disasm = fn.get("disasm", "") or fn.get("disassembly", "")
                func_hash = fn.get("function_hash") or fn.get("id")

                if not disasm or not name:
                    continue

                # Avoid duplicate analysis
                if (name, address) in seen_functions:
                    continue
                seen_functions.add((name, address))

                patterns, confidence = _analyze_disassembly_patterns(disasm, name)

                # Only report if we have meaningful confidence
                if confidence >= 0.15:
                    total_patterns = sum(patterns.values())

                    # Build evidence snippet
                    evidence_parts = []
                    for op, count in sorted(patterns.items(), key=lambda x: -x[1]):
                        if count > 0:
                            evidence_parts.append(f"{op}:{count}")

                    fid = _make_id("instr-pattern", f"{name}-{address}-{total_patterns}")

                    finding = {
                        "id": fid,
                        "type": "instruction_pattern",
                        "name": f"crypto_pattern_{name}",
                        "confidence": confidence,
                        "reason_tags": ["instruction_analysis", "bitwise_ops"],
                        "evidence": {
                            "function_name": name,
                            "function_hash": func_hash,
                            "pattern_counts": patterns,
                            "total_instructions": len(disasm.split('\n')),
                            "pattern_summary": ", ".join(evidence_parts[:5]),
                        },
                    }

                    # Extract location data
                    additional_data = {}
                    if address or function_size:
                        try:
                            if address:
                                # Convert address to hex and create address range
                                if isinstance(address, str):
                                    if address.startswith("0x") or address.startswith("0X"):
                                        addr_int = int(address, 16)
                                    else:
                                        addr_int = int(address)
                                else:
                                    addr_int = int(address)

                                start_hex = hex(addr_int)
                                if function_size:
                                    try:
                                        size_int = int(function_size) if isinstance(function_size, str) else function_size
                                        end_hex = hex(addr_int + size_int)
                                    except (ValueError, TypeError):
                                        end_hex = start_hex
                                else:
                                    end_hex = start_hex

                                additional_data["address_or_range"] = {
                                    "start": start_hex,
                                    "end": end_hex,
                                }
                                if function_size:
                                    additional_data["address_or_range"]["size"] = function_size

                                # Map to section
                                section = _get_section_for_offset(sections_data, addr_int)
                                if section != "unknown":
                                    additional_data["section"] = section
                        except (ValueError, TypeError):
                            pass

                    # Add function name
                    if name and name not in ["", "Unknown"]:
                        additional_data["function_name"] = name

                    if additional_data:
                        finding["additional_data"] = additional_data

                    # Enhanced evidence snippet
                    snippet_lines = []
                    snippet_lines.append(f"Function: {name}")
                    snippet_lines.append(f"Patterns: {', '.join(evidence_parts[:5])}")
                    if patterns['xor'] > 3:
                        snippet_lines.append(f"⚠️ High XOR count: {patterns['xor']} (key mixing indicator)")
                    if patterns['rol'] + patterns['ror'] > 2:
                        snippet_lines.append(f"🔄 Rotations: {patterns['rol'] + patterns['ror']} (cipher rounds indicator)")

                    finding["evidence_snippet"] = "; ".join(snippet_lines)
                    findings.append(finding)

    except Exception as e:
        # Fail softly - continue to entropy analysis
        pass
    
    # PART 2: Entropy-based detection (high entropy = potential crypto/obfuscation)
    if static_artifacts:
        ent_path = static_artifacts.get("entropy_map.json")
        if ent_path:
            try:
                with open(ent_path, "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
                entmap = doc.get("entropy_map", [])
                
                # Detect high-entropy regions (potential crypto primitives)
                high_entropy_regions = []
                for e in entmap:
                    ent = e.get("entropy", 0.0)
                    off = e.get("offset")
                    
                    # High entropy thresholds:
                    # 7.8+ = Very high (crypto tables, compressed data)
                    # 7.5+ = High (possible crypto code)
                    # 7.0+ = Elevated (worth noting)
                    if ent >= 7.0:
                        high_entropy_regions.append((off, ent))
                
                # Cluster nearby high-entropy regions
                clustered = _cluster_entropy_regions(high_entropy_regions)
                
                for cluster_start, cluster_end, max_entropy, avg_entropy in clustered:
                    # Higher confidence for sustained high entropy
                    if avg_entropy >= 7.8:
                        confidence = 0.75
                        risk = "very_high_entropy"
                    elif avg_entropy >= 7.5:
                        confidence = 0.65
                        risk = "high_entropy"
                    else:
                        confidence = 0.45
                        risk = "elevated_entropy"

                    fid = _make_id("entropy", f"{cluster_start}:{cluster_end}:{avg_entropy}")

                    finding = {
                        "id": fid,
                        "type": "high_entropy_region",
                        "name": "entropy_region",
                        "confidence": confidence,
                        "reason_tags": ["entropy", risk],
                        "evidence_snippet": f"Offset 0x{cluster_start:x}-0x{cluster_end:x}: avg_entropy={avg_entropy:.2f}, max={max_entropy:.2f}",
                        "address_or_range": {
                            "start": hex(cluster_start),
                            "end": hex(cluster_end)
                        },
                        "evidence": {
                            "offset_start": cluster_start,
                            "offset_end": cluster_end,
                            "avg_entropy": round(avg_entropy, 3),
                            "max_entropy": round(max_entropy, 3),
                        }
                    }

                    # Extract location data
                    additional_data = {}

                    # Map to section
                    section = _get_section_for_offset(sections_data, cluster_start)
                    if section != "unknown":
                        additional_data["section"] = section

                    # Try to find containing function
                    if isinstance(ghidra_export, list):
                        func_name = _find_containing_function(ghidra_export, cluster_start)
                        if func_name != "unknown":
                            additional_data["function_name"] = func_name

                    if additional_data:
                        finding["additional_data"] = additional_data

                    findings.append(finding)
            
            except Exception:
                pass
    
    return findings


def _cluster_entropy_regions(regions: List[Tuple[int, float]], max_gap: int = 512) -> List[Tuple[int, int, float, float]]:
    """Cluster nearby high-entropy regions together.
    
    Returns: List of (start_offset, end_offset, max_entropy, avg_entropy)
    """
    if not regions:
        return []
    
    # Sort by offset
    regions = sorted(regions, key=lambda x: x[0])
    
    clusters = []
    current_cluster = [regions[0]]
    
    for i in range(1, len(regions)):
        offset, entropy = regions[i]
        prev_offset, _ = current_cluster[-1]
        
        # If within max_gap, add to current cluster
        if offset - prev_offset <= max_gap:
            current_cluster.append((offset, entropy))
        else:
            # Finalize current cluster
            clusters.append(_finalize_cluster(current_cluster))
            current_cluster = [(offset, entropy)]
    
    # Don't forget the last cluster
    if current_cluster:
        clusters.append(_finalize_cluster(current_cluster))
    
    return clusters


def _finalize_cluster(cluster: List[Tuple[int, float]]) -> Tuple[int, int, float, float]:
    """Convert cluster of (offset, entropy) to summary."""
    start = cluster[0][0]
    end = cluster[-1][0]
    entropies = [e for _, e in cluster]
    return (start, end, max(entropies), sum(entropies) / len(entropies))
