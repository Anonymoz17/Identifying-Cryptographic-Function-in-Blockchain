"""
File type validation for dynamic detection.

Checks if a case is suitable for dynamic analysis before running.
Specifically detects source code files that won't work with Frida.
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# File types that are source code (not executable binaries)
SOURCE_CODE_TYPES = {
    'python', 'c', 'cpp', 'c++', 'cxx', 
    'java', 'javascript', 'ts', 'typescript',
    'go', 'rust', 'csharp', 'c#', 'vb', 'vb.net',
    'ruby', 'php', 'swift', 'kotlin',
    'source', 'text', 'script', 'code',
    'sql', 'html', 'xml', 'json', 'yaml', 'yml'
}

# File types that are executable binaries
BINARY_TYPES = {
    'executable', 'pe32', 'pe64', 'elf', 'mach-o',
    'binary', 'dll', 'so', 'dylib', 'exe',
    'windows', 'x86', 'x64', 'arm', 'arm64'
}


class FileTypeAnalysis:
    """Results of file type analysis for a case."""
    
    def __init__(self):
        self.total_files = 0
        self.source_files = 0
        self.binary_files = 0
        self.unknown_files = 0
        self.file_types: Dict[str, int] = {}
        self.is_suitable_for_dynamic = False
        self.warnings: List[str] = []
        self.recommendations: List[str] = []
    
    def source_code_ratio(self) -> float:
        """Get percentage of source code files."""
        if self.total_files == 0:
            return 0.0
        return (self.source_files / self.total_files) * 100
    
    def summary(self) -> str:
        """Get human-readable summary."""
        lines = [
            f"Total files: {self.total_files}",
            f"Source code: {self.source_files} ({self.source_code_ratio():.0f}%)",
            f"Binaries: {self.binary_files}",
            f"Unknown: {self.unknown_files}",
        ]
        return "\n".join(lines)


def analyze_case_file_types(workdir: str) -> FileTypeAnalysis:
    """
    Analyze what types of files are in a case.
    
    Args:
        workdir: Path to case workspace
    
    Returns:
        FileTypeAnalysis with results
    """
    result = FileTypeAnalysis()
    workdir_path = Path(workdir)
    preproc_dir = workdir_path / "preproc"
    
    if not preproc_dir.exists():
        result.warnings.append("Preproc directory not found")
        return result
    
    # Scan all files
    for hash_dir in preproc_dir.iterdir():
        if not hash_dir.is_dir():
            continue
        
        metadata_path = hash_dir / "metadata.json"
        if not metadata_path.exists():
            result.unknown_files += 1
            result.total_files += 1
            continue
        
        try:
            with open(metadata_path) as f:
                meta = json.load(f)
            
            file_type = meta.get('file_type', 'unknown').lower().strip()
            result.file_types[file_type] = result.file_types.get(file_type, 0) + 1
            result.total_files += 1
            
            # Classify file type
            if any(st in file_type for st in SOURCE_CODE_TYPES):
                result.source_files += 1
            elif any(bt in file_type for bt in BINARY_TYPES):
                result.binary_files += 1
            else:
                result.unknown_files += 1
        
        except Exception:
            result.unknown_files += 1
            result.total_files += 1
    
    # Generate analysis
    result.is_suitable_for_dynamic = result.source_files == 0 or result.binary_files > result.source_files
    
    if result.source_files > 0:
        result.warnings.append(
            f"{result.source_files} source code files detected. "
            f"Dynamic analysis requires compiled binaries."
        )
        result.recommendations.append(
            "Use Static Analysis instead (already works with source code)"
        )
        result.recommendations.append(
            "Or compile source code to binaries (.exe/.dll) first"
        )
    
    if result.binary_files == 0 and result.source_files > 0:
        result.recommendations.append(
            "⚠️ Dynamic analysis will find NO crypto calls on source code"
        )
    
    return result


def validate_file_for_dynamic_analysis(file_type: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a single file type is suitable for dynamic analysis.
    
    Args:
        file_type: The file type from metadata.json
    
    Returns:
        Tuple of (is_suitable, reason)
    """
    file_type_lower = file_type.lower().strip()
    
    # Check if source code
    if any(st in file_type_lower for st in SOURCE_CODE_TYPES):
        return (False, f"Source code file ({file_type}). Compile to binary first.")
    
    # Check if binary
    if any(bt in file_type_lower for bt in BINARY_TYPES):
        return (True, None)
    
    # Unknown - assume binary-ish
    return (True, f"Unknown type ({file_type}), assuming binary")


def get_recommendations(analysis: FileTypeAnalysis) -> str:
    """Get formatted recommendations."""
    if not analysis.recommendations:
        return "✓ Case is suitable for dynamic analysis"
    
    lines = ["Recommendations:"]
    for i, rec in enumerate(analysis.recommendations, 1):
        lines.append(f"  {i}. {rec}")
    return "\n".join(lines)


def should_run_dynamic_analysis(workdir: str) -> Tuple[bool, str]:
    """
    Determine if dynamic analysis should run for a case.
    
    Args:
        workdir: Path to case workspace
    
    Returns:
        Tuple of (should_run, message)
    """
    analysis = analyze_case_file_types(workdir)
    
    if analysis.total_files == 0:
        return (False, "No files found in preproc directory")
    
    # If all are source code, should not run
    if analysis.source_files == analysis.total_files:
        msg = (
            f"All {analysis.total_files} files are source code. "
            "Dynamic analysis requires compiled binaries. "
            "Use Static Analysis instead."
        )
        return (False, msg)
    
    # If mostly source code, warn but allow
    if analysis.source_code_ratio() > 80:
        msg = (
            f"⚠️ {analysis.source_code_ratio():.0f}% of files are source code. "
            "These will show 0 crypto calls in dynamic analysis. "
            "Continue anyway? (Run static analysis for these files)"
        )
        return (True, msg)  # Allow but warn
    
    # Mixed or mostly binaries - OK
    return (True, "Case is suitable for dynamic analysis")


def format_file_type_report(workdir: str) -> str:
    """
    Generate a detailed file type report.
    
    Args:
        workdir: Path to case workspace
    
    Returns:
        Formatted report string
    """
    analysis = analyze_case_file_types(workdir)
    
    lines = [
        "╔" + "═"*78 + "╗",
        "║" + "FILE TYPE ANALYSIS REPORT".center(78) + "║",
        "╚" + "═"*78 + "╝",
        "",
        analysis.summary(),
        "",
        "Files by type:",
    ]
    
    for file_type, count in sorted(analysis.file_types.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  • {file_type}: {count}")
    
    if analysis.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in analysis.warnings:
            lines.append(f"  ⚠️ {warning}")
    
    if analysis.recommendations:
        lines.append("")
        lines.append("Recommendations:")
        for rec in analysis.recommendations:
            lines.append(f"  → {rec}")
    
    if analysis.is_suitable_for_dynamic:
        lines.append("")
        lines.append("✓ Suitable for dynamic analysis")
    else:
        lines.append("")
        lines.append("✗ NOT suitable for dynamic analysis (source code)")
    
    return "\n".join(lines)


# Convenience functions

def quick_check(workdir: str) -> bool:
    """Quick check: is case suitable for dynamic analysis?"""
    should_run, _ = should_run_dynamic_analysis(workdir)
    return should_run


def print_file_type_report(workdir: str):
    """Print formatted report to console."""
    print(format_file_type_report(workdir))
