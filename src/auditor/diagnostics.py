"""Comprehensive diagnostics module for debugging analysis pipeline.

This module provides centralized diagnostic tracking, timing measurements,
file availability validation, and detailed reporting capabilities to help
identify bottlenecks and data flow issues.
"""

import time
import os
import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class DiagnosticTracker:
    """Tracks timing, file availability, and diagnostic events throughout the pipeline."""

    def __init__(self):
        self.start_time = time.time()
        self.events: List[Dict[str, Any]] = []
        self.stages: Dict[str, Dict[str, Any]] = {}
        self.file_checks: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []

    def log_stage_start(self, stage_name: str, description: str = "") -> None:
        """Mark the start of a pipeline stage."""
        self.stages[stage_name] = {
            "name": stage_name,
            "description": description,
            "start_time": time.time(),
            "end_time": None,
            "duration": None,
            "status": "running"
        }
        self.log_event("stage_start", stage_name, description)
        logger.debug(f"[DIAGNOSTIC] Stage '{stage_name}' started: {description}")

    def log_stage_end(self, stage_name: str, status: str = "completed", details: str = "") -> None:
        """Mark the end of a pipeline stage."""
        if stage_name not in self.stages:
            logger.warning(f"[DIAGNOSTIC] Attempted to end stage '{stage_name}' that was never started")
            return

        stage = self.stages[stage_name]
        stage["end_time"] = time.time()
        stage["duration"] = stage["end_time"] - stage["start_time"]
        stage["status"] = status
        stage["details"] = details

        self.log_event("stage_end", stage_name, f"{status} ({stage['duration']:.2f}s) {details}")
        logger.debug(f"[DIAGNOSTIC] Stage '{stage_name}' ended: {status} in {stage['duration']:.2f}s")

    def log_heuristic_timing(self, heuristic_name: str, duration: float, status: str = "completed") -> None:
        """Log execution timing for a specific heuristic."""
        self.log_event("heuristic_timing", heuristic_name, f"{status} in {duration:.2f}s")
        if duration > 25.0:  # Warning if close to 30s timeout
            msg = f"Heuristic '{heuristic_name}' took {duration:.2f}s (approaching 30s timeout)"
            self.warnings.append(msg)
            logger.warning(f"[DIAGNOSTIC] {msg}")

    def validate_file_exists(self, file_path: str, label: str = "", fail_if_missing: bool = False) -> bool:
        """Check if a file exists and log the result."""
        exists = os.path.isfile(file_path)
        check_record = {
            "label": label,
            "path": file_path,
            "exists": exists,
            "timestamp": datetime.now().isoformat()
        }

        if exists:
            try:
                size = os.path.getsize(file_path)
                check_record["size_bytes"] = size
                logger.debug(f"[DIAGNOSTIC] File OK: {label} ({size} bytes)")
            except Exception as e:
                check_record["error"] = str(e)
                logger.warning(f"[DIAGNOSTIC] Could not get file size for {label}: {e}")
        else:
            logger.warning(f"[DIAGNOSTIC] File MISSING: {label} at {file_path}")
            if fail_if_missing:
                msg = f"Critical file missing: {label} at {file_path}"
                self.errors.append(msg)
            else:
                msg = f"File missing: {label} at {file_path}"
                self.warnings.append(msg)

        self.file_checks.append(check_record)
        return exists

    def validate_directory_exists(self, dir_path: str, label: str = "", fail_if_missing: bool = False) -> bool:
        """Check if a directory exists and log the result."""
        exists = os.path.isdir(dir_path)
        check_record = {
            "label": label,
            "path": dir_path,
            "is_directory": exists,
            "timestamp": datetime.now().isoformat()
        }

        if exists:
            try:
                entries = len(os.listdir(dir_path))
                check_record["entries"] = entries
                logger.debug(f"[DIAGNOSTIC] Directory OK: {label} ({entries} entries)")
            except Exception as e:
                check_record["error"] = str(e)
                logger.warning(f"[DIAGNOSTIC] Could not list directory {label}: {e}")
        else:
            logger.warning(f"[DIAGNOSTIC] Directory MISSING: {label} at {dir_path}")
            if fail_if_missing:
                msg = f"Critical directory missing: {label} at {dir_path}"
                self.errors.append(msg)
            else:
                msg = f"Directory missing: {label} at {dir_path}"
                self.warnings.append(msg)

        self.file_checks.append(check_record)
        return exists

    def validate_pipeline_transition(self, from_stage: str, to_stage: str,
                                    required_files: Dict[str, str]) -> bool:
        """Validate that all required files exist for a pipeline transition."""
        self.log_event("transition_check", f"{from_stage} → {to_stage}",
                      f"Checking {len(required_files)} files")

        all_exist = True
        for label, path in required_files.items():
            exists = self.validate_file_exists(path, label=f"{from_stage}→{to_stage}:{label}",
                                             fail_if_missing=False)
            if not exists:
                all_exist = False

        if all_exist:
            logger.info(f"[DIAGNOSTIC] ✓ All files available for {from_stage} → {to_stage}")
        else:
            msg = f"⚠ Missing files for {from_stage} → {to_stage}"
            self.warnings.append(msg)
            logger.warning(f"[DIAGNOSTIC] {msg}")

        return all_exist

    def log_event(self, event_type: str, component: str, message: str) -> None:
        """Log a generic diagnostic event."""
        event = {
            "timestamp": time.time(),
            "elapsed_sec": time.time() - self.start_time,
            "type": event_type,
            "component": component,
            "message": message
        }
        self.events.append(event)

    def log_warning(self, message: str) -> None:
        """Log a warning."""
        self.warnings.append(message)
        logger.warning(f"[DIAGNOSTIC] ⚠ {message}")

    def log_error(self, message: str) -> None:
        """Log an error."""
        self.errors.append(message)
        logger.error(f"[DIAGNOSTIC] ✗ {message}")

    def get_summary(self) -> Dict[str, Any]:
        """Generate a diagnostic summary."""
        total_elapsed = time.time() - self.start_time

        stage_timings = []
        for stage_name, stage_info in self.stages.items():
            if stage_info["duration"] is not None:
                stage_timings.append({
                    "stage": stage_name,
                    "duration_sec": stage_info["duration"],
                    "status": stage_info["status"]
                })

        return {
            "total_elapsed_sec": total_elapsed,
            "num_events": len(self.events),
            "num_file_checks": len(self.file_checks),
            "num_warnings": len(self.warnings),
            "num_errors": len(self.errors),
            "stages": stage_timings,
            "warnings": self.warnings[:10],  # First 10 warnings
            "errors": self.errors[:10],      # First 10 errors
        }

    def generate_report(self, output_path: Optional[str] = None) -> str:
        """Generate a comprehensive diagnostic report."""
        report_lines = [
            "=" * 80,
            "DIAGNOSTIC REPORT",
            "=" * 80,
            f"Generated: {datetime.now().isoformat()}",
            f"Total elapsed time: {time.time() - self.start_time:.2f}s",
            "",
        ]

        # Stage summary
        report_lines.extend([
            "PIPELINE STAGES:",
            "-" * 80,
        ])
        for stage_name, stage_info in sorted(self.stages.items(),
                                            key=lambda x: x[1]["start_time"]):
            if stage_info["duration"] is not None:
                report_lines.append(
                    f"  {stage_name:30s} | {stage_info['status']:10s} | {stage_info['duration']:7.2f}s"
                )
                if stage_info.get("details"):
                    report_lines.append(f"    └─ {stage_info['details']}")
            else:
                report_lines.append(f"  {stage_name:30s} | (ongoing)")

        # File checks
        report_lines.extend([
            "",
            "FILE AVAILABILITY CHECKS:",
            "-" * 80,
        ])
        for check in self.file_checks:
            status = "✓" if check.get("exists") or check.get("is_directory") else "✗"
            size_info = f" ({check.get('size_bytes', 0)} bytes)" if check.get("size_bytes") else ""
            report_lines.append(f"  {status} {check['label']:40s} {size_info}")
            if not (check.get("exists") or check.get("is_directory")):
                report_lines.append(f"      → {check['path']}")

        # Warnings
        if self.warnings:
            report_lines.extend([
                "",
                f"WARNINGS ({len(self.warnings)}):",
                "-" * 80,
            ])
            for warning in self.warnings[:20]:
                report_lines.append(f"  ⚠ {warning}")

        # Errors
        if self.errors:
            report_lines.extend([
                "",
                f"ERRORS ({len(self.errors)}):",
                "-" * 80,
            ])
            for error in self.errors[:20]:
                report_lines.append(f"  ✗ {error}")

        # Heuristic timing summary
        heuristic_events = [e for e in self.events if e["type"] == "heuristic_timing"]
        if heuristic_events:
            report_lines.extend([
                "",
                "HEURISTIC TIMINGS:",
                "-" * 80,
            ])
            for event in heuristic_events:
                report_lines.append(f"  {event['component']:30s} | {event['message']}")

        report_lines.extend([
            "",
            "=" * 80,
        ])

        report_text = "\n".join(report_lines)

        if output_path:
            try:
                with open(output_path, "w") as f:
                    f.write(report_text)
                logger.info(f"[DIAGNOSTIC] Report saved to {output_path}")
            except Exception as e:
                logger.error(f"[DIAGNOSTIC] Failed to save report: {e}")

        return report_text

    def save_json_report(self, output_path: str) -> None:
        """Save diagnostic data as JSON for programmatic analysis."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "total_elapsed_sec": time.time() - self.start_time,
            "stages": self.stages,
            "file_checks": self.file_checks,
            "warnings": self.warnings,
            "errors": self.errors,
            "events_count": len(self.events),
            "summary": self.get_summary(),
        }

        try:
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"[DIAGNOSTIC] JSON report saved to {output_path}")
        except Exception as e:
            logger.error(f"[DIAGNOSTIC] Failed to save JSON report: {e}")


# Global singleton for use throughout the pipeline
_global_tracker: Optional[DiagnosticTracker] = None


def get_tracker() -> DiagnosticTracker:
    """Get or create the global diagnostic tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = DiagnosticTracker()
    return _global_tracker


def reset_tracker() -> None:
    """Reset the global diagnostic tracker (useful for multiple runs)."""
    global _global_tracker
    _global_tracker = None


def create_new_tracker() -> DiagnosticTracker:
    """Create a new tracker instance (useful for per-run diagnostics)."""
    return DiagnosticTracker()
