"""
Dynamic detection runner - main orchestrator for Frida-based analysis.

This module implements the main DynamicRunner class that orchestrates
all components of the dynamic analysis pipeline.

Pattern: Pipeline orchestration (same as StaticRunner)
Error Handling: Never throws - returns DynamicResult with errors list
"""

import os
import sys
import time
from typing import Optional
from datetime import datetime

# Context and configuration
from .context import DynamicContext, DynamicResult, ToolVersions
from .config import Config
from . import cache
from . import hints_adapter
from . import sandbox
from . import input_feeder
from . import frida_scripter
from . import frida_harness
from . import trace_manager
from . import traces_sanitizer
from . import results_packager
from . import quota_manager
from . import retention_manager
from . import resilience
from . import performance
from . import file_type_validator


class DynamicRunner:
    """
    Main orchestrator for dynamic analysis runs.

    Follows the same pattern as StaticRunner for consistency.
    Coordinates all stages of dynamic analysis:
    1. License validation
    2. Hints loading
    3. Cache checking
    4. Sandbox setup
    5. Frida instrumentation
    6. Trace collection
    7. Sanitization
    8. Results packaging

    Usage:
        runner = DynamicRunner()
        ctx = DynamicContext(...)
        result = runner.run(ctx)

        if result.is_success():
            print(f"Analysis complete: {result.dynamic_results_path}")
        else:
            print(f"Errors: {result.errors}")
    """

    def __init__(self):
        """Initialize runner."""
        self._frida_available = self._check_frida_available()

    def _check_frida_available(self) -> bool:
        """Check if Frida is available."""
        try:
            import frida
            return True
        except ImportError:
            return False

    def _check_license(self) -> tuple[bool, Optional[str]]:
        """
        Check if dynamic analysis is licensed.

        Returns:
            Tuple of (is_licensed, error_message)
        """
        # TODO: Implement proper license checking
        # For now, assume always available (remove in production)
        # Expected: license.has_feature('dynamic')
        return (True, None)

        # Placeholder for real implementation:
        # try:
        #     from src.licensing import license_manager
        #     if not license_manager.has_feature('dynamic'):
        #         return (False, "Dynamic analysis requires premium license")
        #     return (True, None)
        # except ImportError:
        #     return (False, "License manager not available")

    def run(self, ctx: DynamicContext) -> DynamicResult:
        """
        Run dynamic analysis on a binary.

        This is the main entry point. It orchestrates all stages
        and always returns a result (never throws).

        Args:
            ctx: Dynamic analysis context

        Returns:
            DynamicResult with paths, summary, and any errors
        """
        result = DynamicResult(file_hash=ctx.file_hash)
        start_time = time.time()

        try:
            # Stage 0: Pre-flight checks
            print(f"[Runner] Starting dynamic analysis for {ctx.file_hash}")
            print(f"[Runner] Mode: {ctx.mode}, Timeout: {ctx.timeout}s")

            result = self._preflight_checks(ctx, result)
            if result.errors:
                print(f"[Runner] Pre-flight checks failed: {result.errors}")
                return result

            # Stage 1: Setup
            print("[Runner] Stage 1: Loading configuration and hints...")
            config, hints_data, analysis_dir = self._setup(ctx, result)
            if hints_data is None or result.errors:
                print(f"[Runner] Setup failed: {result.errors}")
                return result

            print(f"[Runner] Loaded {len(hints_data.get('hints', []))} hints from static analysis")

            # Stage 2: Check cache
            print("[Runner] Stage 2: Checking cache...")
            if cache.should_use_cache(ctx, analysis_dir):
                print("[Runner] Cache hit! Loading cached results")
                return self._load_cached_result(ctx, analysis_dir, result)

            print("[Runner] Cache miss, running full analysis")

            # Stage 3: Setup sandbox
            print("[Runner] Stage 3: Setting up sandbox...")
            sand = self._setup_sandbox(ctx, config)
            if sand.temp_dir:
                print(f"[Runner] Sandbox created: {sand.temp_dir}")

            # Stage 4: Prepare input configuration
            print("[Runner] Stage 4: Preparing input...")
            input_config = self._prepare_input(ctx, config, sand.temp_dir)
            if input_config.has_args() or input_config.has_input_file():
                print(f"[Runner] Input config: {input_feeder.get_input_summary(input_config)}")

            # Stage 5: Generate Frida hooks
            print("[Runner] Stage 5: Generating Frida hooks...")
            hooks = self._generate_hooks(hints_data, config)
            print(f"[Runner] Generated {len(hooks)} JavaScript hook scripts")

            # Stage 6: Create trace manager
            print("[Runner] Stage 6: Initializing trace manager...")
            trace_mgr = self._create_trace_manager(config)
            print(f"[Runner] Trace limits: {trace_mgr.max_events} events, {trace_mgr.max_crypto_calls} crypto calls")

            # Stage 7: Run Frida harness
            print("[Runner] Stage 7: Running Frida instrumentation...")
            binary_path = os.path.join(ctx.preproc_dir, 'input.bin')

            try:
                trace_collection = self._run_harness(
                    ctx,
                    binary_path,
                    hooks,
                    sand,
                    input_config,
                    trace_mgr
                )

                print(f"[Runner] Collected {trace_collection.get_event_count()} events")

                # Check if incomplete
                if trace_collection.is_incomplete():
                    result.incomplete = True
                    result.incomplete_reason = trace_collection.get_incomplete_reason()
                    print(f"[Runner] Analysis incomplete: {result.incomplete_reason}")

            finally:
                # Always cleanup sandbox
                print("[Runner] Cleaning up sandbox...")
                sand.cleanup()

            # Stage 8: Sanitize traces
            print("[Runner] Stage 8: Sanitizing traces...")
            sanitized_events, violations = self._sanitize_traces(trace_mgr.get_events())

            if violations:
                print(f"[Runner] Warning: {len(violations)} sanitization violations detected")
                for violation in violations[:5]:  # Show first 5
                    print(f"[Runner]   - {violation}")

            # Update trace manager with sanitized events
            trace_mgr.events = sanitized_events

            # Stage 9: Package results
            print("[Runner] Stage 9: Packaging results...")
            execution_time = time.time() - start_time

            result = self._package_results(
                ctx,
                trace_mgr,
                hints_data,
                analysis_dir,
                execution_time,
                result.incomplete,
                result.incomplete_reason
            )

            print(f"[Runner] Results written to {analysis_dir}")

            # Stage 10: Write cache metadata
            print("[Runner] Stage 10: Writing cache metadata...")
            self._write_cache(ctx, analysis_dir, result)

            print(f"[Runner] Dynamic analysis complete in {execution_time:.2f}s")
            return result

        except Exception as e:
            print(f"[Runner] Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            result.add_error(f"Unexpected error in dynamic analysis: {e}")
            return result

    def _preflight_checks(self, ctx: DynamicContext, result: DynamicResult) -> DynamicResult:
        """
        Pre-flight checks before analysis.

        Checks:
        1. License validation
        2. Frida availability
        3. Binary exists
        4. File type compatibility (source code vs binary)
        5. Quota limits (if enabled)

        Args:
            ctx: Context
            result: Result to populate

        Returns:
            Updated result
        """
        # Check license
        is_licensed, license_error = self._check_license()
        if not is_licensed:
            result.add_error(license_error or "Dynamic analysis not licensed")
            return result

        # Check Frida available
        if not self._frida_available:
            result.add_error("Frida not available. Install with: pip install frida-tools")
            return result

        # Check binary exists
        binary_path = os.path.join(ctx.preproc_dir, 'input.bin')
        if not os.path.exists(binary_path):
            result.add_error(f"Binary not found: {binary_path}")
            return result
        
        # Check file type (NEW: validate it's not source code)
        try:
            metadata_path = os.path.join(ctx.preproc_dir, 'metadata.json')
            if os.path.exists(metadata_path):
                import json
                with open(metadata_path) as f:
                    meta = json.load(f)
                
                file_type = meta.get('file_type', 'unknown')
                is_suitable, reason = file_type_validator.validate_file_for_dynamic_analysis(file_type)
                
                if not is_suitable:
                    result.add_error(
                        f"File type not suitable for dynamic analysis: {reason}\n"
                        f"Hint: Use Static Analysis for source code files instead."
                    )
                    return result
                
                if reason:
                    print(f"[Runner] File type check: {reason}")
        
        except Exception as e:
            print(f"[Runner] Warning: Could not validate file type: {e}")
        
        # Check quota limits (if user_id provided in context)
        if hasattr(ctx, 'user_id') and ctx.user_id:
            try:
                qm = quota_manager.QuotaManager(ctx.analysis_base)
                quota_status = qm.check_quota(ctx.user_id, ctx.file_hash)
                
                if not quota_status['allowed']:
                    violations = quota_status.get('violations', [])
                    result.add_error(f"Quota exceeded: {'; '.join(violations)}")
                    return result
                
                print(f"[Runner] Quota check passed for user {ctx.user_id}")
                
            except quota_manager.QuotaExceededError as e:
                result.add_error(str(e))
                return result
            except Exception as e:
                # Don't fail analysis if quota check has issues
                print(f"[Runner] Warning: Quota check failed: {e}")

        # Update Frida version
        if self._frida_available:
            try:
                import frida
                ctx.tool_versions.frida = frida.__version__
            except Exception:
                ctx.tool_versions.frida = "unknown"

        return result

    def _setup(self, ctx: DynamicContext, result: DynamicResult) -> tuple:
        """
        Setup stage - load config and hints.

        Args:
            ctx: Context
            result: Result to populate with errors

        Returns:
            Tuple of (config, hints_data, analysis_dir)
        """
        # Load configuration
        config = Config.load(preproc_dir=ctx.preproc_dir, config_path=ctx.config_path)

        # Load hints from static analysis
        try:
            hints_data = hints_adapter.load_hints(ctx.hints_path)
        except hints_adapter.HintsLoadError as e:
            result.add_error(f"Failed to load hints: {e}")
            result.add_error("Hint: Run static analysis first to generate hints.json")
            return (config, None, None)

        # Determine analysis directory
        analysis_dir = os.path.join(ctx.analysis_base, 'analysis', 'dynamic', ctx.file_hash)

        return (config, hints_data, analysis_dir)

    def _load_cached_result(self, ctx: DynamicContext, analysis_dir: str, result: DynamicResult) -> DynamicResult:
        """
        Load cached result.

        Args:
            ctx: Context
            analysis_dir: Analysis directory
            result: Result to populate

        Returns:
            Updated result with cached data
        """
        result.cached = True
        result.dynamic_results_path = os.path.join(analysis_dir, 'dynamic_results.json')
        result.trace_path = os.path.join(analysis_dir, 'trace.ndjson')

        # Load summary from results file
        try:
            import json
            with open(result.dynamic_results_path, 'r') as f:
                results_data = json.load(f)
                result.summary = results_data.get('summary', {})
                result.incomplete = results_data.get('incomplete', False)
                result.incomplete_reason = results_data.get('incomplete_reason')
        except Exception as e:
            result.add_error(f"Failed to load cached results: {e}")

        return result

    def _setup_sandbox(self, ctx: DynamicContext, config: Config) -> sandbox.Sandbox:
        """Setup Windows sandbox."""
        sand = sandbox.Sandbox(timeout=ctx.timeout, memory_limit=ctx.memory_limit)
        sand.setup()
        return sand

    def _prepare_input(self, ctx: DynamicContext, config: Config, sandbox_temp_dir: str) -> input_feeder.InputConfig:
        """Prepare input configuration."""
        return input_feeder.prepare_input(ctx.preproc_dir, config, sandbox_temp_dir)

    def _generate_hooks(self, hints_data: dict, config: Config) -> list:
        """Generate Frida hooks from hints."""
        return frida_scripter.generate_hooks(hints_data, config)

    def _create_trace_manager(self, config: Config) -> trace_manager.TraceManager:
        """Create trace manager with configured limits."""
        return trace_manager.TraceManager(
            max_events=config.get('max_trace_events', default=10000),
            max_size_mb=config.get('max_trace_size_mb', default=10),
            max_crypto_calls=config.get('max_crypto_calls', default=100)
        )

    def _run_harness(
        self,
        ctx: DynamicContext,
        binary_path: str,
        hooks: list,
        sand: sandbox.Sandbox,
        input_config: input_feeder.InputConfig,
        trace_mgr: trace_manager.TraceManager
    ) -> frida_harness.TraceCollection:
        """Run Frida harness and collect traces."""

        # Add network blocking script
        network_script = sand.get_network_blocking_script()
        all_scripts = [network_script] + hooks

        # Callback to add events to trace manager
        def on_message(event):
            trace_mgr.add_event(event)

        # Create harness
        harness = frida_harness.FridaHarness(
            mode=ctx.mode,
            timeout=ctx.timeout,
            attach_pid=ctx.attach_pid,
            on_message=on_message
        )

        # Run instrumentation
        trace_collection = harness.run(
            target=binary_path,
            scripts=all_scripts,
            sandbox=sand,
            input_config=input_config
        )

        return trace_collection

    def _sanitize_traces(self, events: list) -> tuple:
        """Sanitize traces to remove sensitive data."""
        return traces_sanitizer.sanitize_traces(events, strict=True)

    def _package_results(
        self,
        ctx: DynamicContext,
        trace_mgr: trace_manager.TraceManager,
        hints_data: dict,
        analysis_dir: str,
        execution_time: float,
        incomplete: bool,
        incomplete_reason: Optional[str]
    ) -> DynamicResult:
        """Package results into JSON files."""
        return results_packager.package_results(
            ctx,
            trace_mgr,
            hints_data,
            analysis_dir,
            execution_time,
            incomplete,
            incomplete_reason
        )

    def _write_cache(self, ctx: DynamicContext, analysis_dir: str, result: DynamicResult):
        """Write cache metadata."""
        cache.write_cache_meta(
            ctx,
            analysis_dir,
            incomplete=result.incomplete,
            incomplete_reason=result.incomplete_reason
        )


# Convenience function for simple usage
def run_dynamic_analysis(file_hash: str, preproc_dir: str, hints_path: str, analysis_base: str, **kwargs) -> DynamicResult:
    """
    Convenience function to run dynamic analysis.

    Args:
        file_hash: SHA256 hash of binary
        preproc_dir: Path to preprocessing directory
        hints_path: Path to hints.json
        analysis_base: Base analysis directory
        **kwargs: Additional context parameters (mode, timeout, etc.)

    Returns:
        DynamicResult

    Example:
        result = run_dynamic_analysis(
            file_hash="abc123",
            preproc_dir="/workdir/preproc/abc123",
            hints_path="/workdir/analysis/static/abc123/hints.json",
            analysis_base="/workdir",
            mode="spawn",
            timeout=500
        )
    """
    ctx = DynamicContext(
        file_hash=file_hash,
        preproc_dir=preproc_dir,
        hints_path=hints_path,
        analysis_base=analysis_base,
        **kwargs
    )

    runner = DynamicRunner()
    return runner.run(ctx)
