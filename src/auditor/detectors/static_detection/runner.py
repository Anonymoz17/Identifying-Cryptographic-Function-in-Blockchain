"""StaticRunner orchestrator (skeleton).

The real runner wires adapters, preproc, ghidra, heuristics, scoring, and
packaging. This is a small stub exposing the eventual run API.
"""
from typing import Any

from .context import RunContext, RunResult
from . import preproc_adapter
from . import static_preproc
from . import ghidra_adapter
from . import heuristics_manager
from . import scoring
from . import hints_generator
from . import results_packager
from . import cache

import os
import json
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Overall timeout for entire static detection pipeline (5 minutes default)
DEFAULT_PIPELINE_TIMEOUT = 300.0
# Per-stage timeouts (can be adjusted based on file size/complexity)
DEFAULT_PREPROC_TIMEOUT = 60.0
DEFAULT_HEURISTICS_TIMEOUT = 120.0


class StaticRunner:
    """Orchestrator for static detection runs.

    Public API: run(context: RunContext) -> RunResult
    """

    def __init__(self) -> None:
        # add dependencies or configuration here in future
        pass

    def run(self, ctx: RunContext) -> RunResult:
        """Run a static detection flow for the given RunContext.

        Orchestrates the complete static analysis pipeline:
        1. Resolves and validates preprocessed input
        2. Checks cache for previous results
        3. Generates static preprocessing artifacts
        4. Conditionally runs Ghidra binary analysis
        5. Executes heuristic detectors
        6. Scores and aggregates findings
        7. Generates hints and packages results

        Returns:
            RunResult with paths to generated artifacts and summary

        Raises:
            FileNotFoundError: If preprocessed input is not found
            ValueError: If input validation fails
            RuntimeError: If critical pipeline step fails
            TimeoutError: If pipeline exceeds timeout
        """
        # Prepare result container
        result = RunResult(file_hash="", cached=False, summary={}, errors=None)

        # Start overall pipeline timer
        pipeline_start = time.time()
        pipeline_timeout = getattr(ctx, "pipeline_timeout", DEFAULT_PIPELINE_TIMEOUT)

        try:
            # Resolve preproc directory according to the storage conventions in
            # `docs/analysis-storage.md`:
            # - `ctx.preproc_dir` may be the exact preproc case folder (e.g.
            #   /.../preproc/<file_hash>/ containing input.bin and metadata.json),
            #   or it may be the case root that contains a `preproc/` directory
            #   with one or more `<file_hash>` subfolders.
            # - Prefer an explicit `ctx.file_hash` when provided. If `ctx.file_hash`
            #   is not set and there is exactly one valid preproc/<hash>/ entry,
            #   auto-select it. If multiple exist, require the caller to supply
            #   `file_hash` to avoid ambiguity.
            # - If a case root was supplied and `ctx.analysis_base` is unset or
            #   '.', default `analysis_base` to the case root so analysis artifacts
            #   are written beside the case.
            preproc_arg = os.path.abspath(ctx.preproc_dir)
            preproc_dir_to_use = preproc_arg
            # If the provided path looks like a case root (contains 'preproc' subdir),
            # choose the specific preproc/<file_hash> folder. Preference order:
            # - if ctx.file_hash is set, use that
            # - if only one candidate directory under preproc/ contains input.bin, use it
            # - otherwise raise a helpful error asking for file_hash
            preproc_root = os.path.join(preproc_arg, "preproc")
            if os.path.isdir(preproc_root):
                # case-root style input
                if ctx.file_hash:
                    candidate = os.path.join(preproc_root, ctx.file_hash)
                    if not os.path.isdir(candidate):
                        raise FileNotFoundError(f"preproc for file_hash {ctx.file_hash} not found under {preproc_root}")
                    preproc_dir_to_use = candidate
                else:
                    # enumerate candidate subdirs that look like preproc dirs
                    candidates = []
                    for name in os.listdir(preproc_root):
                        p = os.path.join(preproc_root, name)
                        if os.path.isdir(p) and os.path.isfile(os.path.join(p, "input.bin")) and os.path.isfile(os.path.join(p, "metadata.json")):
                            candidates.append(p)
                    if len(candidates) == 1:
                        preproc_dir_to_use = candidates[0]
                    elif len(candidates) == 0:
                        raise FileNotFoundError(f"no preproc/<hash>/ directories with input.bin found under {preproc_root}")
                    else:
                        # multiple candidates — allow opt-in auto-selection of the
                        # most-recent preproc (by input.bin mtime) via
                        # RunContext.auto_select_latest. Otherwise require
                        # explicit file_hash to avoid surprising behavior.
                        if getattr(ctx, "auto_select_latest", False):
                            # pick candidate with newest input.bin mtime
                            def mtime_of(p):
                                ip = os.path.join(p, "input.bin")
                                try:
                                    return os.path.getmtime(ip)
                                except Exception:
                                    return 0

                            candidates.sort(key=mtime_of, reverse=True)
                            preproc_dir_to_use = candidates[0]
                        else:
                            hashes = [os.path.basename(c) for c in candidates]
                            raise ValueError(
                                f"multiple preproc cases found under {preproc_root}; please specify file_hash in RunContext.file_hash. Found: {hashes}"
                            )
                # if analysis_base wasn't explicitly provided, default it to the case root
                if not ctx.analysis_base or ctx.analysis_base == ".":
                    ctx.analysis_base = preproc_arg

            # Validate and load preproc artifacts
            preproc = preproc_adapter.load_preproc(preproc_dir_to_use)
            result.file_hash = preproc.file_hash

            # Determine analysis output directory: <analysis_base>/analysis/static/<file_hash>/
            analysis_dir = os.path.abspath(
                os.path.join(ctx.analysis_base, "analysis", "static", preproc.file_hash)
            )
            os.makedirs(analysis_dir, exist_ok=True)

            # Quick cache decision using cache helpers. This will evaluate
            # presence of `static_results.json`, `.cache_meta.json`, profile and
            # tool-version compatibility, and TTL. `cache.should_use_cache`
            # returns (bool, reason).
            static_results_path = os.path.join(analysis_dir, "static_results.json")
            hints_path = os.path.join(analysis_dir, "hints.json")
            use_cache, reason = cache.should_use_cache(analysis_dir, ctx)
            if use_cache:
                result.cached = True
                result.hints_path = hints_path if os.path.isfile(hints_path) else None
                result.static_results_path = static_results_path
                result.summary = {"note": f"reused cached static results ({reason})"}
                return result

            # Check overall timeout before expensive operations
            elapsed = time.time() - pipeline_start
            if elapsed > pipeline_timeout:
                raise TimeoutError(f"Static detection pipeline exceeded timeout ({elapsed:.1f}s > {pipeline_timeout}s)")

            # STAGE 1: Generate lightweight static preproc artifacts
            logger.info(f"[STAGE 1] Starting static preprocessing...")
            preproc_out = os.path.join(analysis_dir, "preproc")
            # Calculate per-stage timeout based on elapsed time
            remaining_time = pipeline_timeout - elapsed
            preproc_timeout = min(DEFAULT_PREPROC_TIMEOUT, max(10.0, remaining_time * 0.2))  # Use 20% of remaining time, minimum 10s
            logger.info(f"[STAGE 1] timeout={preproc_timeout:.1f}s, remaining={remaining_time:.1f}s")

            stage1_start = time.time()
            try:
                static_artifacts = static_preproc.generate_static_preproc(
                    preproc_dir=preproc_dir_to_use,
                    out_dir=preproc_out,
                    profile=ctx.profile,
                    timeout_sec=preproc_timeout
                )
                stage1_elapsed = time.time() - stage1_start
                logger.info(f"[STAGE 1] Completed in {stage1_elapsed:.2f}s")
            except Exception as e:
                stage1_elapsed = time.time() - stage1_start
                logger.error(f"[STAGE 1] FAILED after {stage1_elapsed:.2f}s: {type(e).__name__}: {e}", exc_info=True)
                raise

            # Add preproc and binary paths to static_artifacts for location enrichment
            static_artifacts["__preproc_dir__"] = preproc_dir_to_use
            static_artifacts["__input_path__"] = preproc.input_path
            logger.debug(f"[STAGE 1] Static artifacts enriched with paths")

            # STAGE 2: Ghidra export
            logger.info(f"[STAGE 2] Starting Ghidra analysis decision...")
            ghidra_out = os.path.join(analysis_dir, "ghidra-export")

            # Check if Ghidra should run based on policy and file type/size
            from . import ghidra_policy, config

            # Get the configured policy: 'auto' (default), 'always', or 'never'
            policy = config.get_ghidra_run_policy()
            logger.info(f"[STAGE 2] Ghidra policy: {policy}")

            if policy == "never":
                should_run = False
                reason = "User policy: never run Ghidra"
            elif policy == "always":
                should_run = True
                reason = "User policy: always run Ghidra"
            else:  # policy == "auto"
                should_run, reason = ghidra_policy.should_run_ghidra(preproc.metadata)

            logger.info(f"[STAGE 2] Decision: should_run={should_run}, reason={reason}")
            ghidra_policy.log_ghidra_decision(preproc.file_hash, should_run, reason)

            ghidra_export_path = None
            ghidra_export = []

            if should_run:
                logger.info(f"[STAGE 2] Running Ghidra analysis...")
                stage2_start = time.time()
                try:
                    # Resolve Ghidra automatically (ctx.ghidra_options -> persisted -> env -> PATH)
                    resolved = ghidra_adapter.resolve_ghidra(getattr(ctx, "ghidra_options", {}) or {})
                    gh_opts = dict(getattr(ctx, "ghidra_options", {}) or {})
                    logger.debug(f"[STAGE 2] Ghidra resolved: {resolved}")
                    if resolved:
                        gh_opts.setdefault("install_dir", os.path.dirname(os.path.dirname(resolved)))
                        # annotate tool_versions if available
                        try:
                            ver = ghidra_adapter.verify_ghidra(resolved)
                            if ver:
                                ctx.tool_versions.ghidra = ver
                                logger.info(f"[STAGE 2] Ghidra version: {ver}")
                        except Exception as e:
                            logger.debug(f"[STAGE 2] Failed to get version: {e}")
                            pass
                    # propagate top-level runner force into ghidra adapter
                    gh_opts.setdefault("force", bool(getattr(ctx, "force", False)))

                    logger.info(f"[STAGE 2] Calling ensure_ghidra_export...")
                    ghidra_start = time.time()
                    ghidra_export_path = ghidra_adapter.ensure_ghidra_export(
                        preproc.input_path, ghidra_out, preproc.file_hash, options=gh_opts
                    )
                    ghidra_elapsed = time.time() - ghidra_start
                    logger.info(f"[STAGE 2] ensure_ghidra_export completed in {ghidra_elapsed:.2f}s, path={ghidra_export_path}")

                    logger.info(f"[STAGE 2] Reading Ghidra functions...")
                    ghidra_export = ghidra_adapter.read_ghidra_functions(ghidra_export_path)
                    logger.info(f"[STAGE 2] Read {len(ghidra_export)} functions from Ghidra")

                    stage2_elapsed = time.time() - stage2_start
                    logger.info(f"[STAGE 2] Completed in {stage2_elapsed:.2f}s")
                except Exception as e:
                    stage2_elapsed = time.time() - stage2_start
                    logger.error(f"[STAGE 2] FAILED after {stage2_elapsed:.2f}s: {type(e).__name__}: {e}", exc_info=True)
                    raise
            else:
                logger.info(f"[STAGE 2] Skipping Ghidra (reason: {reason})")
                # Create empty ghidra-export directory for consistency
                os.makedirs(ghidra_out, exist_ok=True)
                # Write a skip marker file explaining why Ghidra was skipped
                skip_marker = os.path.join(ghidra_out, "SKIPPED.txt")
                try:
                    with open(skip_marker, "w", encoding="utf-8") as f:
                        f.write(f"Ghidra analysis skipped\n")
                        f.write(f"Reason: {reason}\n")
                        f.write(f"File hash: {preproc.file_hash}\n")
                except Exception:
                    pass

            # Check timeout before heuristics
            elapsed = time.time() - pipeline_start
            if elapsed > pipeline_timeout:
                raise TimeoutError(f"Static detection pipeline exceeded timeout before heuristics ({elapsed:.1f}s > {pipeline_timeout}s)")

            # STAGE 3: Run heuristics
            logger.info(f"[STAGE 3] Loading heuristics...")
            # collect heuristic callables from heuristics package
            heuristics = []
            try:
                from .heuristics.signature import signature_heuristic
                heuristics.append(signature_heuristic)
                logger.debug(f"[STAGE 3] Loaded signature_heuristic")
            except Exception as e:
                logger.warning(f"[STAGE 3] Failed to load signature_heuristic: {e}")
                pass
            try:
                from .heuristics.instruction_patterns import instruction_patterns_heuristic
                heuristics.append(instruction_patterns_heuristic)
                logger.debug(f"[STAGE 3] Loaded instruction_patterns_heuristic")
            except Exception as e:
                logger.warning(f"[STAGE 3] Failed to load instruction_patterns_heuristic: {e}")
                pass
            try:
                from .heuristics.constants import constants_heuristic
                heuristics.append(constants_heuristic)
                logger.debug(f"[STAGE 3] Loaded constants_heuristic")
            except Exception as e:
                logger.warning(f"[STAGE 3] Failed to load constants_heuristic: {e}")
                pass

            logger.info(f"[STAGE 3] Loaded {len(heuristics)} heuristics: {[h.__name__ for h in heuristics]}")

            # Calculate heuristics timeout from remaining time
            remaining_time = pipeline_timeout - elapsed
            heuristics_timeout = min(DEFAULT_HEURISTICS_TIMEOUT, max(10.0, remaining_time * 0.4))  # Use 40% of remaining
            logger.info(f"[STAGE 3] timeout={heuristics_timeout:.1f}s, remaining={remaining_time:.1f}s")

            logger.info(f"[STAGE 3] Starting heuristics execution...")
            stage3_start = time.time()
            try:
                findings = heuristics_manager.run_heuristics(
                    ghidra_export,
                    preproc.metadata,
                    heuristics,
                    static_artifacts=static_artifacts,
                    timeout_sec=heuristics_timeout
                )
                stage3_elapsed = time.time() - stage3_start
                logger.info(f"[STAGE 3] Completed in {stage3_elapsed:.2f}s, found {len(findings)} findings")
            except Exception as e:
                stage3_elapsed = time.time() - stage3_start
                logger.error(f"[STAGE 3] FAILED after {stage3_elapsed:.2f}s: {type(e).__name__}: {e}", exc_info=True)
                raise

            # 4) PHASE 2: Enrich findings with Ghidra context (function call graph, signatures)
            if ghidra_export:
                try:
                    from . import ghidra_enrichment
                    findings = ghidra_enrichment.enrich_findings_with_context(findings, ghidra_export)
                except Exception:
                    # Enrichment is optional; continue if it fails
                    pass

            # 5) scoring aggregation
            scored = scoring.aggregate_scores(findings)

            # 6) hints generation (full and public redacted)
            hints_dir = analysis_dir
            hints_path = hints_generator.generate_hints(scored, hints_dir, redact=False, file_hash=preproc.file_hash)
            hints_public_path = hints_generator.generate_hints(scored, hints_dir, redact=True, file_hash=preproc.file_hash)

            # 7) package results
            meta = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "profile": ctx.profile,
                "tool_versions": ctx.tool_versions.__dict__ if hasattr(ctx.tool_versions, "__dict__") else {},
            }
            static_results_path = results_packager.package_results(preproc.file_hash, scored, analysis_dir, meta=meta)

            # 8) cache metadata is written by results_packager.package_results
            # which already persisted a `.cache_meta.json` next to the
            # `static_results.json`. Keep runner logic minimal here.

            # populate result
            result.hints_path = hints_path
            result.static_results_path = static_results_path
            result.summary = {"findings_count": len(scored)}
            result.cached = False
            return result

        except FileNotFoundError as exc:
            # Input file or preprocessed data not found
            error_msg = str(exc)
            result.errors = [f"File not found: {error_msg}"]
            result.summary = {"error_type": "file_not_found", "message": error_msg}
            return result
            
        except ValueError as exc:
            # Input validation or data format error
            error_msg = str(exc)
            result.errors = [f"Validation error: {error_msg}"]
            result.summary = {"error_type": "validation_error", "message": error_msg}
            return result
            
        except TimeoutError as exc:
            # Ghidra or other subprocess timeout
            error_msg = str(exc)
            result.errors = [f"Timeout: {error_msg}"]
            result.summary = {
                "error_type": "timeout",
                "message": error_msg,
                "hint": "Consider setting policy='never' if analyzing source code only"
            }
            return result
            
        except PermissionError as exc:
            # File permission issues
            error_msg = str(exc)
            result.errors = [f"Permission denied: {error_msg}"]
            result.summary = {"error_type": "permission_error", "message": error_msg}
            return result
            
        except Exception as exc:
            # Catch-all for unexpected errors
            import traceback
            error_msg = str(exc)
            error_trace = traceback.format_exc()
            
            # Log full traceback for debugging
            try:
                import logging
                logging.error(f"Static detection pipeline error: {error_trace}")
            except:
                pass
            
            # attempt to write a minimal static_results.json indicating failure
            try:
                err_meta = {
                    "error": error_msg,
                    "error_type": type(exc).__name__,
                    "file_hash": getattr(result, "file_hash", None)
                }
                out_dir = os.path.abspath(os.path.join(ctx.analysis_base, "analysis", "static", getattr(result, "file_hash", "unknown")))
                os.makedirs(out_dir, exist_ok=True)
                results_packager.package_results(getattr(result, "file_hash", ""), [], out_dir, meta=err_meta)
            except Exception:
                pass
                
            result.errors = [error_msg]
            result.summary = {
                "error_type": type(exc).__name__,
                "message": error_msg,
                "hint": "Run setup check: python -m src.auditor.detectors.static_detection.setup"
            }
            return result
