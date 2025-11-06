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

import os
import json
from datetime import datetime


class StaticRunner:
    """Orchestrator for static detection runs.

    Public API: run(context: RunContext) -> RunResult
    """

    def __init__(self) -> None:
        # add dependencies or configuration here in future
        pass

    def run(self, ctx: RunContext) -> RunResult:
        """Run a static detection flow for the given RunContext.

        Currently a stub that raises NotImplementedError. The final
        implementation will ensure caching, call ghidra_adapter,
        heuristics_manager, scoring, and packaging.
        """
        # Prepare result container
        result = RunResult(file_hash="", cached=False, summary={}, errors=None)

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

            # Quick cache check: if static_results.json exists and not forced, return cached
            static_results_path = os.path.join(analysis_dir, "static_results.json")
            hints_path = os.path.join(analysis_dir, "hints.json")
            if os.path.isfile(static_results_path) and not ctx.force:
                result.cached = True
                result.hints_path = hints_path if os.path.isfile(hints_path) else None
                result.static_results_path = static_results_path
                result.summary = {"note": "reused cached static results"}
                return result

            # 1) generate lightweight static preproc artifacts (profile-aware)
            preproc_out = os.path.join(analysis_dir, "preproc")
            static_artifacts = static_preproc.generate_static_preproc(preproc_dir=ctx.preproc_dir, out_dir=preproc_out, profile=ctx.profile)

            # 2) ensure ghidra export (stub or real implementation)
            ghidra_out = os.path.join(analysis_dir, "ghidra-export")
            ghidra_export_path = ghidra_adapter.ensure_ghidra_export(preproc.input_path, ghidra_out, preproc.file_hash, options={})
            ghidra_export = ghidra_adapter.read_ghidra_functions(ghidra_export_path)

            # 3) run heuristics
            # collect heuristic callables from heuristics package
            heuristics = []
            try:
                from .heuristics.signature import signature_heuristic
                heuristics.append(signature_heuristic)
            except Exception:
                pass
            try:
                from .heuristics.instruction_patterns import instruction_patterns_heuristic
                heuristics.append(instruction_patterns_heuristic)
            except Exception:
                pass
            try:
                from .heuristics.constants import constants_heuristic
                heuristics.append(constants_heuristic)
            except Exception:
                pass

            findings = heuristics_manager.run_heuristics(ghidra_export, preproc.metadata, heuristics)

            # 4) scoring aggregation
            scored = scoring.aggregate_scores(findings)

            # 5) hints generation (full and public redacted)
            hints_dir = analysis_dir
            hints_path = hints_generator.generate_hints(scored, hints_dir, redact=False)
            hints_public_path = hints_generator.generate_hints(scored, hints_dir, redact=True)

            # 6) package results
            meta = {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "profile": ctx.profile,
                "tool_versions": ctx.tool_versions.__dict__ if hasattr(ctx.tool_versions, "__dict__") else {},
            }
            static_results_path = results_packager.package_results(preproc.file_hash, scored, analysis_dir, meta=meta)

            # 7) write cache metadata
            cache_meta = {
                "file_hash": preproc.file_hash,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "profile": ctx.profile,
                "tool_versions": ctx.tool_versions.__dict__ if hasattr(ctx.tool_versions, "__dict__") else {},
                "ghidra_export": ghidra_export_path,
            }
            with open(os.path.join(analysis_dir, ".cache_meta.json"), "w", encoding="utf-8") as fh:
                json.dump(cache_meta, fh, indent=2)

            # populate result
            result.hints_path = hints_path
            result.static_results_path = static_results_path
            result.summary = {"findings_count": len(scored)}
            result.cached = False
            return result

        except Exception as exc:  # pragma: no cover - surface as error in run result
            # attempt to write a minimal static_results.json indicating failure
            try:
                err_meta = {"error": str(exc), "file_hash": getattr(result, "file_hash", None)}
                out_dir = os.path.abspath(os.path.join(ctx.analysis_base, "analysis", "static", getattr(result, "file_hash", "unknown")))
                os.makedirs(out_dir, exist_ok=True)
                results_packager.package_results(getattr(result, "file_hash", ""), [], out_dir, meta=err_meta)
            except Exception:
                pass
            result.errors = [str(exc)]
            return result
