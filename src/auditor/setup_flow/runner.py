from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from .setupcontext import SetupContext
from .intake import safe_enumerate
from .hash_dedupe import HasherDedupe
from .persistence import NDJSONBufferedWriter, atomic_write_json
from .manifest import ManifestWriter
from .preproc import preprocess_items
from .archives import extract_archive
from .progress import ProgressReporter
import os
import time


def run_pipeline(
    ctx: SetupContext,
    notifier=None,
    cancel_event: Optional[threading.Event] = None,
    max_workers: int = 2,
    skip_duplicates: bool = True,
    progress_reporter: Optional[ProgressReporter] = None,
    pre_count: bool = True,
    two_phase: bool = False,
):
    """Run enumerate -> hash/dedupe -> preproc pipeline for a SetupContext.

    This function attaches a dedupe NDJSON writer to HasherDedupe and
    runs the streaming preproc which writes `inputs.manifest.ndjson`.
    """
    case_dir = ctx.case_dir or Path(ctx.workdir or ".")
    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)

    # if requested, run a quick pre-count of files to give progress an exact total
    # We present two visual phases to the UI: 'scanning' (simulated 0..100)
    # and 'preprocessing' (accurate file counts). Scanning will advance
    # gradually as directories are visited and jump to 100 when counting
    # completes.
    if progress_reporter and pre_count:
        try:
            # start a simulated scanning phase with a 0..100 scale that
            # linearly progresses over a fixed duration (120s) for UX.
            progress_reporter.start_phase("scanning", total=100)

            animation_duration = 120.0
            start_t = time.monotonic()
            last_emit = start_t
            scan_progress = 0

            # count regular files under ctx.scope while allowing the
            # scanning animation to advance independently. If the actual
            # counting finishes before the animation, we cancel the
            # animation and jump to 100 immediately.
            count = 0
            scope = getattr(ctx, "scope", None)
            if scope is None:
                scope = getattr(ctx, "workdir", None)
            if scope is not None:
                for root, dirs, files in os.walk(str(scope)):
                    # apply simple excludes from config
                    try:
                        ex = set(getattr(ctx.config, "exclude_dirs", (".git", "node_modules", "__pycache__")))
                        # modify dirs in-place to skip excluded directories
                        dirs[:] = [d for d in dirs if d not in ex]
                    except Exception:
                        pass
                    # update file count
                    count += len(files)

                    # update scanning animation based on elapsed time, but
                    # limit to 99 so we can jump to 100 on completion.
                    now = time.monotonic()
                    elapsed = now - start_t
                    target = int(min(99, (elapsed / animation_duration) * 100))
                    if target > scan_progress and (now - last_emit) > 0.2:
                        scan_progress = target
                        last_emit = now
                        try:
                            progress_reporter.update_processed(scan_progress)
                        except Exception:
                            pass

            # counting finished: cancel animation and jump to 100
            try:
                progress_reporter.update_processed(100)
            except Exception:
                pass

            # now start preprocessing with the exact total
            progress_reporter.start_phase("preprocessing", total=count)
            # also write initial progress.json
            progress_reporter._maybe_emit()
        except Exception:
            try:
                progress_reporter.start_phase("preprocessing", total=None)
            except Exception:
                pass

    # Prepare dedupe writer
    dedupe_path = case_dir / "dedupe.ndjson"
    dedupe_writer = NDJSONBufferedWriter(dedupe_path, flush_every=20)

    # Create hasher/dedupe and attach writer
    hd = HasherDedupe(notifier=notifier, chunk_size=8192, skip_duplicates=skip_duplicates)
    hd.attach_dedupe_writer(str(dedupe_path))

    # Build enumeration iterator
    enum_iter = safe_enumerate(ctx, notifier=notifier)

    # Expand enumerated items with archive members (if enabled) so hashing/dedupe
    # runs over both original inputs and any extracted files. This allows
    # deduplication across both sources.
    def expanded_iter():
        for item in enum_iter:
            yield item
            try:
                if getattr(ctx.config, "extract_archives", False):
                    p = item.get("path")
                    if p and isinstance(p, (str,)):
                        ap = Path(p)
                    elif p:
                        ap = p
                    else:
                        ap = None
                    if ap and ap.exists() and ap.is_file():
                        # simple extension check (archive candidates)
                        if ap.suffix.lower() in getattr(ctx.config, "archive_exts", (".zip", ".tar", ".gz", ".bz2")):
                            for extracted in extract_archive(ap, ctx, notifier=notifier, sandbox_parent=(ctx.case_dir if ctx.case_dir else None), recursive=False):
                                # extracted is dict with Path in 'path'
                                yield {"path": str(extracted.get("path")), "origin": f"extracted:{ap.name}", "size": extracted.get("size"), "parent_archive": str(ap)}
            except Exception:
                # best-effort: continue on extractor failure
                try:
                    if notifier:
                        notifier.warn("Archive expansion failed; continuing", path=str(item.get("path")))
                except Exception:
                    pass

    # Process hashing/dedupe -> this yields items with sha256
    hashed_iter = hd.process(expanded_iter())

    # Prepare manifest writer (streaming NDJSON) with notifier integration
    manifest_path = case_dir / "inputs.manifest.ndjson"
    manifest_writer = ManifestWriter(manifest_path, flush_every=20, notifier=notifier)

    # Run preproc streaming; pass ctx, notifier and manifest writer
    try:
        # build progress callback for preproc that updates the reporter
        def _preproc_progress_cb(processed, total):
            try:
                if progress_reporter is not None:
                    # update processed count directly
                    progress_reporter.update_processed(processed)
            except Exception:
                pass

        result = preprocess_items(
            hashed_iter,
            ctx,
            notifier=notifier,
            manifest_writer=manifest_writer,
            progress_cb=_preproc_progress_cb if progress_reporter else None,
            cancel_event=cancel_event,
            max_extract_depth=getattr(ctx.config, "max_extract_depth", 2),
            do_extract=bool(getattr(ctx.config, "extract_archives", True)),
            build_ast=getattr(ctx.config, "build_ast", False),
            build_disasm=getattr(ctx.config, "build_disasm", False),
            stream=True,
            compute_sha=not getattr(ctx.config, "fast_scan", False),
            copy_inputs=not getattr(ctx.config, "fast_scan", False),
        )
    finally:
        # flush dedupe writer buffer
        try:
            hd.flush_dedupe()
        except Exception:
            pass
        # flush manifest writer and write a small manifest summary
        try:
            manifest_writer.flush()
        except Exception:
            pass
        try:
            manifest_writer.write_summary(case_dir / "inputs.manifest.summary.json", {"written_lines": hd.stats.get("processed", 0)})
        except Exception:
            pass

        # finalize progress reporter
        try:
            if progress_reporter is not None:
                progress_reporter.finish_phase()
                # ensure final progress.json written
                progress_reporter._maybe_emit()
        except Exception:
            pass

    # write dedupe summary
    try:
        summary = {
            "processed": hd.stats.get("processed", 0),
            "duplicates": hd.stats.get("duplicates", 0),
            "errors": hd.stats.get("errors", 0),
        }
        atomic_write_json(case_dir / "dedupe-summary.json", summary)
    except Exception:
        pass

    return result
