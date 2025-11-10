# Dynamic Analysis Implementation Progress

**Last Updated:** 2025-11-10
**Status:** In Progress

## Quick Status

| Phase | Status | Progress |
|-------|--------|----------|
| Phase 1: Core Infrastructure | 🟡 In Progress | 10% |
| Phase 2: Frida Harness & Sandbox | ⚪ Not Started | 0% |
| Phase 3: Script Generation & Instrumentation | ⚪ Not Started | 0% |
| Phase 4: Trace Management & Sanitization | ⚪ Not Started | 0% |
| Phase 5: JSON Schemas & Validation | ⚪ Not Started | 0% |
| Phase 6: UI Integration | ⚪ Not Started | 0% |
| Phase 7: Testing & Documentation | ⚪ Not Started | 0% |

**Legend:**
- ✅ Complete
- 🟡 In Progress
- ⚪ Not Started
- ❌ Blocked

---

## Phase 1: Core Infrastructure (Foundation)

**Goal:** Create basic module structure and orchestration framework

### Files to Create

- [x] `docs/dynamic_analysis_design.md` - Design specification
- [x] `docs/dynamic_analysis_progress.md` - This file
- [ ] `src/auditor/detectors/dynamic_detection/__init__.py`
- [ ] `src/auditor/detectors/dynamic_detection/context.py`
- [ ] `src/auditor/detectors/dynamic_detection/runner.py`
- [ ] `src/auditor/detectors/dynamic_detection/hints_adapter.py`
- [ ] `src/auditor/detectors/dynamic_detection/config.py`
- [ ] `src/auditor/detectors/dynamic_detection/cache.py`

### Tasks

- [x] Create design documentation
- [x] Create progress tracker
- [ ] Create module directory structure
- [ ] Implement context dataclasses (DynamicContext, DynamicResult)
- [ ] Implement config management
- [ ] Implement hints adapter (load hints.json)
- [ ] Implement cache validation
- [ ] Implement runner orchestrator skeleton
- [ ] Add license check (`license.has_feature('dynamic')`)

### Notes
- Following StaticRunner patterns for consistency
- Using dataclasses for type safety
- Error handling: return results with errors list, never throw

---

## Phase 2: Frida Harness & Sandbox

**Goal:** Implement Frida execution modes and Windows sandboxing

### Files to Create

- [ ] `src/auditor/detectors/dynamic_detection/frida_harness.py`
- [ ] `src/auditor/detectors/dynamic_detection/sandbox.py`
- [ ] `src/auditor/detectors/dynamic_detection/input_feeder.py`

### Tasks

- [ ] Implement spawn mode (launch binary with Frida)
- [ ] Implement attach mode (hook running process)
- [ ] Implement message handler for Frida events
- [ ] Implement timeout handling (500s default)
- [ ] Implement sandbox setup (temp folder, isolated env)
- [ ] Implement network blocking (Frida socket hooks)
- [ ] Implement memory limit monitoring
- [ ] Implement sandbox cleanup (always, even on crash)
- [ ] Implement input feeder (args/input_file from config)

### Notes
- Spawn mode priority (most common use case)
- Attach mode for running processes (PID-based)
- Graceful timeout handling with partial results
- Windows-specific sandbox implementation

---

## Phase 3: Frida Script Generation & Instrumentation

**Goal:** Generate JavaScript hooks from hints and implement instrumenters

### Files to Create

- [ ] `src/auditor/detectors/dynamic_detection/frida_scripter.py`
- [ ] `src/auditor/detectors/dynamic_detection/instrumenters/__init__.py`
- [ ] `src/auditor/detectors/dynamic_detection/instrumenters/crypto_ops.py`
- [ ] `src/auditor/detectors/dynamic_detection/instrumenters/memory_scan.py`
- [ ] `src/auditor/detectors/dynamic_detection/instrumenters/call_graph.py`

### Tasks

- [ ] Implement hook generator from hints
- [ ] Implement crypto_ops instrumenter
  - [ ] Hook bcrypt.dll APIs (BCryptEncrypt, BCryptDecrypt, etc.)
  - [ ] Hook crypt32.dll APIs (CryptEncrypt, CryptDecrypt, etc.)
  - [ ] Capture first 100 crypto calls only
  - [ ] Hash all buffers (sha256)
- [ ] Implement memory_scan instrumenter (optional, lightweight)
  - [ ] Scan for high-entropy buffers (> 7.5 bits/byte)
  - [ ] Limit to 4KB per range
  - [ ] Hash potential key material
- [ ] Implement call_graph instrumenter
  - [ ] Track caller→crypto function relationships
  - [ ] Build call graph edges
- [ ] Implement JavaScript helper functions
  - [ ] hashBuffer() - sha256 hashing
  - [ ] calculateEntropy() - entropy calculation
  - [ ] network blocking hooks

### Notes
- Priority: crypto_ops (core feature)
- memory_scan and call_graph are optional
- All data must be hashed (no raw buffers)
- Capture limits enforced in JavaScript

---

## Phase 4: Trace Management & Sanitization

**Goal:** Collect, limit, and sanitize trace events

### Files to Create

- [ ] `src/auditor/detectors/dynamic_detection/trace_manager.py`
- [ ] `src/auditor/detectors/dynamic_detection/traces_sanitizer.py`
- [ ] `src/auditor/detectors/dynamic_detection/results_packager.py`

### Tasks

- [ ] Implement TraceManager class
  - [ ] Event collection with limits
  - [ ] Max 10,000 events
  - [ ] Max 10 MB file size
  - [ ] Max 100 crypto calls
  - [ ] Summary generation
- [ ] Implement TraceSanitizer class
  - [ ] Hash all buffer data
  - [ ] Redact sensitive fields
  - [ ] Remove raw pointers
- [ ] Implement results packager
  - [ ] Generate dynamic_results.json
  - [ ] Include summary statistics
  - [ ] Include findings
  - [ ] Mark incomplete runs
- [ ] Implement NDJSON writer
  - [ ] Write trace.ndjson (one JSON per line)
  - [ ] Atomic writes

### Notes
- Traces always saved (even partial on timeout/crash)
- NDJSON format for efficient streaming
- Summary in JSON for quick access
- Mark incomplete: `"incomplete": true, "reason": "timeout"`

---

## Phase 5: JSON Schemas & Validation

**Goal:** Define schemas and implement validation

### Files to Create

- [ ] `src/auditor/detectors/dynamic_detection/schemas/dynamic_results.schema.json`
- [ ] `src/auditor/detectors/dynamic_detection/schemas/trace_event.schema.json`
- [ ] `src/auditor/detectors/dynamic_detection/schemas/dynamic_config.schema.json`
- [ ] `src/auditor/detectors/dynamic_detection/validator.py`

### Tasks

- [ ] Create dynamic_results.schema.json
  - [ ] Define structure (file_hash, summary, findings, meta)
  - [ ] Include incomplete flag
- [ ] Create trace_event.schema.json
  - [ ] Define event types (crypto_call, memory_scan, call_graph)
  - [ ] Define required fields per type
- [ ] Create dynamic_config.schema.json
  - [ ] Define args, input_file, timeout, instrumenters
- [ ] Implement validator module
  - [ ] Schema validation functions
  - [ ] Error reporting

### Notes
- Follow static detection schema patterns
- Schema version: "1.0"
- Validate before writing files

---

## Phase 6: UI Integration

**Goal:** Replace dynamic analysis stub with functional UI

### Files to Modify

- [ ] `src/pages/detectors.py`

### Tasks

- [ ] Replace `_build_dynamic_ui()` stub with functional UI
- [ ] Add mode selector (Spawn / Attach radio buttons)
- [ ] Add PID input field (for attach mode)
- [ ] Add timeout slider (50-1000s, default 500s)
- [ ] Add config editor (optional JSON for args/input)
- [ ] Add instrumenter toggles (crypto_ops, memory_scan, call_graph)
- [ ] Add force re-run checkbox
- [ ] Wire "Run Dynamic Analysis" button to DynamicRunner
- [ ] Implement background thread execution
- [ ] Add progress bar with real-time updates
- [ ] Add results display
  - [ ] Summary tab (crypto calls, findings)
  - [ ] Traces tab (NDJSON viewer with pagination)
  - [ ] Call Graph tab (visual graph if implemented)
  - [ ] Console tab (logs)
- [ ] Implement batch processing (run on all binaries with hints)
- [ ] Add license check UI (show "Premium feature" message)
- [ ] Add incomplete run indicator

### Notes
- Follow static UI patterns for consistency
- Thread-safe UI updates via `self.after(0, callback)`
- Batch processing in UI layer only
- License check before execution

---

## Phase 7: Testing & Documentation

**Goal:** Comprehensive testing and documentation updates

### Files to Create

- [ ] `tests/test_dynamic_detection_workflow.py`
- [ ] `tests/test_frida_harness.py`
- [ ] `tests/test_instrumenters.py`
- [ ] `tests/test_context.py`
- [ ] `tests/test_hints_adapter.py`
- [ ] `tests/test_trace_manager.py`
- [ ] `tests/test_traces_sanitizer.py`
- [ ] `tests/test_cache.py`
- [ ] `tests/fixtures/sample_crypto_binary.exe`
- [ ] `tests/fixtures/hints_sample.json`

### Files to Update

- [ ] `README.md` - Add dynamic analysis usage
- [ ] `docs/pipeline.md` - Mark dynamic stage as implemented
- [ ] `docs/analysis-storage.md` - Update with dynamic outputs

### Tasks

#### Unit Tests
- [ ] Test context dataclasses
- [ ] Test hints adapter
- [ ] Test frida scripter (hook generation)
- [ ] Test trace manager (limits)
- [ ] Test trace sanitizer
- [ ] Test cache validation

#### Integration Tests
- [ ] Test full pipeline with mock Frida
- [ ] Test spawn mode with sample binary
- [ ] Test attach mode
- [ ] Test timeout handling (partial results)
- [ ] Test crash handling (save partial traces)
- [ ] Test cache hit/miss

#### End-to-End Tests
- [ ] Test with real crypto binary (bcrypt.dll)
- [ ] Test hints → hooks → traces → results flow
- [ ] Test sanitization (verify no raw keys)
- [ ] Test trace limits (10k events, 10MB, 100 crypto calls)
- [ ] Test UI integration
- [ ] Test batch processing

#### Documentation
- [ ] Update README with dynamic analysis section
- [ ] Update pipeline.md with completed dynamic stage
- [ ] Add usage examples
- [ ] Add troubleshooting guide
- [ ] Add Frida installation instructions

### Notes
- Create sample crypto binary for testing
- Mock Frida for unit tests (use unittest.mock)
- Use real Frida for integration tests
- Verify no secrets in test outputs

---

## Known Issues & Blockers

### Blockers
- None currently

### Known Issues
- None yet (implementation not started)

### Technical Debt
- None yet

---

## Next Steps

### Immediate (Today)
1. Create module directory structure
2. Implement context.py with dataclasses
3. Implement config.py
4. Implement hints_adapter.py
5. Implement runner.py skeleton

### Short-term (This Week)
1. Implement cache.py
2. Implement frida_harness.py (spawn mode)
3. Implement sandbox.py
4. Implement frida_scripter.py
5. Test basic spawn mode with mock

### Medium-term (Next Week)
1. Implement instrumenters (crypto_ops priority)
2. Implement trace manager
3. Implement trace sanitizer
4. Implement results packager
5. Test with real Frida and sample binary

### Long-term (Within Two Weeks)
1. Complete attach mode
2. Complete optional instrumenters (memory_scan, call_graph)
3. UI integration
4. Comprehensive testing
5. Documentation updates

---

## Questions & Decisions

### Resolved
- **Q:** Should we implement both spawn and attach modes?
  - **A:** Yes, both modes are needed
- **Q:** What timeout should we use?
  - **A:** 500s default (configurable)
- **Q:** Should we cache incomplete results?
  - **A:** No, or use shorter TTL
- **Q:** License gating required?
  - **A:** Yes, check `license.has_feature('dynamic')`

### Pending
- None currently

---

## Success Criteria

### Phase 1 Complete When:
- [x] Design documentation exists
- [x] Progress tracker exists
- [ ] Module structure created
- [ ] Context dataclasses implemented
- [ ] Runner skeleton runs without errors
- [ ] Can load hints from static stage
- [ ] License check working

### Phase 2 Complete When:
- [ ] Can spawn binary with Frida
- [ ] Can attach to running process
- [ ] Sandbox enforced (temp folder, no network)
- [ ] Timeout handling works (partial results)
- [ ] Cleanup always runs (even on crash)

### Phase 3 Complete When:
- [ ] Hooks generated from hints
- [ ] crypto_ops hooks working (bcrypt.dll, crypt32.dll)
- [ ] All buffers hashed (no raw data)
- [ ] Capture limits enforced (100 crypto calls)

### Phase 4 Complete When:
- [ ] Traces collected with limits (10k events, 10MB)
- [ ] Traces sanitized (no secrets)
- [ ] dynamic_results.json generated
- [ ] trace.ndjson written (NDJSON format)
- [ ] Incomplete runs marked correctly

### Phase 5 Complete When:
- [ ] All schemas defined
- [ ] Validation working
- [ ] Schema errors caught before write

### Phase 6 Complete When:
- [ ] UI functional (spawn/attach modes)
- [ ] Background execution working
- [ ] Progress updates real-time
- [ ] Results displayed correctly
- [ ] Batch processing working
- [ ] License check enforced in UI

### Phase 7 Complete When:
- [ ] All unit tests passing
- [ ] All integration tests passing
- [ ] End-to-end tests passing
- [ ] Documentation updated
- [ ] Sample binary included

### Overall Complete When:
- [ ] All phases complete
- [ ] All tests passing
- [ ] Documentation complete
- [ ] Works with real crypto binaries
- [ ] UI integrated and tested
- [ ] No known blockers

---

## Implementation Log

### 2025-11-10
- Created design documentation (dynamic_analysis_design.md)
- Created progress tracker (dynamic_analysis_progress.md)
- Started Phase 1: Core Infrastructure

---

**End of Document**
