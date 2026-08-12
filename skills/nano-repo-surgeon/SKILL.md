---
name: nano-repo-surgeon
description: Use when auditing, diagnosing or fixing any repository with evidence-driven QA — trigger: auditar, auditoría, QA profundo, buscar bugs, corrección por sprints, clasificar CONFIRMED vs HYPOTHESIS_TO_VALIDATE, BUILD_SUCCESS != CORRECT_RUNTIME, PID_CREATED != READY, PORT_OPEN != PROTOCOL_READY.
---

# UNIVERSAL REPOSITORY GUARDIAN PRO v2

## Mission
Perform deep, evidence-driven engineering QA on any repository and transform findings into verified correction sprints.

## Universal scope
Supports mixed repositories containing Android, Flutter, Kotlin, Java, Dart, Rust, C/C++, JNI/FFI/NDK/CMake, Python, JS/TS, Go, C#, Swift, web, backend, desktop, Linux, services, CI/CD and native runtimes.

## Core doctrine
- BUILD_SUCCESS != CORRECT_RUNTIME
- PID_CREATED != READY
- PORT_OPEN != PROTOCOL_READY
- WARNING != BUG
- PATTERN_MATCH != ROOT_CAUSE
- FIX_APPLIED != FIX_VERIFIED
- CORRELATION != CAUSATION

Classify every finding:
- CONFIRMED
- HYPOTHESIS_TO_VALIDATE
- DISCARDED
- INFORMATIONAL

## Audit dimensions
1. syntax and malformed code/config
2. imports, unresolved symbols and dead code
3. algorithmic correctness
4. business/function logic
5. state machines
6. lifecycle
7. orchestration and ownership
8. dependency injection and scopes
9. SOLID / DRY / KISS / YAGNI / SoC
10. architecture and dependency direction
11. dependencies, SDK/toolchain and ABI compatibility
12. Gradle/AGP/Kotlin/JDK
13. Flutter/Dart
14. Android manifest/services/processes/permissions
15. C/C++/NDK/CMake
16. JNI/FFI
17. Linux-on-Android
18. processes/zombies/orphans
19. memory/heap/mmap/GPU/buffers/FD
20. concurrency/races/deadlocks/starvation
21. network/sockets/timeouts/retries/backoff
22. data/schema/transactions/serialization
23. security/injection/path traversal/TLS/secrets
24. rendering/Surface/Texture/BufferQueue/overlap
25. logs, stack traces and observability
26. performance bottlenecks
27. tests, CI/CD and regression
28. duplicate/redundant/malformed/legacy code
29. external repository/library risk
30. rollback and maintainability

## Required forensic workflow
DISCOVER
→ MAP ARCHITECTURE
→ MAP DEPENDENCIES
→ MAP RUNTIME
→ MAP OWNERSHIP
→ MAP LIFECYCLE
→ STATIC/SYNTAX
→ COMPATIBILITY
→ LOG FORENSICS
→ REPRODUCE
→ FIRST MEANINGFUL FAILURE
→ ROOT CAUSE
→ BUG DEPENDENCY GRAPH
→ CORRECTION SPRINT
→ MINIMAL PATCH
→ VERIFICATION
→ REGRESSION
→ LEARNING

## Root-cause hierarchy
Always distinguish:
1. primary root cause
2. contributing condition
3. secondary failure
4. visible symptom
5. log noise

## Orchestration audit
For every critical resource/process/service:
OWNER
CREATED_BY
START_CONDITION
READY_SIGNAL
STATE_MACHINE
STOP_CONDITION
REAPER/DISPOSER
RETRY_POLICY
RECOVERY_POLICY

Detect split-brain ownership, duplicate start/stop, shutdown races and readiness inferred from sleeps.

## Memory audit
Separate:
- managed heap
- Dart heap
- Java/Kotlin heap
- native heap
- mmap
- GPU
- buffers
- file descriptors
- child-process RSS

Look for leak trends, missing cleanup, retained contexts/listeners, JNI GlobalRefs, native allocation mismatches, mapped regions and unbounded queues.

## Compatibility audit
Create a matrix for:
SDK / compiler / runtime / framework / plugin / native ABI / library.
Local extraction is not enough for claims about current upstream compatibility; when external research is allowed, verify against official docs/repositories/releases.

## Security audit
Look for:
- command/shell/SQL/template injection
- path traversal
- unsafe native execution
- exposed services/ports
- exported Android components
- insecure TLS
- secrets/log leakage
- unsafe temp files
- dependency vulnerabilities
- excessive permissions

## UI/render audit
Check:
- overflow/clipping/overlap
- touch interception
- z-order
- Surface/PlatformView lifecycle
- frame backpressure
- stale textures
- producer/consumer imbalance
- redraw/rebuild storms

## Self-improving behavior
Learning is evidence-gated and versioned.

The system may improve:
- ranking
- fingerprinting
- incident grouping
- confidence calibration
- duplicate detection
- test recommendation
- regression selection

It must not silently:
- disable tests
- ignore errors
- auto-edit production code
- lower security
- upgrade dependencies
- execute arbitrary shell commands

Learn only from explicit outcomes:
CONFIRMED
FALSE_POSITIVE
FIX_PASS
FIX_FAIL
REGRESSION

Maintain:
.repo-guardian/knowledge.json

A learned pattern changes confidence, never converts a hypothesis into CONFIRMED without current evidence.

## Real-time / incremental mode
On each code change:
git diff
→ changed files
→ syntax/config scan
→ risk-boundary scan
→ impacted symbols/dependencies
→ targeted verification
→ log/runtime evidence if available

Use deep full-repo scans for releases, large PRs, SDK changes, native changes, dependency upgrades and regressions.

## Bug report schema
BUG-ID
STATUS
SEVERITY
CONFIDENCE
CATEGORY
FILE
SYMBOL
LINE
FINGERPRINT
SYMPTOM
FIRST_FAILURE
EVIDENCE
EXPECTED
ACTUAL
ROOT_CAUSE
CONTRIBUTING_FACTORS
IMPACT
DEPENDENCIES
MINIMAL_FIX
STRUCTURAL_FIX
FILES_TO_MODIFY
DO_NOT_TOUCH
TARGETED_TEST
LIFECYCLE_TEST
MEMORY/PROCESS_CLEANUP
REGRESSION
ROLLBACK
CLOSURE_GATE

## Correction sprints
Generate only relevant sprints:
SPRINT 0 — BASELINE
SPRINT 1 — BUILD/SYNTAX BLOCKERS
SPRINT 2 — CRASHES/SECURITY/DATA INTEGRITY
SPRINT 3 — LOGIC/STATE
SPRINT 4 — LIFECYCLE/ORCHESTRATION
SPRINT 5 — PROCESSES/MEMORY
SPRINT 6 — CONCURRENCY
SPRINT 7 — CONNECTIVITY
SPRINT 8 — COMPATIBILITY
SPRINT 9 — PERFORMANCE/RENDERING
SPRINT 10 — ARCHITECTURE/SOLID
SPRINT 11 — CLEANUP
SPRINT 12 — FINAL REGRESSION

For each sprint:
objective
bugs
dependencies
files
forbidden scope
risk
implementation order
tests
exit criteria
rollback

## Closure gate
A bug is CLOSED only after all applicable stages:
ROOT_CAUSE_CONFIRMED
→ PATCH_APPLIED
→ STATIC_PASS
→ BUILD_PASS
→ TARGETED_TEST_PASS
→ RUNTIME_PASS
→ LIFECYCLE_PASS
→ CLEANUP_PASS
→ REGRESSION_PASS

Otherwise: PARTIAL / FAIL / UNVERIFIED.
