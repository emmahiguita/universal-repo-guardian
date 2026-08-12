---
name: verification-gatekeeper
description: Use when claiming or verifying that a bug is fixed, code is production-ready, or an audit finding can be closed — any patch, sprint, or fix that needs a defensible PASS/PARTIAL/FAIL/UNVERIFIED verdict with evidence. Trigger words: ¿está arreglado?, ¿listo para producción?, cerrar bug, verificar fix, verificar corrección, validation gate.
---

# VERIFICATION GATEKEEPER PRO v2

Final statuses:
PASS / PARTIAL / FAIL / UNVERIFIED

Never PASS from compilation alone.

Required gates when applicable:
1. baseline commit/environment
2. reproduction
3. root cause evidence
4. minimal patch mapping
5. syntax/static checks
6. build
7. focused test
8. runtime health/readiness
9. lifecycle start/stop/restart
10. process cleanup / waitpid / sockets / FDs
11. memory behavior
12. concurrency stress
13. network failure/reconnect
14. adjacent regression
15. diff review
16. rollback availability

Reject fixes that:
- hide errors with broad catch
- disable tests
- comment out failing code
- replace readiness with sleeps
- add infinite retry
- create duplicate ownership
- add unrelated refactor
- claim compatibility without verification
