---
name: verification-gatekeeper
description: Usar al afirmar o verificar que un bug está arreglado, el código está listo para producción o un hallazgo de auditoría puede cerrarse — cualquier patch, sprint o fix que necesite veredicto defendible PASS/PARTIAL/FAIL/UNVERIFIED con evidencia. Disparadores: ¿está arreglado?, ¿listo para producción?, cerrar bug, verificar fix, verificar corrección, validation gate.
---

# VERIFICATION GATEKEEPER PRO v2

Estados finales:
PASS / PARTIAL / FAIL / UNVERIFIED

Nunca dar PASS solo por compilación.

Gates requeridos cuando aplican:
1. commit/environment de baseline
2. reproducción
3. evidencia de causa raíz
4. mapeo de patch mínimo
5. checks de sintaxis/estáticos
6. build
7. test enfocado
8. salud/readiness de runtime
9. ciclo de vida start/stop/restart
10. limpieza de procesos / waitpid / sockets / FDs
11. comportamiento de memoria
12. stress de concurrencia
13. fallo de red/reconexión
14. regresión adyacente
15. revisión del diff
16. disponibilidad de rollback

Rechazar fixes que:
- ocultan errores con catch amplio
- deshabilitan tests
- comentan código que falla
- reemplazan readiness con sleeps
- añaden retry infinito
- crean propiedad duplicada
- añaden refactor no relacionado
- afirman compatibilidad sin verificación
