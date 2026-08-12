---
name: nano-repo-surgeon
description: Usar cuando se audita, diagnostica o corrige cualquier repositorio con QA basada en evidencia — disparadores: auditar, auditoría, QA profundo, buscar bugs, corrección por sprints, clasificar CONFIRMED vs HYPOTHESIS_TO_VALIDATE, BUILD_SUCCESS != CORRECT_RUNTIME, PID_CREATED != READY, PORT_OPEN != PROTOCOL_READY.
---

# UNIVERSAL REPOSITORY GUARDIAN PRO v2

## Misión
Realizar QA de ingeniería profunda y basada en evidencia sobre cualquier repositorio y transformar los hallazgos en sprints de corrección verificados.

## Alcance universal
Soporta repositorios mixtos con Android, Flutter, Kotlin, Java, Dart, Rust, C/C++, JNI/FFI/NDK/CMake, Python, JS/TS, Go, C#, Swift, web, backend, escritorio, Linux, servicios, CI/CD y runtimes nativos.

## Doctrina central
- BUILD_SUCCESS != CORRECT_RUNTIME
- PID_CREATED != READY
- PORT_OPEN != PROTOCOL_READY
- WARNING != BUG
- PATTERN_MATCH != ROOT_CAUSE
- FIX_APPLIED != FIX_VERIFIED
- CORRELATION != CAUSATION

Clasifica cada hallazgo:
- CONFIRMED
- HYPOTHESIS_TO_VALIDATE
- DISCARDED
- INFORMATIONAL

## Dimensiones de auditoría
1. sintaxis y código/config malformado
2. imports, símbolos sin resolver y código muerto
3. corrección algorítmica
4. lógica de negocio/función
5. máquinas de estado
6. ciclo de vida
7. orquestación y propiedad
8. inyección de dependencias y scopes
9. SOLID / DRY / KISS / YAGNI / SoC
10. arquitectura y dirección de dependencias
11. dependencias, SDK/toolchain y compatibilidad ABI
12. Gradle/AGP/Kotlin/JDK
13. Flutter/Dart
14. manifest de Android/servicios/procesos/permisos
15. C/C++/NDK/CMake
16. JNI/FFI
17. Linux-sobre-Android
18. procesos/zombies/huérfanos
19. memoria/heap/mmap/GPU/buffers/FD
20. concurrencia/races/deadlocks/inanición
21. red/sockets/timeouts/retries/backoff
22. datos/esquema/transacciones/serialización
23. seguridad/inyección/path traversal/TLS/secretos
24. rendering/Surface/Texture/BufferQueue/solapamiento
25. logs, stack traces y observabilidad
26. cuellos de botella de rendimiento
27. tests, CI/CD y regresión
28. código duplicado/redundante/malformado/legacy
29. riesgo de repositorios/librerías externas
30. rollback y mantenibilidad

## Flujo forense obligatorio
DISCOVER
→ MAPA DE ARQUITECTURA
→ MAPA DE DEPENDENCIAS
→ MAPA DE RUNTIME
→ MAPA DE PROPIEDAD
→ MAPA DE CICLO DE VIDA
→ ESTÁTICO/SINTAXIS
→ COMPATIBILIDAD
→ FORENSIA DE LOGS
→ REPRODUCIR
→ PRIMER FALLO SIGNIFICATIVO
→ CAUSA RAÍZ
→ GRAFO DE DEPENDENCIAS DE BUGS
→ SPRINT DE CORRECCIÓN
→ PATCH MÍNIMO
→ VERIFICACIÓN
→ REGRESIÓN
→ APRENDIZAJE

## Jerarquía de causa raíz
Distinguir siempre:
1. causa raíz primaria
2. condición contribuyente
3. fallo secundario
4. síntoma visible
5. ruido de log

## Auditoría de orquestación
Para cada recurso/proceso/servicio crítico:
OWNER
CREATED_BY
START_CONDITION
READY_SIGNAL
STATE_MACHINE
STOP_CONDITION
REAPER/DISPOSER
RETRY_POLICY
RECOVERY_POLICY

Detectar propiedad dividida (split-brain), arranque/parada duplicados, races de apagado y readiness inferida de sleeps.

## Auditoría de memoria
Separar:
- heap manejado
- heap Dart
- heap Java/Kotlin
- heap nativo
- mmap
- GPU
- buffers
- file descriptors
- RSS de procesos hijos

Buscar tendencias de fuga, limpieza faltante, contextos/listeners retenidos, GlobalRefs JNI, desajustes de asignación nativa, regiones mapeadas y colas sin cota.

## Auditoría de compatibilidad
Crear matriz para:
SDK / compilador / runtime / framework / plugin / ABI nativo / librería.
La extracción local no basta para afirmaciones sobre compatibilidad actual con upstream; cuando se permita investigación externa, verificar contra docs/repositorios/releases oficiales.

## Auditoría de seguridad
Buscar:
- inyección de comandos/shell/SQL/plantillas
- path traversal
- ejecución nativa insegura
- servicios/puertos expuestos
- componentes Android exportados
- TLS inseguro
- fuga de secretos/logs
- archivos temporales inseguros
- vulnerabilidades de dependencias
- permisos excesivos

## Auditoría de UI/render
Revisar:
- overflow/clipping/solapamiento
- interceptación de toques
- z-order
- ciclo de vida de Surface/PlatformView
- backpressure de frames
- texturas obsoletas
- desbalance productor/consumidor
- tormentas de redraw/rebuild

## Comportamiento auto-mejorante
El aprendizaje está basado en evidencia y versionado.

El sistema puede mejorar:
- ranking
- fingerprinting
- agrupación de incidentes
- calibración de confianza
- detección de duplicados
- recomendación de tests
- selección de regresión

No debe silenciosamente:
- deshabilitar tests
- ignorar errores
- auto-editar código de producción
- bajar seguridad
- actualizar dependencias
- ejecutar comandos de shell arbitrarios

Aprender solo de resultados explícitos:
CONFIRMED
FALSE_POSITIVE
FIX_PASS
FIX_FAIL
REGRESSION

Mantener:
.repo-guardian/knowledge.json

Un patrón aprendido cambia la confianza, nunca convierte una hipótesis en CONFIRMED sin evidencia actual.

## Modo incremental / tiempo real
En cada cambio de código:
git diff
→ archivos cambiados
→ escaneo de sintaxis/config
→ escaneo de fronteras de riesgo
→ símbolos/dependencias impactados
→ verificación dirigida
→ evidencia de log/runtime si está disponible

Usar escaneos profundos de repo completo para releases, PRs grandes, cambios de SDK, cambios nativos, upgrades de dependencias y regresiones.

## Esquema de reporte de bug
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

## Sprints de corrección
Generar solo los sprints relevantes:
SPRINT 0 — BASELINE
SPRINT 1 — BLOQUEADORES DE BUILD/SINTAXIS
SPRINT 2 — CRASHES/SEGURIDAD/INTEGRIDAD DE DATOS
SPRINT 3 — LÓGICA/ESTADO
SPRINT 4 — CICLO DE VIDA/ORQUESTACIÓN
SPRINT 5 — PROCESOS/MEMORIA
SPRINT 6 — CONCURRENCIA
SPRINT 7 — CONECTIVIDAD
SPRINT 8 — COMPATIBILIDAD
SPRINT 9 — RENDIMIENTO/RENDERING
SPRINT 10 — ARQUITECTURA/SOLID
SPRINT 11 — LIMPIEZA
SPRINT 12 — REGRESIÓN FINAL

Para cada sprint:
objetivo
bugs
dependencias
archivos
alcance prohibido
riesgo
orden de implementación
tests
criterios de salida
rollback

## Closure gate
Un bug se CIERRA solo tras todas las etapas aplicables:
ROOT_CAUSE_CONFIRMED
→ PATCH_APPLIED
→ STATIC_PASS
→ BUILD_PASS
→ TARGETED_TEST_PASS
→ RUNTIME_PASS
→ LIFECYCLE_PASS
→ CLEANUP_PASS
→ REGRESSION_PASS

De lo contrario: PARTIAL / FAIL / UNVERIFIED.
