# Playbook: Deadlock y bloqueos de concurrencia

## Síntomas
- UI congelada sin crash
- Worker no responde pese a estar vivo
- Timeouts en cascada cuando no hay carga
- `blocked forever` / `lock timeout` / `Watchdog` en logs
- Solo ocurre en producción o bajo condiciones específicas

## Diagnóstico
1. Captura estado de hilos en el momento del bloqueo:
   - Java/Kotlin: `jstack` / `kill -3 <pid>` (dump de hilos)
   - Android: `debuggerd -b <pid>` o ANR traces (`/data/anr/`)
   - Rust: backtraces con `parking_lot`/`std::sync` habilitado
2. Construye grafo lock/wait: quién espera qué lock, quién lo tiene.
3. Busca ciclo en el grafo — un ciclo = deadlock confirmado.
4. Inversión de orden: ¿dos sitios toman locks A→B y B→A?
5. Para async: ¿algún `await` dentro de sección crítica? ¿Future que nunca se completa?

## Causas raíz comunes
- Doble lock no reentrante (ej. `synchronized` anidado sobre el mismo objeto vía camino indirecto)
- Espera síncrona del resultado de otro hilo que necesita un lock que tú tienes
- `await` sobre completer que depende del propio hilo
- Cola de eventos saturada: el evento que desbloquearía nunca se procesa

## Fix mínimo
- Orden canónico de adquisición de locks documentado
- Sección crítica sin `await` ni callbacks
- Timeout en toda espera inter-hilo (`wait` con límite, `Future.timeout`)
- Romper ciclo: quitar un lock del camino (estructura sin bloqueo o copia)

## Verificación
1. Stress de concurrencia: N hilos × operación conflictiva × 10k iteraciones
2. Reproducir el escenario exacto del bloqueo (rotación, red, background)
3. Timeout de watchdog dispara y recupera en vez de colgar
4. Sin regresión: operaciones normales sin degradación de throughput
5. Correr con detector: `helgrind`/`tsan` (C/C++), dumps de hilos periódicos

## Errores típicos
- "No se reproduce en mi máquina" → deadlock dependiente de timing requiere stress
- Añadir `sleep` para "reducir la probabilidad" → oculta, no arregla
- Eliminar el lock entero sin análisis → race condition nueva (peor)
