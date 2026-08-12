# Playbook: Fuga de memoria

## Síntomas
- RSS crece monótono por sesión
- `OOM` / `OutOfMemoryError` tras horas de uso
- Java/Kotlin heap estable pero nativo crece (o al revés)
- FDs agotados: `Too many open files` sin carga aparente

## Diagnóstico
1. Baseline: heap manejado (Java/Kotlin, Dart), heap nativo, mmap, GPU, FDs, RSS de procesos hijos — por separado.
2. Identifica dueño esperado de cada asignación: quién crea, quién libera.
3. Reproduce el ciclo sospechoso (abrir/cerrar pantalla, reconnect, rotación).
4. Compara curvas por categoría tras N ciclos — ¿qué categoría crece?
5. Para Dart: `flutter run --profile` + Observatory/DevTools memory, busca retención de BuildContext/Streams.
6. Para nativo: `dumpsys meminfo <pid>` (Native Heap, PSS), `lsof` para FDs.

## Causas raíz comunes
- Listener/registro sin desregistrar (observer pattern sin remove)
- GlobalRef JNI acumulado
- StreamSubscription sin cancel
- Búfer/cache sin límite (cola de frames, historial)
- Context retenido en singleton
- waitpid nunca llamado → zombies (ver playbook process-zombie)

## Fix mínimo
- Dueño único por recurso con `dispose/close/remove` simétrico al create
- Colas con cota explícita (drop-oldest) en todo lo asíncrono
- Cache con política de evicción documentada
- Reapado de hijos: `waitpid`/`SIGCHLD` en el padre dueño

## Verificación
1. N ciclos del escenario → memoria vuelve a la línea base (plateau, no escalera)
2. FDs estables tras 100 reconexiones
3. Heap nativo estable tras 1h de uso
4. Detector: LeakCanary (Android), DevTools (Flutter), valgrind/ASan (nativo)
5. Regresión: operaciones normales sin degradación

## Errores típicos
- Medir solo Java heap en app híbrida — el leak suele estar en nativo/GPU/FD
- Confundir plateau normal de GC con estabilidad real
- "Lo arreglé" sin reproducir el ciclo que lo causaba
