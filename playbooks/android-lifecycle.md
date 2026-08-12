# Playbook: Ciclo de vida Android

## Síntomas
- Servicio se detiene solo o no arranca tras volver de background
- Duplicados de worker/daemon tras recrear Activity
- `onServiceDisconnected` sin rebind posterior
- NPE de Context retenido (Activity filtrada en singleton)
- Estado inconsistente tras rotación o muerte de proceso

## Diagnóstico
1. Mapea cada servicio: `AndroidManifest.xml` — exported, process, foregroundServiceType.
2. Para cada recurso: OWNER / CREATED_BY / START_CONDITION / STOP_CONDITION / REAPER.
3. Revisa `onCreate/onStartCommand/onBind/onDestroy` — quién guarda qué.
4. Busca arranques duplicados: `bindService` en `onResume` sin chequeo de estado previo.
5. Verifica `START_STICKY` vs `START_NOT_STICKY` vs `START_REDELIVER_INTENT` — ¿coincide con la semántica esperada?
6. Context retenido: ¿se guardó Activity en lugar de `applicationContext`?

## Causas raíz comunes
- Estado central en Activity en vez de Service/Singleton
- Sin manejo de `onServiceDisconnected` (Messenger muere → app pierde canal para siempre)
- Doble arranque: Activity + Service crean el mismo recurso
- Context con ciclo de vida corto almacenado en objeto de vida larga

## Fix mínimo
- Centralizar propiedad del recurso en UNA clase (ej. Service) — prohibir doble dueño
- `onServiceDisconnected` → programar rebind con backoff (ej. 1s inicial, 3s intervalo)
- Guardar `applicationContext`, nunca Activity
- Filtros de estado: si `state != IDLE`, no re-arrancar

## Verificación
1. Rotar pantalla 5× → sin duplicados de proceso (`ps`)
2. Background 60s → foreground → recurso sigue vivo y responde
3. Matar worker manualmente → rebind automático en <5s
4. `dumpsys activity services` — un solo servicio, sin instancias huérfanas
5. Ciclo arranque/parada 10× → sin estado residual

## Errores típicos de verificación
- "Arranca" probado solo con app en foreground → no prueba recreation
- Sin probar muerte del proceso remoto → rebind nunca ejercitado
- Chequear solo PID, no la señal de salud de la app (PID_CREATED != READY)
