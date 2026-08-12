# Playbook: Renderizado Flutter / Surface Android

## Síntomas
- Frames congelados o pantalla negra intermitente
- `Can't acquire next buffer` / `Already acquired max frames` en logcat
- Textura desactualizada tras pausa/resume
- Rebotes de rebuild: UI recalcula sin cambios de datos
- Solapamiento/z-order incorrecto con PlatformView

## Diagnóstico
1. Captura pipeline completo: Flutter frame → PlatformView/Texture/Surface → BufferQueue → GPU/consumer.
2. Verifica propiedad de cada recurso: quién crea Surface/Texture, quién la libera.
3. `adb shell dumpsys SurfaceFlinger` — buffers pendientes, productor sin consumir.
4. Backpressure: ¿productor encola sin límite? ¿latest-frame-wins implementado?
5. Revisa `dispose()` de controllers (`StreamController`, `AnimationController`, `TextEditingController`, `FocusNode`).
6. Perfila pacing de frames: `flutter run --profile` + DevTools timeline.

## Causas raíz comunes
- Buffer no liberado → BufferQueue saturado → `Can't acquire next buffer`
- Copia O(N²) en camino caliente (ej. acumular `Uint8List` frame a frame)
- Rebuild storm: `setState` en root sin selección de widget
- `Texture`/`Surface` sin `dispose` en el ciclo de vida del PlatformView
- Z-order: PlatformView sobre/ bajo widgets nativos sin orquestar

## Fix mínimo
- Latest-frame-wins: si llega frame nuevo y el anterior no se consumió, descartar el viejo
- Acotar cola de frames (cola circular / drop policy explícito)
- `dispose` en todos los recursos con dueño único
- `const` + `RepaintBoundary` para cortar rebuild innecesario
- Evitar copia por frame: reutilizar buffer o copiar solo delta

## Verificación
1. Sesión 10 min con logcat filtrando `BufferQueue|frame|surface` → sin saturación
2. Pausa/resume × 10 → textura correcta siempre
3. Timeline DevTools: sin jank > 16ms sostenido en escena objetivo
4. Leak check: abrir/cerrar pantalla × 20 → buffers/GPU estables
5. Rotación + redimensionamiento → sin artefactos

## Errores típicos
- Tratar `Can't acquire next buffer` como ruido — es backpressure hasta que se demuestre lo contrario
- "Arreglar" con más `sleep` → enmascara y empeora el pacing
- Medir FPS promedio y no el peor frame (jank = percentil 99)
