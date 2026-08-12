# Playbook: Crash JNI / FFI / nativo

## Síntomas
- `JNI DETECTED ERROR` / `CheckJNI` / `SIGSEGV` en librería nativa
- Crash solo en release o solo en dispositivo
- `Fatal signal` con backtrace en `lib<proyecto>.so`
- Strings/Buffers corruptos tras llamadas cross-boundary

## Diagnóstico
1. Encuentra el PRIMER error nativo del log (los siguientes suelen ser cascada).
2. Valida firma exportada vs declarada:
   - `nm -D lib<proyecto>.so | grep Java_` vs `external fun` en Kotlin
3. Revisa:
   - ABI: arm64-v8a vs armeabi-v7a en el APK final
   - Thread attachment: ¿llamada JNI desde hilo nativo sin `AttachCurrentThread`?
   - Referencias: GlobalRef sin `DeleteGlobalRef`, LocalRef en bucle largo
   - Excepción pendiente: ¿se comprueba `ExceptionCheck` tras cada llamada JNI?
   - Ownership de punteros: quién libera qué (malloc vs NewByteArray)
4. Reproduce en dispositivo con `-Xcheck:jni` (detecta uso ilegal temprano).

## Causas raíz comunes
- Firma JNI desactualizada tras refactor (renombrar clase/paquete Kotlin sin actualizar C)
- Búfer de tamaño fijo sin validar longitud de entrada
- `NewStringUTF` con datos no UTF-8 válidos
- GlobalRef acumulado por callback repetido
- Llamada a JNI tras `DetachCurrentThread`

## Fix mínimo
- Una sola fuente de verdad de firmas (generar encabezado o mapeo único)
- Validar longitud y null en TODA entrada de la frontera
- RAII para refs: `LocalRef` scope guard, `GlobalRef` con dueño
- `ExceptionCheck` después de cada llamada que pueda fallar
- `env->FatalError` nunca en producción — propagar error

## Verificación
1. `-Xcheck:jni` en dispositivo sin reportes nuevos
2. Stress: 10k llamadas cross-boundary sin drift de memoria nativa
3. Ciclo de vida × 20: abrir/cerrar el feature (refs no se acumulan)
4. `dumpsys meminfo` nativo estable antes/después
5. El crash original reproducido → desaparece tras fix

## Errores típicos
- Arreglar el síntoma (línea del crash) sin validar la frontera completa
- Probar solo en emulador — W^X, SELinux y ABI reales solo existen en dispositivo
- Confundir rc=126 (política de ejecución) con rc=127 (falta intérprete/librería)
