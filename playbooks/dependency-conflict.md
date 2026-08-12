# Playbook: Conflicto de dependencias / ABI / toolchain

## Síntomas
- `Duplicate class` / `Duplicate SO name` / `cannot locate symbol`
- Build OK en una máquina, falla en otra
- `NoSuchMethodError` / `IncompatibleClassChangeError` en runtime
- Carga nativa falla: `dlopen failed` / `undefined symbol` / `ELF interpreter` incorrecto
- `rc=126` (política de ejecución) vs `rc=127` (intérprete/librería inexistente)

## Diagnóstico
1. Extrae el grafo de dependencias real (no el declarado):
   - Gradle: `./gradlew dependencies` y comparar versiones transitivas
   - npm/pub: lockfile como fuente de verdad
2. Aísla versiones en conflicto: dos ramas que declaran distinta versión del mismo paquete.
3. Para nativo: `readelf -d <lib>` — DT_NEEDED, SONAME, RPATH/RUNPATH, intérprete ELF.
4. Verifica ABI: 32 vs 64 bits, armv7 vs arm64, glibc vs bionic.
5. `ldd`/`LD_LIBRARY_PATH` en el entorno real del proceso, no en la shell de desarrollo.

## Causas raíz comunes
- Dependencia transitiva duplicada con versiones incompatibles
- Librería compilada para otra ABI/glibc copiada al entorno destino
- Shebang apuntando a intérprete inexistente en el target (ej. `#!/data/data/com.termux/files/usr/bin/sh` en Android sin Termux)
- W^X: ejecutable en filesystem sin permiso de ejecución (truco linker64)
- Gradle/AGP/Kotlin con plugin que requiere versión superior

## Fix mínimo
- Pin de versión compatible en un solo lugar (constraint/resolutionStrategy)
- Para nativo: compilar contra el toolchain del target, verificar con `readelf` ANTES de desplegar
- Shebang: resolver al intérprete real del entorno (buscar `/system/bin/sh` y alternativas)
- Documentar matriz SDK/compilador/runtime/ABI — extracción local no basta para claims de upstream

## Verificación
1. `./gradlew dependencies` sin conflictos reportados
2. Build limpio en máquina distinta (CI)
3. Runtime real en dispositivo: carga de librería + smoke del feature
4. `readelf -d` post-build sobre el artefacto final, no el intermedio
5. Reproducir el error original y confirmar que desaparece

## Errores típicos
- "Compila" → runtime nunca probado (BUILD_SUCCESS != RUNTIME_SUCCESS)
- Arreglar downgradeando sin verificar compatibilidad declarada upstream
- Probar solo con `LD_LIBRARY_PATH` del dev, no el entorno real del worker
