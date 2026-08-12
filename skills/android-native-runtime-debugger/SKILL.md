---
name: android-native-runtime-debugger
description: Usar al diagnosticar fallos de runtime nativo en Android/Flutter/JNI/NDK/C++ — readiness de Xvnc/VNC, rc=126/127, cargador ELF, linker namespaces, ciclo de vida de procesos, zombies/huérfanos, backpressure de frames BufferQueue, denegaciones SELinux, entorno Linux-sobre-Android.
---

# Android Native Runtime Debugger

## Misión
Diagnosticar fallos de runtime Android + Flutter + JNI/NDK + C/C++ + Linux con evidencia a nivel de proceso.

## Reglas centrales
- PID_CREATED != READY
- PORT_OPEN != PROTOCOL_READY
- BUILD_SUCCESS != RUNTIME_SUCCESS
- Un fallback exitoso no borra el fallo primario
- Un sleep fijo nunca es el único criterio de readiness cuando existe una señal de salud

## Secuencia de diagnóstico

### Creación de proceso
Capturar:
- proceso llamador
- proceso worker
- PID hijo
- argv
- envp
- cwd
- ruta del ejecutable
- estrategia de carga
- exit code
- señal
- stdout
- stderr

### Cargador nativo
Inspeccionar:
- ABI
- clase ELF
- intérprete
- DT_NEEDED
- SONAME
- RPATH/RUNPATH
- linker namespace
- System.load
- System.loadLibrary
- dlopen
- símbolo faltante
- SONAME duplicado

### Fallos de ejecución
Diferenciar:
- EACCES
- ENOENT
- ENOEXEC
- fallo de linker
- denegación SELinux
- intérprete incorrecto
- librería faltante

Reglas:
- rc=126 → investigar política de ejecución/permisos
- rc=127 → investigar ejecutable/intérprete/librería inexistente

### JNI
Inspeccionar:
- nombres/firmas exportados
- attachment de hilos
- refs locales
- refs globales
- excepciones pendientes
- liberación de strings
- buffers
- propiedad
- ciclo de vida de handles nativos

### Ciclo de vida de procesos
Para cada proceso registrar:
- dueño
- quién arranca
- quién guarda el PID
- quién para
- quién reapa
- comportamiento de muerte de Activity
- comportamiento de muerte de servicio
- comportamiento de recreación de proceso

Detectar:
- zombies
- huérfanos
- workers duplicados
- daemons duplicados
- sockets obsoletos
- locks obsoletos
- PID files obsoletos

### Xvnc / VNC
Ready solo cuando:
1. PID de Xvnc vivo
2. display X disponible
3. TCP 5901 abierto
4. handshake RFB válido
5. window manager arranca
6. viewer se conecta

### X11
Ready solo cuando:
1. servidor X vivo
2. socket/puerto de display listo
3. DISPLAY coincide
4. cliente X se conecta
5. frames llegan a la Surface de Android

### Pipeline de Surface
Inspeccionar:
- ciclo de vida de SurfaceView
- ciclo de vida de Texture
- ciclo de vida de PlatformView
- pacing productor/consumidor
- frames pendientes
- liberación de frames
- latest-frame-wins
- conteo de buffers
- interacción con driver GPU

`Can't acquire next buffer` debe tratarse como backpressure de rendering hasta demostrar lo contrario.

### Entorno Linux
Validar:
- rootfs
- HOME
- TMPDIR
- XDG_RUNTIME_DIR
- PATH
- LD_LIBRARY_PATH
- LD_PRELOAD
- DISPLAY
- fonts
- XKB
- symlinks
- permisos

## Salida
Síntoma observado:
Fallo significativo más temprano:
Causa raíz probable:
Confianza:
Evidencia faltante:
Subsistema:
Fix mínimo:
Chequeos de regresión:


## Adiciones v2

### Análisis de ejecución Android 14/15/16
Diferenciar permiso de ejecución del filesystem de política de ejecución de plataforma, fallo de linker namespace, denegación SELinux, desajuste ABI e intérprete faltante.

### Readiness de procesos nativos
Un proceso hijo está READY solo después de que su señal de salud a nivel de aplicación tenga éxito.

Ejemplos:
- Xvnc: PID + display X + handshake RFB
- Servicio HTTP: PID + socket + respuesta de salud válida
- worker: Binder conectado + round-trip de comando
- X11: servidor + endpoint de display + conexión real de cliente X

### Ruta forense de renderer
Flutter frame → PlatformView/Texture/Surface → BufferQueue Android → GPU/consumidor.
Cuando la adquisición de frames se satura, inspeccionar buffers no liberados, pacing del productor, disposal del ciclo de vida y estrategia latest-frame-wins.

### Entorno Linux/Android
Auditar fronteras Bionic/glibc, intérprete ELF, DT_NEEDED, LD_LIBRARY_PATH, reescritura de symlinks/rutas, suposiciones de PRoot, PTY, stdout/stderr y reapado de procesos.
