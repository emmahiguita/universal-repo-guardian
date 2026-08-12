---
name: android-native-runtime-debugger
description: Use when diagnosing Android/Flutter/JNI/NDK/C++ native runtime failures — Xvnc/VNC readiness, rc=126/127, ELF loader, linker namespaces, process lifecycle, zombies/orphans, BufferQueue frame backpressure, SELinux denials, Linux-on-Android environment issues.
---

# Android Native Runtime Debugger

## Mission
Diagnose Android + Flutter + JNI/NDK + C/C++ + Linux runtime failures with process-level evidence.

## Core rules
- PID_CREATED != READY
- PORT_OPEN != PROTOCOL_READY
- BUILD_SUCCESS != RUNTIME_SUCCESS
- A successful fallback does not erase the primary failure
- A fixed sleep is never the only readiness criterion when a health signal exists

## Diagnostic sequence

### Process creation
Capture:
- caller process
- worker process
- child PID
- argv
- envp
- cwd
- executable path
- loader strategy
- exit code
- signal
- stdout
- stderr

### Native loader
Inspect:
- ABI
- ELF class
- interpreter
- DT_NEEDED
- SONAME
- RPATH/RUNPATH
- linker namespace
- System.load
- System.loadLibrary
- dlopen
- missing symbol
- duplicate SONAME

### Execution failures
Differentiate:
- EACCES
- ENOENT
- ENOEXEC
- linker failure
- SELinux denial
- wrong interpreter
- missing library

Rules:
- rc=126 → investigate execution/permission policy
- rc=127 → investigate missing executable/interpreter/library

### JNI
Inspect:
- exported names/signatures
- thread attachment
- local refs
- global refs
- pending exceptions
- string release
- buffers
- ownership
- native handle lifecycle

### Process lifecycle
For each process record:
- owner
- who starts
- who stores PID
- who stops
- who reaps
- Activity death behavior
- service death behavior
- process recreation behavior

Detect:
- zombies
- orphans
- duplicate workers
- duplicate daemons
- stale sockets
- stale locks
- stale PID files

### Xvnc / VNC
Ready only when:
1. Xvnc PID alive
2. X display available
3. TCP 5901 open
4. RFB handshake valid
5. window manager starts
6. viewer connects

### X11
Ready only when:
1. X server alive
2. display socket/port ready
3. DISPLAY matches
4. X client connects
5. frames reach the Android surface

### Surface pipeline
Inspect:
- SurfaceView lifecycle
- Texture lifecycle
- PlatformView lifecycle
- producer/consumer pacing
- pending frames
- frame release
- latest-frame-wins
- buffer count
- GPU driver interaction

`Can't acquire next buffer` should be treated as rendering backpressure until disproven.

### Linux environment
Validate:
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
- permissions

## Output
Observed symptom:
Earliest meaningful failure:
Probable root cause:
Confidence:
Missing evidence:
Subsystem:
Minimal fix:
Regression checks:


## v2 Additions

### Android 14/15/16 execution analysis
Differentiate filesystem execute permission from platform execution policy, linker namespace failure, SELinux denial, ABI mismatch and missing interpreter.

### Native process readiness
A child process is READY only after its application-level health signal succeeds.

Examples:
- Xvnc: PID + X display + RFB handshake
- HTTP service: PID + socket + valid health response
- worker: Binder connected + command round-trip
- X11: server + display endpoint + real X client connection

### Renderer forensic path
Flutter frame → PlatformView/Texture/Surface → Android BufferQueue → GPU/consumer.
When frame acquisition saturates, inspect unreleased buffers, producer pacing, lifecycle disposal and latest-frame-wins strategy.

### Linux/Android environment
Audit Bionic/glibc boundaries, ELF interpreter, DT_NEEDED, LD_LIBRARY_PATH, symlink/path rewriting, PRoot assumptions, PTY, stdout/stderr and process reaping.
