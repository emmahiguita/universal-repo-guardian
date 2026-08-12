"""Constantes y reglas compartidas — fuente única de verdad.

Contiene: pares recurso/liberación, reglas de riesgo y de log, extensiones,
build files, severidades, patrones de import y de función, permisos Android y el
fingerprint determinístico.
"""

from __future__ import annotations

import hashlib
import re

# ---------------------------------------------------------------------------
# Pares recurso -> operación que lo libera
# ---------------------------------------------------------------------------

RESOURCE_PAIRS: dict[str, str] = {
    "malloc": "free",
    "calloc": "free",
    "realloc": "free",
    "mmap": "munmap",
    "open": "close",
    "fopen": "fclose",
    "socket": "close",
    "new": "delete",
    "StreamController": "close",
    "AnimationController": "dispose",
    "TextEditingController": "dispose",
    "FocusNode": "dispose",
}

# Tokens que tocan recursos (adquisición + liberación + dispose).
RESOURCE_CALL_TOKENS: frozenset[str] = frozenset(
    set(RESOURCE_PAIRS) | set(RESOURCE_PAIRS.values()) | {"dispose"}
)

# Orden por longitud descendente para que los tokens largos matcheen antes.
RESOURCE_CALL_RE = re.compile(
    "|".join(re.escape(t) for t in sorted(RESOURCE_CALL_TOKENS, key=len, reverse=True)),
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Sistema de archivos
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", ".gradle", ".dart_tool", ".idea", ".vscode", "build", "dist",
    "node_modules", "target", ".venv", "venv", "__pycache__", ".next",
    "Pods", "DerivedData", ".terraform", "vendor/bundle"
}

TEXT_EXTS = {
    ".kt", ".kts", ".java", ".dart", ".rs", ".c", ".cc", ".cpp", ".cxx",
    ".h", ".hh", ".hpp", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs",
    ".json", ".toml", ".yaml", ".yml", ".xml", ".gradle", ".properties",
    ".md", ".sh", ".bash", ".zsh", ".ps1", ".cmake", ".txt", ".go",
    ".cs", ".swift", ".sql"
}

CODE_EXTS = {
    ".kt", ".java", ".dart", ".rs", ".c", ".cc", ".cpp", ".cxx", ".h",
    ".hpp", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".cs", ".swift"
}

BUILD_NAMES = {
    "Cargo.toml", "Cargo.lock", "pubspec.yaml", "pubspec.lock",
    "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "gradle.properties", "gradle-wrapper.properties", "CMakeLists.txt",
    "Android.mk", "Application.mk", "package.json", "package-lock.json",
    "pnpm-lock.yaml", "yarn.lock", "pyproject.toml", "requirements.txt",
    "go.mod", "go.sum", "pom.xml", "Podfile", "Package.swift",
    "AndroidManifest.xml", "Dockerfile", "docker-compose.yml"
}

# ---------------------------------------------------------------------------
# Severidad
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {
    "P0": 100,
    "P1": 60,
    "P2": 25,
    "P3": 10,
}

# ---------------------------------------------------------------------------
# Reglas de riesgo (data-driven: añadir una regla = añadir una tupla)
# ---------------------------------------------------------------------------

RISK_RULES = [
    # Marcadores de sintaxis / malformación
    ("merge_conflict", "P0", re.compile(r"^(<<<<<<<|=======|>>>>>>>)", re.M),
     "Marcador de conflicto de merge sin resolver"),
    ("todo_fixme", "P3", re.compile(r"\b(TODO|FIXME|HACK|XXX)\b"),
     "Marcador de implementación incompleta o temporal"),
    # Manejo de errores
    ("empty_catch", "P1", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}", re.S),
     "Excepción tragada sin manejo"),
    ("broad_catch", "P2", re.compile(r"catch\s*\(\s*(?:Exception|Throwable|dynamic|e)\b"),
     "Captura amplia puede ocultar la causa raíz"),
    ("ignored_result", "P2", re.compile(r"\blet\s+_\s*=\s*[^;]+;|(?:^|\s)_\s*=\s*[^;\n]+", re.M),
     "Resultado ignorado a propósito; verificar propagación de errores"),
    # Bloqueo / orquestación
    ("fixed_sleep", "P2", re.compile(r"\b(Thread\.sleep|sleep\(|usleep\(|Future\.delayed)\b"),
     "Delay fijo usado; verificar que no sustituye señal de readiness/sincronización"),
    ("infinite_loop", "P1", re.compile(r"\bwhile\s*\(\s*true\s*\)|\bwhile\s+true\b|\bfor\s*\(\s*;\s*;\s*\)"),
     "Bucle potencialmente sin salida"),
    ("process_spawn", "P1", re.compile(r"\b(fork|execve|execl|execvp|waitpid|setsid|ProcessBuilder|Runtime\.exec|subprocess\.)\b"),
     "Frontera de ciclo de vida de proceso"),
    ("kill_force", "P2", re.compile(r"\b(SIGKILL|kill\s+-9|pkill\s+-9)\b"),
     "Terminación forzada de proceso; verificar apagado limpio y reapado"),
    # Memoria nativa / FFI
    ("native_alloc", "P1", re.compile(r"\b(malloc|calloc|realloc|free|new\s+|delete\s+|mmap|munmap)\b"),
     "Frontera de propiedad de memoria nativa"),
    ("unsafe_copy", "P1", re.compile(r"\b(strcpy|strcat|sprintf|gets|memcpy)\b"),
     "Operación de memoria nativa insegura o sensible a tamaño"),
    ("native_loader", "P1", re.compile(r"\b(dlopen|dlsym|dlclose|System\.loadLibrary|System\.load)\b"),
     "Frontera de carga dinámica nativa"),
    ("jni_boundary", "P1", re.compile(r"\b(JNIEnv|JNIEXPORT|JNI_OnLoad|external\s+fun|@JvmStatic\s+external)\b"),
     "Frontera de propiedad/errores JNI"),
    ("ffi_boundary", "P1", re.compile(r"\b(DynamicLibrary\.open|Pointer<|ffi\.|Foreign Function|extern \"C\")\b"),
     "Frontera de propiedad/ABI FFI"),
    # Concurrencia
    ("lock_usage", "P2", re.compile(r"\b(Mutex|mutex|synchronized|Semaphore|ReentrantLock|pthread_mutex|RwLock|Arc<Mutex)\b"),
     "Frontera de bloqueo/concurrencia"),
    ("global_mutable", "P2", re.compile(r"\b(static\s+mut|var\s+\w+\s*=\s*mutable|late\s+var|companion object)\b"),
     "Estado mutable compartido potencial"),
    # Red
    ("network_local", "P2", re.compile(r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0|5901|6000|DISPLAY)\b"),
     "Endpoint de red/display; verificar propiedad, exposición, timeout y limpieza"),
    ("network_retry", "P2", re.compile(r"\b(retry|reconnect|backoff|keepalive)\b", re.I),
     "Frontera de política de reconexión/retry"),
    ("trust_all_tls", "P0", re.compile(r"(danger_accept_invalid_certs|TrustAll|HostnameVerifier\s*\{\s*true|CERT_NONE)", re.I),
     "Verificación TLS posiblemente deshabilitada"),
    # Rutas / permisos
    ("hardcoded_android_path", "P2", re.compile(r"/data/(?:data|user/0)/[\w.\-]+"),
     "Ruta sandbox de Android hardcodeada"),
    ("hardcoded_absolute_path", "P3", re.compile(r"(?:^|[\"'])(/[A-Za-z0-9_.-]+/|[A-Za-z]:\\\\)"),
     "Ruta absoluta puede reducir portabilidad"),
    ("shell_injection", "P0", re.compile(r"(?:sh\s+-c|bash\s+-c|Runtime\.exec|ProcessBuilder)[^\n]*(?:\+|\$\{|format\(|f\")"),
     "Construcción de comando posiblemente desde entrada dinámica"),
    # UI / Flutter / Android
    ("flutter_dispose", "P2", re.compile(r"\b(StreamController|AnimationController|TextEditingController|FocusNode)\b"),
     "Recurso Flutter desechable; verificar dispose/close"),
    ("android_context", "P2", re.compile(r"\b(Activity|Context)\b"),
     "Frontera de propiedad de contexto/ciclo de vida Android"),
    ("surface_pipeline", "P2", re.compile(r"\b(SurfaceView|TextureView|PlatformView|SurfaceTexture|ImageReader|BufferQueue)\b"),
     "Frontera de ciclo de vida de Surface/render"),
    # SQL / datos
    ("sql_dynamic", "P0", re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(?:\+|\$\{|format\(|f\")", re.I),
     "Construcción dinámica de SQL potencial"),
    ("transaction", "P2", re.compile(r"\b(transaction|BEGIN TRANSACTION|commit\(|rollback\()\b", re.I),
     "Frontera de consistencia transaccional de datos"),
    # Seguridad / credenciales / Android
    ("hardcoded_credential", "P0", re.compile(r"\b(password|passwd|api_key|apikey|secret|token)\b\s*[:=]\s*[\"'][^\"']{4,}[\"']", re.I),
     "Credencial o secreto posiblemente hardcodeado"),
    ("cleartext_traffic", "P1", re.compile(r'usesCleartextTraffic\s*=\s*"true"', re.I),
     "Tráfico en claro habilitado en el manifest"),
    ("android_exported", "P1", re.compile(r'android:exported\s*=\s*"true"', re.I),
     "Componente Android exportado; verificar superficie de ataque"),
    ("wildcard_import", "P3", re.compile(r"^(?:import\s+[\w.]+\s*\*|from\s+\S+\s+import\s+\*)", re.M),
     "Import wildcard; reduce trazabilidad de dependencias"),
    ("run_blocking", "P2", re.compile(r"\brunBlocking\b"),
     "Bloqueo de corrutina en el hilo llamador; verificar que no es Main"),
    ("debug_print", "P3", re.compile(r"\b(print|println|Log\.d|console\.log)\s*\("),
     "Salida de debug en código de producción"),
]

LOG_RULES = [
    ("native_crash", "P0", re.compile(r"\b(SIGSEGV|SIGABRT|SIGBUS|SIGILL|tombstone)\b", re.I)),
    ("android_fatal", "P0", re.compile(r"FATAL EXCEPTION|ANR in |OutOfMemoryError", re.I)),
    ("permission_exec", "P1", re.compile(r"Permission denied|EACCES|rc=126", re.I)),
    ("not_found", "P1", re.compile(r"rc=127|ENOENT|not found|No such file", re.I)),
    ("linker", "P1", re.compile(r"dlopen failed|cannot locate symbol|undefined symbol|linker", re.I)),
    ("jni_abort", "P0", re.compile(r"JNI DETECTED ERROR|JNI ERROR|CheckJNI", re.I)),
    ("surface_backpressure", "P1", re.compile(r"Can't acquire next buffer|Already acquired max frames|BLASTBufferQueue|BufferQueue", re.I)),
    ("xkb", "P1", re.compile(r"xkbcomp|XKB", re.I)),
    ("vnc", "P2", re.compile(r"\b(Xvnc|VNC|RFB|5901)\b", re.I)),
    ("x11", "P2", re.compile(r"\b(XSDL|X11|DISPLAY|6000)\b", re.I)),
    ("network", "P1", re.compile(r"connection refused|timed? out|timeout|ECONNRESET|Broken pipe", re.I)),
    ("oom", "P0", re.compile(r"\b(OOM|Out of memory|low memory|malloc failed)\b", re.I)),
    ("deadlock", "P0", re.compile(r"\b(deadlock|blocked forever|lock timeout)\b", re.I)),
]

# ---------------------------------------------------------------------------
# Manifest Android
# ---------------------------------------------------------------------------

ANDROID_DANGEROUS_PERMISSIONS = {
    "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
    "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_PHONE_STATE",
    "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "ADD_VOICEMAIL",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "USE_SIP", "BODY_SENSORS", "SEND_SMS",
    "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE", "ACCESS_MEDIA_LOCATION", "ACCEPT_HANDOVER", "ACTIVITY_RECOGNITION",
}

# ---------------------------------------------------------------------------
# Patrones de import y de función
# ---------------------------------------------------------------------------

IMPORT_PATTERNS = {
    ".kt": re.compile(r"^import\s+([\w.]+)(\*)?", re.M),
    ".kts": re.compile(r"^import\s+([\w.]+)(\*)?", re.M),
    ".java": re.compile(r"^import\s+(static\s+)?([\w.]+)(\*)?", re.M),
    ".dart": re.compile(r"^import\s+['\"]([^'\"]+)['\"]", re.M),
    ".py": re.compile(r"^from\s+([\w.]+)\s+import\s+([\w*]+)", re.M),
    ".go": re.compile(r"^import\s+\(([^)]*)\)|^import\s+\"([^\"]+)\"", re.M | re.S),
    ".ts": re.compile(r"^import\s+.*?from\s+['\"]([^'\"]+)['\"]", re.M),
    ".tsx": re.compile(r"^import\s+.*?from\s+['\"]([^'\"]+)['\"]", re.M),
    ".js": re.compile(r"^import\s+.*?from\s+['\"]([^'\"]+)['\"]", re.M),
}

FUNC_PATTERNS = {
    ".py": re.compile(r"^def\s+(\w+)\s*\(", re.M),
    ".kt": re.compile(r"^fun\s+(\w+)\s*\(", re.M),
    ".java": re.compile(r"(?:public|private|protected|static|final|synchronized|\s)+[\w<>\[\],\s]+\s+(\w+)\s*\([^;]*\)\s*\{", re.M),
    ".dart": re.compile(r"^(?:[\w<>,?\s]+\s+)?(\w+)\s*\([^;]*\)\s*\{", re.M),
    ".rs": re.compile(r"^(?:pub\s+)?fn\s+(\w+)\s*\(", re.M),
    ".c": re.compile(r"^[\w\s*]+\s+(\w+)\s*\([^;]*\)\s*\{", re.M),
    ".cpp": re.compile(r"^[\w\s*:<>]+\s+(\w+)\s*\([^;]*\)\s*\{", re.M),
}

# Nombres que no son "código muerto" aunque no tengan referencias internas
ENTRY_OR_CALLBACK = {
    "main", "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onCreateView", "onBind", "onUnbind", "onStartCommand", "configure", "initState",
    "build", "dispose", "didChangeDependencies", "onReceive", "JNI_OnLoad",
}

WORD_RE = re.compile(r"\b\w+\b")

# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def fingerprint(*parts: str) -> str:
    """Fingerprint determinístico (sha256 truncado) de un hallazgo o incidente."""
    raw = "|".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]
