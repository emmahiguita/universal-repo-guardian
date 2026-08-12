"""Constantes compartidas — fuente única de verdad para conceptos repetidos.

Antes, el mapeo recurso -> liberación estaba duplicado en varios módulos
(semantic.py, metrics.py, guardian_cfg/ownership.py). Cualquier cambio de regla
había que replicarlo en cada copia, con riesgo de divergencia.
"""

from __future__ import annotations

import hashlib
import re

# Recurso -> operación que lo libera. Fuente canónica para:
#   - auditoría de ownership (semantic.resource_ownership_scan)
#   - scoring de riesgo de función (metrics.function_risk)
#   - paquete guardian_cfg (ownership)
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

# Tokens que tocan recursos (adquisición + liberación + dispose) para detectar
# llamadas relacionadas con recursos en el riesgo de función.
RESOURCE_CALL_TOKENS: frozenset[str] = frozenset(
    set(RESOURCE_PAIRS) | set(RESOURCE_PAIRS.values()) | {"dispose"}
)

# Orden por longitud descendente para que los tokens largos matcheen antes
# (ej. "TextEditingController" antes de "Text").
RESOURCE_CALL_RE = re.compile(
    "|".join(re.escape(t) for t in sorted(RESOURCE_CALL_TOKENS, key=len, reverse=True)),
    re.IGNORECASE,
)


def fingerprint(*parts: str) -> str:
    """Fingerprint determinístico (sha256 truncado) de un hallazgo o incidente.

    Fuente única: antes estaba duplicado en core.py (`_fingerprint`) y semantic.py (`_fp`).
    """
    raw = "|".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]
