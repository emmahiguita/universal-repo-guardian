"""Facade de compatibilidad — re-exporta la API pública.

La implementación está repartida en sub-módulos con una sola responsabilidad:

  constants  — datos y reglas (RISK_RULES, LOG_RULES, extensiones, build files...)
  fsio       — sistema de archivos (safe_root, iter_files, read_text, is_text_candidate)
  scanners   — escáneres de repositorio (sintaxis, riesgo, duplicados, manifest, imports...)
  knowledge  — base de conocimiento adaptativa
  analysis   — contexto y agregación (inventario, compatibilidad, logs, verify, deep_snapshot)

Este módulo existe para no romper a los consumidores que importan desde
`nano_repo_guardian.core` (server.py, metrics.py, tests).
"""

from __future__ import annotations

from . import __version__ as VERSION
from .analysis import (
    analyze_log_text,
    build_compatibility_matrix,
    deep_snapshot,
    dependency_inventory,
    git_changed_files,
    incremental_scan,
    inventory,
    verify,
)
from .correction import correction_gate
from .fsio import is_text_candidate, iter_files, read_text, safe_root
from .knowledge import apply_knowledge, knowledge_dir, load_knowledge, record_verified_outcome
from .scanners import (
    Finding,
    android_manifest_audit,
    architecture_smells,
    dead_code_scan,
    duplicate_scan,
    hotspot_scan,
    imports_audit,
    risk_scan,
    search_code,
    syntax_scan,
)

__all__ = [
    "Finding",
    "VERSION",
    "analyze_log_text",
    "android_manifest_audit",
    "apply_knowledge",
    "architecture_smells",
    "build_compatibility_matrix",
    "correction_gate",
    "dead_code_scan",
    "deep_snapshot",
    "dependency_inventory",
    "duplicate_scan",
    "git_changed_files",
    "hotspot_scan",
    "imports_audit",
    "incremental_scan",
    "inventory",
    "is_text_candidate",
    "iter_files",
    "knowledge_dir",
    "load_knowledge",
    "read_text",
    "record_verified_outcome",
    "risk_scan",
    "safe_root",
    "search_code",
    "syntax_scan",
    "verify",
]
