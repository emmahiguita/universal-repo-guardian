from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:
    raise SystemExit("Instala el SDK de MCP: pip install mcp") from exc

# Soporte dual: ejecutado como script (python server.py) o como módulo (python -m nano_repo_guardian.server).
# Al lanzarlo como script no hay parent package y el import relativo falla.
try:
    from .core import (
        analyze_log_text,
        android_manifest_audit,
        apply_knowledge,
        architecture_smells,
        build_compatibility_matrix,
        dead_code_scan,
        deep_snapshot,
        dependency_inventory,
        duplicate_scan,
        hotspot_scan,
        imports_audit,
        incremental_scan,
        inventory,
        load_knowledge,
        record_verified_outcome,
        risk_scan,
        search_code,
        syntax_scan,
        verify,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from nano_repo_guardian.core import (
        analyze_log_text,
        android_manifest_audit,
        apply_knowledge,
        architecture_smells,
        build_compatibility_matrix,
        dead_code_scan,
        deep_snapshot,
        dependency_inventory,
        duplicate_scan,
        hotspot_scan,
        imports_audit,
        incremental_scan,
        inventory,
        load_knowledge,
        record_verified_outcome,
        risk_scan,
        search_code,
        syntax_scan,
        verify,
    )

# Windows: stdout en cp1252 rompe el protocolo JSON-RPC si hay texto no-ASCII.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
except (AttributeError, OSError, ValueError):
    pass

ROOT = Path(os.environ.get("NANO_REPO_ROOT", os.getcwd())).resolve()
mcp = FastMCP("universal-repo-guardian")

@mcp.tool()
def repo_inventory() -> dict:
    """Inventario del repositorio: lenguajes, archivos de build, archivos críticos de runtime, tests y soporte Graphify.
    Úsalo como PRIMER paso de cualquier auditoría: da el mapa de qué hay antes de escanear."""
    return inventory(ROOT)

@mcp.tool()
def syntax_and_malformed_scan() -> list[dict]:
    """Escaneo determinístico de sintaxis/malformación: Python (ast), JSON (parseo real), marcadores de merge conflict.
    Hallazgos aquí son CONFIRMED — no hipótesis."""
    return syntax_scan(ROOT)

@mcp.tool()
def repo_search(query: str, max_results: int = 100) -> list[dict]:
    """Búsqueda de texto en código/config sin ejecución de shell. Devuelve archivo, línea y texto.
    Úsalo para investigar candidatos P0/P1 encontrados por risk_boundaries."""
    return search_code(query, ROOT, max_results)

@mcp.tool()
def risk_boundaries(max_findings: int = 1500) -> list[dict]:
    """Fronteras de riesgo: manejo de errores, procesos, memoria nativa, JNI/FFI, concurrencia, red, TLS, shell/SQL, Flutter/Android.
    Resultados son HYPOTHESIS_TO_VALIDATE salvo evidencia determinística (merge conflict). Incluye ajuste de confianza por conocimiento verificado."""
    return apply_knowledge(risk_scan(ROOT, max_findings), ROOT)

@mcp.tool()
def architecture_risks() -> list[dict]:
    """Candidatos a god-file y complejidad de ramas alta (archivos >= 1200 líneas o >= 100 ramas). Requieren revisión de arquitectura."""
    return architecture_smells(ROOT)

@mcp.tool()
def duplicate_code_scan(min_lines: int = 6, max_groups: int = 100) -> list[dict]:
    """Bloques de código duplicados exactos entre archivos. Match exacto para evitar falsos positivos."""
    return duplicate_scan(ROOT, min_lines, max_groups)

@mcp.tool()
def hotspot_files(top_n: int = 50) -> list[dict]:
    """Ranking de hotspots de ingeniería por tamaño + complejidad de ramas + densidad de fronteras de riesgo."""
    return hotspot_scan(ROOT, top_n)

@mcp.tool()
def compatibility_matrix() -> dict:
    """Matriz de compatibilidad local: compileSdk/targetSdk/NDK, wrapper de Gradle, Flutter/Dart, Rust, CMake, Node, Python, Go.
    La compatibilidad remota con upstream requiere verificación autoritativa aparte."""
    return build_compatibility_matrix(ROOT)

@mcp.tool()
def dependencies() -> list[dict]:
    """Inventario de dependencias declaradas (npm/pub/Gradle/pip) sin resolver registros remotos."""
    return dependency_inventory(ROOT)

@mcp.tool()
def analyze_log(log_text: str) -> dict:
    """Agrupa errores de log por fingerprint y encuentra la señal de alta severidad MÁS TEMPRANA.
    Reglas: SIGSEGV/tombstone, FATAL EXCEPTION, rc=126/127, linker, JNI, BufferQueue, XKB, VNC, OOM, deadlock.
    Pega el texto del log — no ruta de archivo."""
    return analyze_log_text(log_text)

@mcp.tool()
def scan_changed_files(staged: bool = False) -> dict:
    """Escaneo incremental rápido sobre archivos cambiados según git diff. Ideal en cada cambio de código."""
    return incremental_scan(ROOT, staged=staged)

@mcp.tool()
def repository_deep_snapshot() -> dict:
    """Snapshot completo de ingeniería: inventario + compatibilidad + dependencias + sintaxis + arquitectura + hotspots + resumen de riesgos + conocimiento."""
    return deep_snapshot(ROOT)

@mcp.tool()
def knowledge_status() -> dict:
    """Lee la base de aprendizaje verificada local (.repo-guardian/knowledge.json)."""
    return load_knowledge(ROOT)

@mcp.tool()
def learn_verified_outcome(
    fingerprint: str,
    outcome: str,
    root_cause: str = "",
    fix: str = "",
    evidence: str = "",
) -> dict:
    """Aprendizaje versionado SOLO de resultados verificados explícitamente. Escribe únicamente .repo-guardian/knowledge.json.
    outcome debe ser: CONFIRMED, FALSE_POSITIVE, FIX_PASS, FIX_FAIL o REGRESSION.
    Nunca registres aprendizaje de una suposición del modelo sin evidencia."""
    return record_verified_outcome(fingerprint, outcome, ROOT, root_cause, fix, evidence)

@mcp.tool()
def run_verification(check: str, timeout: int = 180) -> dict:
    """Ejecuta un comando de verificación de allow-list estricta. NO expone ejecución de shell arbitraria.
    Checks disponibles: git_diff_check, cargo_check, cargo_fmt_check, cargo_clippy, dart_analyze, flutter_analyze, go_test."""
    return verify(check, ROOT, timeout)

@mcp.tool()
def android_manifest_audit_tool() -> list[dict]:
    """Audita AndroidManifest.xml con parseo XML real: permisos peligrosos conocidos, componentes exportados
    (explícito o implícito por intent-filter), usesCleartextTraffic, allowBackup, debuggable, providers expuestos.
    Cubre la sección de permisos/seguridad Android de una auditoría completa."""
    return android_manifest_audit(ROOT)

@mcp.tool()
def imports_audit_tool() -> dict:
    """Audita imports por archivo: duplicados (CONFIRMED), wildcards y candidatos a no usados (HYPOTHESIS_TO_VALIDATE).
    La heurística de no-usados compara el último segmento del import contra el cuerpo del archivo — verificar antes de borrar."""
    return imports_audit(ROOT)

@mcp.tool()
def dead_code_scan_tool(max_files: int = 2000) -> list[dict]:
    """Candidatos a código muerto: funciones definidas sin menciones en el resto del repo (heurística por nombre).
    Siempre HYPOTHESIS_TO_VALIDATE P3 — la reflexión, callbacks, exports y entry points pueden falsear el conteo."""
    return dead_code_scan(ROOT, max_files)

@mcp.prompt()
def universal_deep_audit() -> str:
    return """Actúa como auditor principal de QA/forensia de código.

Orden obligatorio:
1. repo_inventory
2. si existe graphify-out/graph.json, usa Graphify antes de navegar crudamente
3. syntax_and_malformed_scan
4. compatibility_matrix + dependencies
5. architecture_risks + hotspot_files + duplicate_code_scan
6. android_manifest_audit_tool (si hay AndroidManifest.xml)
7. imports_audit_tool + dead_code_scan_tool
8. risk_boundaries
9. repo_search dirigido sobre candidatos P0/P1
10. correlaciona logs suministrados con analyze_log
11. reconstruye grafos de runtime/ciclo de vida/propiedad
12. clasifica cada afirmación:
    CONFIRMED / HYPOTHESIS_TO_VALIDATE / DISCARDED / INFORMATIONAL
13. separa síntoma de causa raíz
14. crea grafo de dependencias de bugs
15. genera sprints de corrección de bugs
16. propone corrección mínima antes que refactor estructural
17. define verificación antes/después, regresión y rollback

Nunca llames bug confirmado a un patrón sin evidencia.
Nunca llames PASS a un fix solo porque el build compila.
"""

@mcp.prompt()
def bug_sprint_report() -> str:
    return """Genera un informe de ingeniería de corrección de bugs:
- matriz de salud ejecutiva
- P0/P1/P2/P3 confirmados
- grafo de dependencias de bugs
- Sprint 0 baseline
- bloqueadores de build
- crashes/seguridad/integridad de datos
- lógica/estado/ciclo de vida
- procesos/memoria/concurrencia
- conectividad/compatibilidad
- rendimiento
- arquitectura/limpieza
- regresión final

Para cada bug incluye:
ID, evidencia, archivo/símbolo, causa raíz, impacto, fix mínimo, fix estructural,
archivos a modificar, archivos a no tocar, test, verificación de ciclo de vida,
limpieza de recursos, regresión, rollback y closure gate.
"""

@mcp.prompt()
def verify_fix() -> str:
    return """Verification Gate:
baseline -> reproducir -> causa raíz -> patch mínimo -> checks estáticos ->
build -> test enfocado -> runtime -> ciclo de vida -> limpieza de recursos ->
regresión adyacente -> revisión del diff.
Estado final solo puede ser: PASS / PARTIAL / FAIL / UNVERIFIED.
"""


# === UNIVERSAL REPO GUARDIAN V3 SEMANTIC TOOLS ===
# Imports a mitad de archivo a propósito: deben ejecutarse después del bootstrap de
# sys.path (soporte script/module). Por eso llevan noqa: E402.
from nano_repo_guardian.benchmark import benchmark_expectations  # noqa: E402
from nano_repo_guardian.compiler_adapters import available_toolchains, recommended_verifiers  # noqa: E402
from nano_repo_guardian.language_adapters import adapter_inventory, detect_adapter  # noqa: E402
from nano_repo_guardian.semantic import (  # noqa: E402
    call_graph_consistency,
    resource_ownership_scan,
    semantic_repository_snapshot,
)


def _v3_language_for(path: Path) -> str | None:
    adapter = detect_adapter(path)
    return adapter.language if adapter else None

@mcp.tool()
def language_adapter_inventory() -> dict:
    return adapter_inventory(ROOT)

@mcp.tool()
def semantic_program_snapshot() -> dict:
    return semantic_repository_snapshot(ROOT, _v3_language_for)

@mcp.tool()
def resource_ownership_audit() -> list[dict]:
    return resource_ownership_scan(ROOT)

@mcp.tool()
def semantic_call_consistency() -> dict:
    return call_graph_consistency(semantic_repository_snapshot(ROOT, _v3_language_for))

@mcp.tool()
def toolchain_status() -> dict:
    return available_toolchains()

@mcp.tool()
def recommended_compiler_verifiers() -> list[dict]:
    return recommended_verifiers(ROOT)

@mcp.tool()
def benchmark_fixture_status() -> dict:
    return benchmark_expectations(ROOT)
# === END V3 SEMANTIC TOOLS ===


# === UNIVERSAL REPO GUARDIAN QUANTITATIVE METRICS ===
from nano_repo_guardian import metrics as _quant  # noqa: E402


@mcp.tool()
def cyclomatic_complexity_report() -> dict:
    return _quant.cyclomatic_report(ROOT)

@mcp.tool()
def dependency_graph_metrics() -> dict:
    return _quant.dependency_graph_metrics(ROOT)

@mcp.tool()
def quantitative_risk_report() -> dict:
    return _quant.quantitative_report(ROOT)
# === END QUANTITATIVE METRICS ===


# === UNIVERSAL REPO GUARDIAN CORRECTION GATE ===
from nano_repo_guardian.correction import correction_gate as _correction_gate  # noqa: E402


@mcp.tool()
def correction_gate(action: str, fingerprint: str = "", verdict: str = "") -> dict:
    """Puerta de corrección: límites anti-bucle y checkpoints humanos.

    action: register_attempt | finalize | resolve_checkpoint | reset | status
    """
    return _correction_gate(action, fingerprint, verdict, ROOT)
# === END CORRECTION GATE ===


def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
