"""Métricas cuantitativas y razonamiento formal de software.

Principio: nada de números inventados. Cada salida lleva un campo `nature`:

  MEDIDO     — valor leído directamente del código (nº de nodos, nº de aristas, LOC).
  CALCULADO  — fórmula determinística sobre datos medidos (ciclomática, centralidad de grado, blast radius).
  ESTIMADO   — suma ponderada con pesos razonados (risk, priority, confidence, function risk).
  HEURISTICO — patrón aproximado, sujeto a falso positivo (concurrencia, ownership textual, state flags).

Se usan `radon` (complejidad ciclomática / McCabe) y `networkx` (grafos) cuando están
instalados; si no, se degrada a implementación stdlib y se declara qué se omite.
"""

from __future__ import annotations

import ast
import builtins
import re
from collections import Counter
from pathlib import Path
from typing import Any

from nano_repo_guardian.constants import RESOURCE_CALL_RE as _RESOURCE_CALLS
from nano_repo_guardian.core import iter_files, read_text, safe_root

try:
    from radon.complexity import cc_visit
    from radon.metrics import mi_visit
    HAS_RADON = True
except Exception:  # pragma: no cover - radon opcional
    HAS_RADON = False

try:
    import networkx as nx
    HAS_NX = True
except Exception:  # pragma: no cover - networkx opcional
    HAS_NX = False

# Severidad normalizada a [0,1]. Escala razonada => ESTIMADO.
SEVERITY_NUM = {"P0": 1.0, "P1": 0.8, "P2": 0.55, "P3": 0.3}

_BUILTIN_NAMES = set(dir(builtins))

CODE_EXT_PY = {".py"}


def _clamp01(x: Any) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# 1. Complejidad ciclomática (McCabe). CALCULADO.
# ---------------------------------------------------------------------------

def _ast_cyclomatic(func_node: ast.AST) -> int:
    """M = decisiones + 1 sobre el AST de Python (fallback sin radon)."""
    decisions = 1
    for node in ast.walk(func_node):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            decisions += 1
        elif isinstance(node, ast.BoolOp):
            decisions += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            decisions += 1 + len(node.ifs)
        elif isinstance(node, ast.ExceptHandler):
            decisions += 1
        elif isinstance(node, ast.match_case):
            decisions += 1
    return decisions


def _ast_rows(text: str, rel: str) -> list[dict[str, Any]]:
    tree = ast.parse(text, filename=rel)
    rows = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            rows.append({
                "name": node.name, "kind": "function", "class": None,
                "complexity": _ast_cyclomatic(node), "file": rel, "line": node.lineno,
                "tool": "ast", "nature": "CALCULADO",
            })
    return rows


def _radon_rows(text: str, rel: str) -> list[dict[str, Any]]:
    rows = []
    for b in cc_visit(text):
        if hasattr(b, "methods"):  # radon.complexity.Class
            for m in b.methods:
                rows.append({
                    "name": m.name, "kind": "method", "class": b.name,
                    "complexity": m.complexity, "file": rel, "line": m.lineno,
                    "tool": "radon", "nature": "CALCULADO",
                })
        else:
            rows.append({
                "name": b.name,
                "kind": "method" if getattr(b, "is_method", False) else "function",
                "class": getattr(b, "classname", None),
                "complexity": b.complexity, "file": rel, "line": b.lineno,
                "tool": "radon", "nature": "CALCULADO",
            })
    return rows


def _module_mi(text: str) -> float | None:
    if not HAS_RADON:
        return None
    try:
        mi = mi_visit(text, False)
        if isinstance(mi, (list, tuple)):
            mi = mi[0] if mi else 0.0
        return round(float(mi), 2)
    except Exception:
        return None


def cyclomatic_report(root: str | Path | None = None, max_functions: int = 500) -> dict[str, Any]:
    r = safe_root(root)
    rows: list[dict[str, Any]] = []
    mi_by_file: dict[str, float] = {}
    for p in iter_files(r):
        if p.suffix.lower() not in CODE_EXT_PY:
            continue
        text = read_text(p)
        if not text:
            continue
        rel = str(p.relative_to(r))
        rows.extend(_radon_rows(text, rel) if HAS_RADON else _ast_rows(text, rel))
        mi = _module_mi(text)
        if mi is not None:
            mi_by_file[rel] = mi
    rows.sort(key=lambda x: -x["complexity"])
    if not rows:
        return {"tool": "radon" if HAS_RADON else "ast", "nature": "CALCULADO",
                "functions": [], "summary": {}, "maintainability_index_by_file": {}}
    cc_values = [x["complexity"] for x in rows]
    buckets = Counter(
        "bajo" if c <= 5 else "moderado" if c <= 10 else "complejo" if c <= 20 else "alto_riesgo"
        for c in cc_values
    )
    return {
        "tool": "radon" if HAS_RADON else "ast",
        "nature": "CALCULADO",
        "functions": rows[:max_functions],
        "maintainability_index_by_file": mi_by_file,
        "summary": {
            "functions_analyzed": len(rows),
            "max_complexity": max(cc_values),
            "avg_complexity": round(sum(cc_values) / len(cc_values), 2),
            "buckets": dict(buckets),
        },
    }


# ---------------------------------------------------------------------------
# 2. Grafo de dependencias entre módulos. CALCULADO (networkx).
# ---------------------------------------------------------------------------

def _python_module_of(p: Path, r: Path) -> str:
    parts = list(p.relative_to(r).parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    elif parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    else:
        return ""
    return ".".join(parts)


def _module_edges(r: Path) -> tuple[list[str], set[tuple[str, str]]]:
    py = [p for p in iter_files(r) if p.suffix.lower() in CODE_EXT_PY]
    nodes = [str(p.relative_to(r)) for p in py]
    module_of: dict[str, str] = {}
    for p in py:
        m = _python_module_of(p, r)
        if m:
            module_of[m] = str(p.relative_to(r))
    edges: set[tuple[str, str]] = set()
    for p in py:
        rel = str(p.relative_to(r))
        text = read_text(p)
        if not text:
            continue
        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    tgt = module_of.get(a.name)
                    if tgt and tgt != rel:
                        edges.add((rel, tgt))
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                base = node.module or ""
                for a in node.names:
                    if a.name == "*":
                        continue
                    full = f"{base}.{a.name}" if base else a.name
                    tgt = module_of.get(full) or module_of.get(base)
                    if tgt and tgt != rel:
                        edges.add((rel, tgt))
    return nodes, edges


def dependency_graph_metrics(root: str | Path | None = None) -> dict[str, Any]:
    r = safe_root(root)
    nodes, edges = _module_edges(r)
    result: dict[str, Any] = {
        "nature": "CALCULADO",
        "nodes": len(nodes),
        "edges": len(edges),
    }
    if HAS_NX and nodes:
        g = nx.DiGraph()
        g.add_nodes_from(nodes)
        g.add_edges_from(edges)
        in_deg = dict(g.in_degree())
        out_deg = dict(g.out_degree())
        deg_cent = nx.degree_centrality(g)
        try:
            bet = nx.betweenness_centrality(g) if len(nodes) <= 500 else {}
        except Exception:
            bet = {}
        isolated = sorted(nx.isolates(g))
        sccs = [sorted(c) for c in nx.strongly_connected_components(g) if len(c) > 1]
        cyclic = sorted({m for c in sccs for m in c})
        is_dag = nx.is_directed_acyclic_graph(g)
        centrality = []
        for n in nodes:
            centrality.append({
                "file": n,
                "in_degree": in_deg.get(n, 0),
                "out_degree": out_deg.get(n, 0),
                "degree_centrality": round(deg_cent.get(n, 0.0), 4),
                "betweenness_centrality": round(bet.get(n, 0.0), 4),
            })
        centrality.sort(key=lambda x: -x["degree_centrality"])
        result.update({
            "density": round(nx.density(g), 4),
            "is_dag": is_dag,
            "cyclic_modules": cyclic,
            "isolated_modules": isolated,
            "topological_order": [str(x) for x in nx.topological_sort(g)] if is_dag else None,
            "critical_path": [str(x) for x in nx.dag_longest_path(g)] if is_dag else None,
            "top_central_modules": centrality[:20],
        })
    else:
        result["note"] = "networkx no disponible; centralidad/ciclos omitidos."
    return result


def blast_radius(root: str | Path | None = None, targets: list[str] | None = None) -> dict[str, Any]:
    """Fracción del sistema que depende (transitivamente) de cada módulo objetivo."""
    r = safe_root(root)
    if not HAS_NX:
        return {"nature": "CALCULADO", "results": [], "note": "networkx no disponible."}
    nodes, edges = _module_edges(r)
    g = nx.DiGraph()
    g.add_nodes_from(nodes)
    g.add_edges_from(edges)
    total = len(nodes)
    deg = nx.degree_centrality(g)
    total_deg = sum(deg.values()) or 1.0
    results: list[dict[str, Any]] = []
    for t in (targets or []):
        if t not in g:
            results.append({"target": t, "error": "modulo_no_encontrado", "nature": "CALCULADO"})
            continue
        affected = set(nx.ancestors(g, t)) | {t}
        br = len(affected) / total if total else 0.0
        wbr = sum(deg[n] for n in affected) / total_deg
        results.append({
            "target": t,
            "affected_components": len(affected),
            "total_components": total,
            "blast_radius": round(br, 4),
            "weighted_blast_radius": round(wbr, 4),
            "classification": ("LOCAL" if br < 0.05 else "MODULO" if br < 0.20
                               else "MULTIMODULO" if br < 0.50 else "SISTEMICO"),
            "affected": sorted(affected)[:100],
            "nature": "CALCULADO",
        })
    return {"nature": "CALCULADO", "results": results}


# ---------------------------------------------------------------------------
# 3. Data flow (Python, lineal conservador). CALCULADO / HEURISTICO.
# ---------------------------------------------------------------------------

def _collect_names(node: ast.AST, out: list[ast.Name]) -> None:
    """Recolecta nombres en orden de código, sin entrar en scopes anidados."""
    if isinstance(node, ast.Name):
        out.append(node)
        return
    if isinstance(node, (ast.Lambda, ast.ClassDef)):
        return
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # no descendemos; el cuerpo se analiza aparte como scope propio
        return
    for child in ast.iter_child_nodes(node):
        _collect_names(child, out)


def _dataflow_scope(body_nodes: list[ast.stmt], params: set[str], rel: str, issues: list[dict[str, Any]]) -> None:
    names: list[ast.Name] = []
    for stmt in body_nodes:
        _collect_names(stmt, names)
    names.sort(key=lambda n: (n.lineno, n.col_offset))
    assigned = set(params)
    loaded = set()
    for n in names:
        if isinstance(n.ctx, ast.Load):
            loaded.add(n.id)
            if n.id not in assigned and n.id not in _BUILTIN_NAMES:
                issues.append({
                    "category": "use_before_def_candidate", "name": n.id, "line": n.lineno,
                    "nature": "CALCULADO",
                    "note": "análisis lineal sin sensibilidad a ramas; puede ser global/param/closure",
                })
        elif isinstance(n.ctx, ast.Store):
            assigned.add(n.id)
    # def-sin-uso: asignadas y nunca leídas en el scope => HEURISTICO
    for name in sorted(assigned - loaded):
        if name in params:
            continue
        issues.append({
            "category": "def_without_use_candidate", "name": name,
            "nature": "HEURISTICO",
            "note": "asignación sin lectura en el scope; verificar uso vía closure/reflexión",
        })


def data_flow_issues(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    rel = str(p)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"file": rel, "status": "UNREADABLE", "issues": [], "nature": "CALCULADO"}
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as e:
        return {"file": rel, "status": "SYNTAX_ERROR", "line": e.lineno or 1, "issues": [], "nature": "CALCULADO"}
    issues: list[dict[str, Any]] = []
    _dataflow_scope(tree.body, set(), rel, issues)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = {a.arg for a in node.args.args + node.args.kwonlyargs}
            if node.args.vararg:
                args.add(node.args.vararg.arg)
            if node.args.kwarg:
                args.add(node.args.kwarg.arg)
            _dataflow_scope(node.body, args, rel, issues)
    return {
        "file": rel, "nature": "CALCULADO",
        "issues": issues,
        "note": "lineal y conservador: sin sensibilidad a ramas ni resolución inter-procedural",
    }


# ---------------------------------------------------------------------------
# 4. Concurrencia. HEURISTICO.
# ---------------------------------------------------------------------------

CONCURRENCY_PATTERNS = [
    ("rust_static_mut", "P1", re.compile(r"\bstatic\s+mut\b"), "estado global mutable sin sincronización (Rust)"),
    ("kotlin_lateinit", "P2", re.compile(r"\blateinit\s+var\b"), "inicialización diferida; verificar acceso antes de init"),
    ("dart_late", "P2", re.compile(r"\blate\s+(?:final\s+)?\w+\s+\w+"), "variable late; verificar acceso antes de init"),
    ("python_global_write", "P2", re.compile(r"^\s*global\s+\w+", re.M), "escritura a global desde función"),
    ("python_nonlocal", "P2", re.compile(r"^\s*nonlocal\s+\w+", re.M), "escritura a variable de closure"),
    ("shared_static_var", "P2", re.compile(r"\bstatic\s+[\w<>,: ]+\s+\w+\s*;"), "variable estática compartida (C/C++/Java)"),
    ("unsafe_block", "P2", re.compile(r"\bunsafe\s*\{"), "bloque unsafe; verificar invariantes de memoria"),
    ("volatile_flag", "P3", re.compile(r"\bvolatile\b"), "verificar visibilidad cross-thread"),
]


def concurrency_flags(root: str | Path | None = None) -> dict[str, Any]:
    r = safe_root(root)
    out: list[dict[str, Any]] = []
    for p in iter_files(r):
        if p.suffix.lower() not in {".py", ".kt", ".kts", ".java", ".dart", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp"}:
            continue
        text = read_text(p)
        if not text:
            continue
        rel = str(p.relative_to(r))
        for cat, sev, pat, why in CONCURRENCY_PATTERNS:
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                out.append({
                    "category": cat, "severity": sev, "file": rel, "line": line,
                    "evidence": m.group(0)[:120], "rationale": why, "nature": "HEURISTICO",
                })
    return {"nature": "HEURISTICO", "count": len(out), "flags": out[:500]}


# ---------------------------------------------------------------------------
# 5. Complejidad de estado (techo 2^n). HEURISTICO en la identificación.
# ---------------------------------------------------------------------------

STATE_HINT = re.compile(
    r"\b(is[A-Z]\w+|has[A-Z]\w+|running|starting|stopping|connected|initialized|ready|loaded|failed|paused|disposed|active)\b"
)


def state_complexity(root: str | Path | None = None) -> dict[str, Any]:
    r = safe_root(root)
    found: Counter[str] = Counter()
    for p in iter_files(r):
        if p.suffix.lower() not in {".py", ".kt", ".kts", ".java", ".dart", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".ts", ".tsx", ".js", ".jsx"}:
            continue
        text = read_text(p)
        if not text:
            continue
        for m in STATE_HINT.finditer(text):
            found[m.group(1)] += 1
    flags = found.most_common(50)
    n = len(flags)
    return {
        "nature": "HEURISTICO",
        "state_flag_candidates": [{"flag": k, "occurrences": v} for k, v in flags],
        "upper_bound_states": 2 ** n if n <= 30 else None,
        "note": "identificación de banderas de estado por nombre es heurística; 2^n es techo teórico, no el nº real de estados válidos.",
    }


# ---------------------------------------------------------------------------
# 6. Fórmulas de scoring. ESTIMADO (pesos razonados) / HEURISTICO.
# ---------------------------------------------------------------------------

def risk_score(severity: str, probability: float, blast_radius: float, centrality: float, detectability: float) -> dict[str, Any]:
    s = _clamp01(SEVERITY_NUM.get(severity, 0.5))
    p, b, c, d = (_clamp01(x) for x in (probability, blast_radius, centrality, detectability))
    raw = s * p * b * c * d
    band = ("BAJO" if raw < 0.19 else "MODERADO" if raw < 0.39 else "ALTO" if raw < 0.59
            else "MUY_ALTO" if raw < 0.79 else "CRITICO")
    return {
        "risk_score": round(raw * 100, 1), "raw": round(raw, 4), "classification": band,
        "factors": {"severity": round(s, 3), "probability": p, "blast_radius": b, "centrality": c, "detectability": d},
        "nature": "ESTIMADO",
    }


def bug_priority(severity: str, probability: float, blast_radius: float, centrality: float,
                 data_loss: float = 0.0, security: float = 0.0) -> dict[str, Any]:
    s = _clamp01(SEVERITY_NUM.get(severity, 0.5))
    p, b, c, dl, sec = (_clamp01(x) for x in (probability, blast_radius, centrality, data_loss, security))
    score = 0.30 * s + 0.20 * p + 0.20 * b + 0.15 * c + 0.10 * dl + 0.05 * sec
    return {"priority": round(score * 100, 1), "nature": "ESTIMADO"}


def confidence_score(direct: float = 0.0, callgraph: float = 0.0, state: float = 0.0,
                     errorpath: float = 0.0, runtime: float = 0.0) -> dict[str, Any]:
    d, cg, st, ep, rt = (_clamp01(x) for x in (direct, callgraph, state, errorpath, runtime))
    conf = 0.35 * d + 0.20 * cg + 0.15 * st + 0.15 * ep + 0.15 * rt
    band = "BAJA" if conf < 0.40 else "MEDIA" if conf < 0.70 else "ALTA" if conf < 0.90 else "MUY_ALTA"
    return {"confidence": round(conf, 3), "band": band, "nature": "ESTIMADO"}


def module_health(bug_penalty: float = 0.0, complexity_penalty: float = 0.0, coupling_penalty: float = 0.0,
                  state_penalty: float = 0.0, concurrency_penalty: float = 0.0, resource_penalty: float = 0.0) -> dict[str, Any]:
    pens = sum(max(0.0, float(x)) for x in (bug_penalty, complexity_penalty, coupling_penalty,
                                            state_penalty, concurrency_penalty, resource_penalty))
    health = max(0.0, 100.0 - pens)
    return {"health_index": round(health, 1), "nature": "HEURISTICO",
            "note": "penalizaciones subjetivas; usar solo para comparar módulos, no como verdad absoluta"}


# ---------------------------------------------------------------------------
# 7. Riesgo de función (FR). Medidas reales del AST => ESTIMADO.
# ---------------------------------------------------------------------------

_CONC_CALLS = re.compile(r"Thread|Executor|async|await|launch|coroutine|lock|mutex|synchronized|submit|join", re.I)


def _call_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _func_metrics(node: ast.AST) -> dict[str, int]:
    calls = assigns = branches = returns = raises = resources = conc = 0
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            calls += 1
            nm = _call_name(child.func)
            if nm and _RESOURCE_CALLS.search(nm):
                resources += 1
            if nm and _CONC_CALLS.search(nm):
                conc += 1
        elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            assigns += 1
        elif isinstance(child, (ast.If, ast.For, ast.While, ast.IfExp, ast.ExceptHandler)):
            branches += 1
        elif isinstance(child, ast.BoolOp):
            branches += len(child.values) - 1
        elif isinstance(child, ast.Return):
            returns += 1
        elif isinstance(child, ast.Raise):
            raises += 1
    return {"calls": calls, "assigns": assigns, "branches": branches,
            "returns": returns, "raises": raises, "resources": resources, "concurrency": conc}


def function_risk(complexity: float, metrics: dict[str, int], centrality: float) -> dict[str, Any]:
    cc_n = _clamp01(complexity / 20.0)
    dep_n = _clamp01(metrics.get("calls", 0) / 20.0)
    state_n = _clamp01(metrics.get("assigns", 0) / 20.0)
    conc_n = _clamp01(metrics.get("concurrency", 0) / 5.0)
    res_n = _clamp01(metrics.get("resources", 0) / 5.0)
    err_n = _clamp01((metrics.get("raises", 0) + metrics.get("branches", 0)) / 20.0)
    cent_n = _clamp01(centrality)
    fr = 0.20 * cc_n + 0.15 * dep_n + 0.15 * state_n + 0.15 * conc_n + 0.10 * res_n + 0.10 * err_n + 0.15 * cent_n
    band = "BAJO" if fr < 0.25 else "MEDIO" if fr < 0.50 else "ALTO" if fr < 0.75 else "CRITICO"
    return {
        "function_risk": round(fr, 3), "classification": band,
        "factors": {"cyclomatic_n": round(cc_n, 3), "dependency_n": round(dep_n, 3), "state_n": round(state_n, 3),
                    "concurrency_n": round(conc_n, 3), "resource_n": round(res_n, 3), "error_n": round(err_n, 3),
                    "centrality_n": round(cent_n, 3)},
        "nature": "ESTIMADO",
    }


# ---------------------------------------------------------------------------
# 8. Reporte cuantitativo agregado.
# ---------------------------------------------------------------------------

def quantitative_report(root: str | Path | None = None, top_n: int = 20) -> dict[str, Any]:
    r = safe_root(root)
    cyc = cyclomatic_report(r)
    graph = dependency_graph_metrics(r)
    conc = concurrency_flags(r)
    state = state_complexity(r)

    # centralidad por archivo (para el FR de las top funciones)
    centrality_by_file: dict[str, float] = {}
    for m in graph.get("top_central_modules", []):
        centrality_by_file[m["file"]] = m.get("degree_centrality", 0.0)

    # re-parse de los archivos de las top-N funciones para medir métricas reales
    file_cache: dict[str, ast.AST | None] = {}
    candidates: list[dict[str, Any]] = []
    for f in cyc["functions"][:top_n]:
        rel = f["file"]
        if rel not in file_cache:
            p = r / rel
            txt = read_text(p)
            try:
                file_cache[rel] = ast.parse(txt, filename=rel) if txt else None
            except SyntaxError:
                file_cache[rel] = None
        tree = file_cache.get(rel)
        metrics = {"calls": 0, "assigns": 0, "branches": 0, "returns": 0, "raises": 0, "resources": 0, "concurrency": 0}
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == f["name"]:
                    metrics = _func_metrics(node)
                    break
        fr = function_risk(f["complexity"], metrics, centrality_by_file.get(rel, 0.0))
        candidates.append({
            "name": f["name"], "file": rel, "line": f["line"],
            "cyclomatic_complexity": f["complexity"],
            "measured_metrics": metrics,
            **fr,
        })

    return {
        "nature_summary": "MEDIDO/CALCULADO para métricas estructurales; ESTIMADO/HEURISTICO para scores.",
        "cyclomatic": cyc,
        "graph": graph,
        "concurrency": conc,
        "state": state,
        "risk_candidates": candidates,
    }
