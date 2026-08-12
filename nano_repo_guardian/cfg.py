"""Análisis de flujo de control (CFG) y de datos (taint source→sink)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

SOURCES = re.compile(r"\b(input|request|query|params|argv|stdin|readLine|readline|Intent\.get|extras)\b", re.I)
SINKS = re.compile(r"\b(exec|system|Runtime\.exec|ProcessBuilder|sh\s+-c|bash\s+-c|executeQuery|rawQuery|eval)\b", re.I)


def build_cfg(path: Path):
    """Construye un grafo de flujo de control (CFG) simplificado de un archivo Python."""
    text = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(text)
    nodes = []
    edges = []
    idx = 0

    def new(kind, line, label):
        nonlocal idx
        idx += 1
        nodes.append({"id": idx, "kind": kind, "line": line, "label": label})
        return idx

    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        start = new("function", fn.lineno, fn.name)
        prev = start
        for stmt in fn.body:
            cur = new(type(stmt).__name__, getattr(stmt, "lineno", fn.lineno),
                      ast.dump(stmt, include_attributes=False)[:180])
            edges.append({"from": prev, "to": cur, "kind": "NEXT"})
            prev = cur
            if isinstance(stmt, ast.If):
                for branch_name, branch in (("TRUE", stmt.body), ("FALSE", stmt.orelse)):
                    if branch:
                        b = new("branch", getattr(branch[0], "lineno", stmt.lineno), branch_name)
                        edges.append({"from": cur, "to": b, "kind": branch_name})
        nodes.append({"id": idx + 1, "kind": "end", "line": fn.end_lineno or fn.lineno, "label": fn.name})
        edges.append({"from": prev, "to": idx + 1, "kind": "NEXT"})
        idx += 1
    return {"nodes": nodes, "edges": edges}


def taint_scan(path: Path):
    """Detecta co-ocurrencia textual de fuentes y sumideros (taint superficial).

    Es hipótesis: solo el flujo de datos real (AST/CFG) puede probar la propagación.
    """
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    source_lines = [i for i, line in enumerate(lines, 1) if SOURCES.search(line)]
    sink_lines = [i for i, line in enumerate(lines, 1) if SINKS.search(line)]
    findings = []
    if source_lines and sink_lines:
        findings.append({
            "status": "HYPOTHESIS_TO_VALIDATE", "severity": "P0",
            "category": "source_to_sink_candidate",
            "source_lines": source_lines[:20], "sink_lines": sink_lines[:20],
            "note": "Textual co-occurrence only. AST/dataflow must prove propagation before CONFIRMED.",
        })
    return findings
