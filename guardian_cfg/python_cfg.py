from __future__ import annotations

import ast
from pathlib import Path


def build_cfg(path: Path):
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
