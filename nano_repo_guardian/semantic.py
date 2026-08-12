from __future__ import annotations

import ast
import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from nano_repo_guardian.constants import RESOURCE_PAIRS


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8", errors="replace")).hexdigest()[:16]

@dataclass
class Symbol:
    name: str
    kind: str
    file: str
    line: int
    language: str

@dataclass
class Edge:
    source: str
    target: str
    kind: str
    file: str
    line: int

class PythonSemanticVisitor(ast.NodeVisitor):
    def __init__(self, file: str):
        self.file = file
        self.symbols: list[Symbol] = []
        self.edges: list[Edge] = []
        self.scope: list[str] = []
        self.branch_count = 0
        self.returns = 0
        self.raises = 0

    def current(self) -> str:
        return ".".join(self.scope) if self.scope else "<module>"

    def visit_ClassDef(self, node):
        self.symbols.append(Symbol(node.name, "class", self.file, node.lineno, "python"))
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def _visit_function(self, node, kind):
        qname = ".".join(self.scope + [node.name]) if self.scope else node.name
        self.symbols.append(Symbol(qname, kind, self.file, node.lineno, "python"))
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node):
        self._visit_function(node, "function")

    def visit_AsyncFunctionDef(self, node):
        self._visit_function(node, "async_function")

    def visit_Call(self, node):
        target = None
        if isinstance(node.func, ast.Name):
            target = node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            target = ".".join(reversed(parts))
        if target:
            self.edges.append(Edge(self.current(), target, "CALLS", self.file, node.lineno))
        self.generic_visit(node)

    def visit_If(self, node):
        self.branch_count += 1
        self.generic_visit(node)

    def visit_For(self, node):
        self.branch_count += 1
        self.generic_visit(node)

    def visit_While(self, node):
        self.branch_count += 1
        self.generic_visit(node)

    def visit_Try(self, node):
        self.branch_count += len(node.handlers)
        self.generic_visit(node)

    def visit_Return(self, node):
        self.returns += 1
        self.generic_visit(node)

    def visit_Raise(self, node):
        self.raises += 1
        self.generic_visit(node)

def python_semantic_analysis(path: Path, root: Path) -> dict[str, Any]:
    rel = str(path.relative_to(root))
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as e:
        return {"file": rel, "language": "python", "status": "SYNTAX_ERROR",
                "error": {"line": e.lineno or 1, "message": e.msg}, "symbols": [], "edges": []}
    visitor = PythonSemanticVisitor(rel)
    visitor.visit(tree)
    return {
        "file": rel, "language": "python", "status": "OK",
        "symbols": [asdict(x) for x in visitor.symbols],
        "edges": [asdict(x) for x in visitor.edges],
        "metrics": {"branches": visitor.branch_count, "returns": visitor.returns, "raises": visitor.raises},
    }

GENERIC_DEF_PATTERNS = {
    "kotlin": re.compile(r"\b(?:class|interface|object|fun)\s+([A-Za-z_]\w*)"),
    "java": re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_]\w*)"),
    "dart": re.compile(r"\b(?:class|mixin|enum|extension|typedef)\s+([A-Za-z_]\w*)"),
    "rust": re.compile(r"\b(?:fn|struct|enum|trait|impl)\s+([A-Za-z_]\w*)"),
    "c_cpp": re.compile(r"\b(?:class|struct|enum)\s+([A-Za-z_]\w*)"),
    "typescript": re.compile(r"\b(?:class|interface|type|enum|function|const|let)\s+([A-Za-z_$][\w$]*)"),
    "javascript": re.compile(r"\b(?:class|function|const|let|var)\s+([A-Za-z_$][\w$]*)"),
    "go": re.compile(r"\b(?:func|type)\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"),
    "csharp": re.compile(r"\b(?:class|interface|record|struct|enum)\s+([A-Za-z_]\w*)"),
    "swift": re.compile(r"\b(?:class|struct|enum|protocol|actor|func)\s+([A-Za-z_]\w*)"),
}
CALL_PATTERN = re.compile(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(")
CALL_EXCLUDES = {"if","for","while","switch","when","catch","return","sizeof","typeof","class","struct","enum","interface"}

def generic_semantic_analysis(path: Path, root: Path, language: str) -> dict[str, Any]:
    rel = str(path.relative_to(root))
    text = path.read_text(encoding="utf-8", errors="replace")
    pattern = GENERIC_DEF_PATTERNS.get(language)
    symbols = []
    if pattern:
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            symbols.append({"name": m.group(1), "kind": "symbol_candidate", "file": rel, "line": line, "language": language})
    calls = []
    for m in CALL_PATTERN.finditer(text):
        name = m.group(1)
        if name.split(".")[-1] in CALL_EXCLUDES:
            continue
        line = text.count("\n", 0, m.start()) + 1
        calls.append({"source": "<unknown>", "target": name, "kind": "CALL_CANDIDATE", "file": rel, "line": line})
    return {
        "file": rel, "language": language, "status": "HEURISTIC",
        "symbols": symbols[:1000], "edges": calls[:3000],
        "limitations": ["Requires compiler/parser adapter for confirmed semantic results."],
    }

def semantic_repository_snapshot(root: Path, file_language) -> dict[str, Any]:
    analyses, edges = [], []
    symbol_counter: Counter[str] = Counter()
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        lang = file_language(p)
        if not lang:
            continue
        data = python_semantic_analysis(p, root) if lang == "python" else generic_semantic_analysis(p, root, lang)
        analyses.append(data)
        for s in data.get("symbols", []):
            symbol_counter[s["name"]] += 1
        edges.extend(data.get("edges", []))
    return {
        "files_analyzed": len(analyses),
        "semantic_files": analyses[:500],
        "symbol_count": sum(symbol_counter.values()),
        "top_symbols": symbol_counter.most_common(100),
        "edge_count": len(edges),
        "edges": edges[:5000],
        "note": "Python uses AST. Other languages use conservative candidates until compiler/parser adapters verify them.",
    }

def resource_ownership_scan(root: Path) -> list[dict[str, Any]]:
    findings = []
    exts = {".c",".cc",".cpp",".cxx",".h",".hpp",".kt",".java",".dart",".py",".rs"}
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = str(p.relative_to(root))
        for acquire, release in RESOURCE_PAIRS.items():
            a = len(re.findall(rf"\b{re.escape(acquire)}\b", text))
            r = len(re.findall(rf"\b{re.escape(release)}\b", text))
            if a and r < a:
                findings.append({
                    "category": "resource_ownership_imbalance",
                    "severity": "P1" if acquire in {"malloc","calloc","mmap","socket","open","fopen","new"} else "P2",
                    "status": "HYPOTHESIS_TO_VALIDATE", "confidence": 0.55,
                    "file": rel, "resource": acquire, "expected_release": release,
                    "acquire_mentions": a, "release_mentions": r,
                    "fingerprint": _fp("resource", rel, acquire, release),
                    "rationale": "Textual imbalance is triage only; RAII, wrappers or cross-file ownership may explain it.",
                })
    return findings

def call_graph_consistency(snapshot: dict[str, Any]) -> dict[str, Any]:
    symbols = set()
    for f in snapshot.get("semantic_files", []):
        for s in f.get("symbols", []):
            symbols.add(s["name"].split(".")[-1])
    unresolved: Counter[str] = Counter()
    for edge in snapshot.get("edges", []):
        target = edge["target"].split(".")[-1]
        if target not in symbols and target not in {"print","println","len","str","int","list","dict","set","map"}:
            unresolved[target] += 1
    return {
        "unresolved_call_candidates": unresolved.most_common(200),
        "status": "HYPOTHESIS_TO_VALIDATE",
        "note": "Dynamic dispatch, external libraries and framework callbacks may legitimately appear unresolved.",
    }
