from __future__ import annotations
import ast
from pathlib import Path
from dataclasses import dataclass, asdict

@dataclass
class Symbol:
    name: str
    kind: str
    line: int

@dataclass
class Call:
    source: str
    target: str
    line: int

class Visitor(ast.NodeVisitor):
    def __init__(self):
        self.scope=[]
        self.symbols=[]
        self.calls=[]
        self.branches=0

    def current(self):
        return ".".join(self.scope) if self.scope else "<module>"

    def visit_ClassDef(self,node):
        self.symbols.append(Symbol(node.name,"class",node.lineno))
        self.scope.append(node.name); self.generic_visit(node); self.scope.pop()

    def visit_FunctionDef(self,node):
        q=".".join(self.scope+[node.name]) if self.scope else node.name
        self.symbols.append(Symbol(q,"function",node.lineno))
        self.scope.append(node.name); self.generic_visit(node); self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self,node):
        target=None
        if isinstance(node.func,ast.Name):
            target=node.func.id
        elif isinstance(node.func,ast.Attribute):
            target=node.func.attr
        if target:
            self.calls.append(Call(self.current(),target,node.lineno))
        self.generic_visit(node)

    def visit_If(self,node):
        self.branches += 1; self.generic_visit(node)
    def visit_For(self,node):
        self.branches += 1; self.generic_visit(node)
    def visit_While(self,node):
        self.branches += 1; self.generic_visit(node)
    def visit_Try(self,node):
        self.branches += len(node.handlers); self.generic_visit(node)

def analyze(path: Path):
    text=path.read_text(encoding="utf-8",errors="replace")
    try:
        tree=ast.parse(text,filename=str(path))
    except SyntaxError as e:
        return {"status":"SYNTAX_ERROR","line":e.lineno or 1,"message":e.msg}
    v=Visitor(); v.visit(tree)
    return {"status":"OK","symbols":[asdict(x) for x in v.symbols],
            "calls":[asdict(x) for x in v.calls],"branches":v.branches}
