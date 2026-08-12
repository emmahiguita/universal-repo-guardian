from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
import shutil

@dataclass(frozen=True)
class LanguageAdapter:
    language: str
    extensions: tuple[str, ...]
    preferred_engine: str
    compiler_probe: str | None

ADAPTERS = (
    LanguageAdapter("python", (".py",), "python_ast", "python"),
    LanguageAdapter("kotlin", (".kt",".kts"), "tree_sitter_or_compiler", "kotlinc"),
    LanguageAdapter("java", (".java",), "tree_sitter_or_compiler", "javac"),
    LanguageAdapter("dart", (".dart",), "tree_sitter_or_analyzer", "dart"),
    LanguageAdapter("rust", (".rs",), "tree_sitter_or_compiler", "cargo"),
    LanguageAdapter("c_cpp", (".c",".cc",".cpp",".cxx",".h",".hpp"), "tree_sitter_or_compiler", "clang"),
    LanguageAdapter("typescript", (".ts",".tsx"), "tree_sitter_or_compiler", "tsc"),
    LanguageAdapter("javascript", (".js",".jsx",".mjs",".cjs"), "tree_sitter_or_parser", "node"),
    LanguageAdapter("go", (".go",), "tree_sitter_or_compiler", "go"),
    LanguageAdapter("csharp", (".cs",), "tree_sitter_or_compiler", "dotnet"),
    LanguageAdapter("swift", (".swift",), "tree_sitter_or_compiler", "swift"),
)
EXT_MAP = {e:a for a in ADAPTERS for e in a.extensions}

def adapter_for(path: Path) -> LanguageAdapter | None:
    return EXT_MAP.get(path.suffix.lower())

def coverage() -> list[dict[str, Any]]:
    return [asdict(a) | {"compiler_available": bool(a.compiler_probe and shutil.which(a.compiler_probe))}
            for a in ADAPTERS]
