from __future__ import annotations

import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AdapterInfo:
    language: str
    extensions: tuple[str, ...]
    parser_mode: str
    verifier: str | None = None

ADAPTERS = (
    AdapterInfo("python", (".py",), "ast", "python_compile"),
    AdapterInfo("kotlin", (".kt", ".kts"), "compiler", "gradle_compile"),
    AdapterInfo("java", (".java",), "compiler", "gradle_compile"),
    AdapterInfo("dart", (".dart",), "analyzer", "dart_analyze"),
    AdapterInfo("rust", (".rs",), "compiler", "cargo_check"),
    AdapterInfo("c_cpp", (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"), "compiler", "cmake_build"),
    AdapterInfo("typescript", (".ts", ".tsx"), "compiler", "tsc_noemit"),
    AdapterInfo("javascript", (".js", ".jsx", ".mjs", ".cjs"), "parser", "node_check"),
    AdapterInfo("go", (".go",), "compiler", "go_test"),
    AdapterInfo("csharp", (".cs",), "compiler", "dotnet_build"),
    AdapterInfo("swift", (".swift",), "compiler", "swift_build"),
)
EXT_TO_ADAPTER = {ext: a for a in ADAPTERS for ext in a.extensions}

def detect_adapter(path: Path) -> AdapterInfo | None:
    return EXT_TO_ADAPTER.get(path.suffix.lower())

def adapter_inventory(root: Path) -> dict[str, Any]:
    counts: dict[str, int] = {}
    grouped: dict[str, list[str]] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        adapter = detect_adapter(p)
        if not adapter:
            continue
        counts[adapter.language] = counts.get(adapter.language, 0) + 1
        grouped.setdefault(adapter.language, []).append(str(p.relative_to(root)))
    return {
        "languages": counts,
        "files": {k: v[:200] for k, v in grouped.items()},
        "adapters": [asdict(x) for x in ADAPTERS],
    }

def toolchain_availability() -> dict[str, bool]:
    commands = {
        "python": sys.executable,
        "gradle": "gradle",
        "dart": "dart",
        "flutter": "flutter",
        "cargo": "cargo",
        "cmake": "cmake",
        "node": "node",
        "npx": "npx",
        "go": "go",
        "dotnet": "dotnet",
        "swift": "swift",
    }
    return {name: shutil.which(cmd) is not None for name, cmd in commands.items()}
