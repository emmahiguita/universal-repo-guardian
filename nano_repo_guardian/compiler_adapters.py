from __future__ import annotations
from pathlib import Path
import os
import shutil
from typing import Any

def available_toolchains() -> dict[str, bool]:
    return {x: shutil.which(x) is not None for x in (
        "python","gradle","dart","flutter","cargo","cmake","node","npx","npm","go","dotnet","swift"
    )}

def recommended_verifiers(root: Path) -> list[dict[str, Any]]:
    out = []
    if (root / "Cargo.toml").exists():
        out.append({"ecosystem":"rust","check":"cargo_check","command":["cargo","check","--workspace"]})
    if (root / "pubspec.yaml").exists():
        if shutil.which("flutter"):
            out.append({"ecosystem":"dart_flutter","check":"flutter_analyze","command":["flutter","analyze"]})
        else:
            out.append({"ecosystem":"dart_flutter","check":"dart_analyze","command":["dart","analyze"]})
    if (root / "go.mod").exists():
        out.append({"ecosystem":"go","check":"go_test","command":["go","test","./..."]})
    if (root / "package.json").exists():
        out.append({"ecosystem":"js_ts","check":"project_test","command":["npm","test"]})
    gradlew = root / ("gradlew.bat" if os.name == "nt" else "gradlew")
    if gradlew.exists():
        out.append({"ecosystem":"gradle","check":"gradle_tasks","command":[str(gradlew),"tasks"]})
    elif (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        out.append({"ecosystem":"gradle","check":"gradle_tasks","command":["gradle","tasks"]})
    if (root / "CMakeLists.txt").exists():
        out.append({"ecosystem":"cmake","check":"cmake_configure","command":["cmake","-S",".","-B","build/guardian-check"]})
    return out
