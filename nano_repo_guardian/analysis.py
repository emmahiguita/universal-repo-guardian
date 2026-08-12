"""Análisis de contexto y agregación.

Inventario, matriz de compatibilidad, dependencias, análisis de logs, búsqueda,
escaneo incremental, verificación con allow-list y snapshot profundo.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from nano_repo_guardian import __version__ as VERSION
from nano_repo_guardian.constants import BUILD_NAMES, LOG_RULES, SEVERITY_WEIGHTS
from nano_repo_guardian.constants import fingerprint as _fingerprint
from nano_repo_guardian.fsio import iter_files, read_text, safe_root
from nano_repo_guardian.knowledge import apply_knowledge, load_knowledge
from nano_repo_guardian.scanners import architecture_smells, hotspot_scan, risk_scan, syntax_scan


def inventory(root: str | Path | None = None) -> dict[str, Any]:
    r = safe_root(root)
    fs = list(iter_files(r))
    ext_counts: Counter[str] = Counter()
    builds, critical, tests = [], [], []
    for p in fs:
        ext_counts[p.suffix.lower() or "<none>"] += 1
        rel = str(p.relative_to(r))
        low = rel.lower()
        if p.name in BUILD_NAMES:
            builds.append(rel)
        if any(k in low for k in ("jni", "ffi", "worker", "service", "bridge", "runtime", "vnc", "x11", "cmake", "gradle")):
            critical.append(rel)
        if any(k in low for k in ("/test/", "/tests/", "_test.", "test_", "integration_test")):
            tests.append(rel)
    languages = {
        "kotlin": ext_counts[".kt"] + ext_counts[".kts"],
        "java": ext_counts[".java"],
        "dart": ext_counts[".dart"],
        "rust": ext_counts[".rs"],
        "c_cpp": sum(ext_counts[e] for e in (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")),
        "python": ext_counts[".py"],
        "typescript_js": sum(ext_counts[e] for e in (".ts", ".tsx", ".js", ".jsx", ".mjs")),
        "go": ext_counts[".go"],
        "csharp": ext_counts[".cs"],
        "swift": ext_counts[".swift"],
    }
    return {
        "guardian_version": VERSION,
        "root": str(r),
        "files_scanned": len(fs),
        "languages": {k: v for k, v in languages.items() if v},
        "extensions": dict(ext_counts.most_common()),
        "build_files": sorted(builds),
        "critical_files": sorted(critical)[:1000],
        "test_files": sorted(tests)[:1000],
        "graphify_available": (r / "graphify-out/graph.json").exists(),
        "graphify_wiki": (r / "graphify-out/wiki/index.md").exists(),
        "agents_md": (r / "AGENTS.md").exists(),
    }


def _extract(pattern: str, text: str):
    m = re.search(pattern, text, re.M)
    return m.group(1) if m else None


def build_compatibility_matrix(root: str | Path | None = None) -> dict[str, Any]:
    r = safe_root(root)
    matrix: dict[str, Any] = {}
    for p in iter_files(r):
        if p.name not in BUILD_NAMES:
            continue
        text = read_text(p)
        rel = str(p.relative_to(r))
        if p.name in ("build.gradle", "build.gradle.kts"):
            matrix.setdefault("android_gradle", []).append({
                "file": rel,
                "compileSdk": _extract(r"compileSdk(?:Version)?\s*[= ]\s*(\d+)", text),
                "targetSdk": _extract(r"targetSdk(?:Version)?\s*[= ]\s*(\d+)", text),
                "minSdk": _extract(r"minSdk(?:Version)?\s*[= ]\s*(\d+)", text),
                "ndkVersion": _extract(r'ndkVersion\s*=\s*"([^"]+)"', text),
                "jvmTarget": _extract(r'jvmTarget\s*=\s*["\']?([^"\'\s]+)', text),
            })
        elif p.name == "gradle-wrapper.properties":
            matrix["gradle_wrapper"] = {
                "file": rel,
                "distribution": _extract(r"distributionUrl=.*gradle-([0-9.]+)-", text),
            }
        elif p.name == "pubspec.yaml":
            matrix.setdefault("flutter", []).append({
                "file": rel,
                "dart_constraint": _extract(r"sdk:\s*[\"']?([^\"'\n]+)", text),
                "flutter_sdk": "declared" if "flutter:" in text else None,
            })
        elif p.name == "Cargo.toml":
            matrix.setdefault("rust", []).append({
                "file": rel,
                "edition": _extract(r'edition\s*=\s*"([^"]+)"', text),
                "rust_version": _extract(r'rust-version\s*=\s*"([^"]+)"', text),
            })
        elif p.name == "CMakeLists.txt":
            matrix.setdefault("cmake", []).append({
                "file": rel,
                "minimum": _extract(r"cmake_minimum_required\s*\(\s*VERSION\s+([0-9.]+)", text),
            })
        elif p.name == "package.json":
            try:
                obj = json.loads(text)
                matrix.setdefault("node", []).append({
                    "file": rel,
                    "engines": obj.get("engines"),
                    "packageManager": obj.get("packageManager"),
                    "dependencies": obj.get("dependencies", {}),
                    "devDependencies": obj.get("devDependencies", {}),
                })
            except json.JSONDecodeError:
                pass
        elif p.name == "pyproject.toml":
            matrix.setdefault("python", []).append({
                "file": rel,
                "requires_python": _extract(r'requires-python\s*=\s*"([^"]+)"', text),
            })
        elif p.name == "go.mod":
            matrix.setdefault("go", []).append({
                "file": rel, "go_version": _extract(r"^go\s+([0-9.]+)", text),
            })
        elif p.name == "AndroidManifest.xml":
            matrix.setdefault("android_manifest", []).append({"file": rel})
    return matrix


def dependency_inventory(root: str | Path | None = None) -> list[dict[str, Any]]:
    """Extract dependency declarations without resolving remote registries."""
    r = safe_root(root)
    deps = []
    for p in iter_files(r):
        text = read_text(p)
        rel = str(p.relative_to(r))
        if p.name == "package.json":
            try:
                obj = json.loads(text)
                for scope in ("dependencies", "devDependencies", "peerDependencies"):
                    for name, ver in (obj.get(scope) or {}).items():
                        deps.append({"ecosystem": "npm", "file": rel, "scope": scope, "name": name, "version": ver})
            except json.JSONDecodeError:
                pass
        elif p.name == "pubspec.yaml":
            current = None
            for line in text.splitlines():
                if re.match(r"^(dependencies|dev_dependencies):\s*$", line):
                    current = line.split(":")[0]
                    continue
                if current and re.match(r"^\S", line):
                    current = None
                if current:
                    m = re.match(r"^\s{2}([A-Za-z0-9_\-]+):\s*(.*)$", line)
                    if m:
                        deps.append({"ecosystem": "pub", "file": rel, "scope": current, "name": m.group(1), "version": m.group(2).strip() or "<complex>"})
        elif p.name in ("build.gradle", "build.gradle.kts"):
            for m in re.finditer(r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*["']([^:"']+):([^:"']+):([^"']+)["']""", text):
                deps.append({"ecosystem": "gradle", "file": rel, "scope": "dependency", "name": f"{m.group(1)}:{m.group(2)}", "version": m.group(3)})
        elif p.name == "requirements.txt":
            for line in text.splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    deps.append({"ecosystem": "pip", "file": rel, "scope": "runtime", "name": s, "version": "<inline>"})
    return deps


def analyze_log_text(text: str, max_per_category: int = 50) -> dict[str, Any]:
    categories: dict[str, list[dict[str, Any]]] = {}
    incidents: list[dict[str, Any]] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        for category, severity, pattern in LOG_RULES:
            if pattern.search(line):
                bucket = categories.setdefault(category, [])
                if len(bucket) < max_per_category:
                    fp = _fingerprint(category, re.sub(r"\d+", "<n>", line)[:400])
                    item = {"line": idx, "text": line[:1200], "severity": severity, "fingerprint": fp}
                    bucket.append(item)
                    incidents.append({"category": category, **item})
    # group fingerprints
    fp_counts = Counter(x["fingerprint"] for x in incidents)
    groups: list[dict[str, Any]] = []
    seen: set[str] = set()
    for x in incidents:
        fp = x["fingerprint"]
        if fp in seen:
            continue
        seen.add(fp)
        groups.append({
            "fingerprint": fp,
            "category": x["category"],
            "severity": x["severity"],
            "count": fp_counts[fp],
            "first_line": x["line"],
            "sample": x["text"],
        })
    groups.sort(key=lambda x: (-SEVERITY_WEIGHTS.get(x["severity"], 0), x["first_line"]))
    return {
        "categories": categories,
        "incident_groups": groups,
        "earliest_high_severity": next((g for g in sorted(groups, key=lambda x: x["first_line"]) if g["severity"] in ("P0", "P1")), None),
    }


def git_changed_files(root: str | Path | None = None, staged: bool = False) -> list[str]:
    r = safe_root(root)
    cmd = ["git", "diff", "--name-only"]
    if staged:
        cmd.insert(2, "--cached")
    try:
        cp = subprocess.run(cmd, cwd=r, shell=False, capture_output=True, text=True, timeout=20)
        if cp.returncode != 0:
            return []
        return [x.strip() for x in cp.stdout.splitlines() if x.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def incremental_scan(root: str | Path | None = None, staged: bool = False) -> dict[str, Any]:
    files = git_changed_files(root, staged=staged)
    return {
        "changed_files": files,
        "syntax": syntax_scan(root, files),
        "risks": risk_scan(root, only_files=files, max_findings=1000),
    }


ALLOWED_VERIFY = {
    "git_diff_check": ["git", "diff", "--check"],
    "cargo_check": ["cargo", "check", "--workspace"],
    "cargo_fmt_check": ["cargo", "fmt", "--all", "--", "--check"],
    "cargo_clippy": ["cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"],
    "dart_analyze": ["dart", "analyze"],
    "flutter_analyze": ["flutter", "analyze"],
    "go_test": ["go", "test", "./..."],
}


def verify(check: str, root: str | Path | None = None, timeout: int = 180) -> dict[str, Any]:
    if check not in ALLOWED_VERIFY:
        raise ValueError(f"check not allowed: {check}")
    r = safe_root(root)
    cmd = ALLOWED_VERIFY[check]
    try:
        cp = subprocess.run(cmd, cwd=r, shell=False, capture_output=True, text=True, timeout=timeout)
        return {
            "check": check, "command": cmd, "returncode": cp.returncode,
            "stdout": cp.stdout[-30000:], "stderr": cp.stderr[-30000:],
            "status": "PASS" if cp.returncode == 0 else "FAIL",
        }
    except FileNotFoundError as e:
        return {"check": check, "status": "UNVERIFIED", "error": str(e)}
    except subprocess.TimeoutExpired:
        return {"check": check, "status": "FAIL", "error": f"timeout after {timeout}s"}


def deep_snapshot(root: str | Path | None = None) -> dict[str, Any]:
    risks = apply_knowledge(risk_scan(root, max_findings=3000), root)
    return {
        "inventory": inventory(root),
        "compatibility": build_compatibility_matrix(root),
        "dependencies": dependency_inventory(root)[:3000],
        "syntax": syntax_scan(root),
        "architecture_smells": architecture_smells(root),
        "hotspots": hotspot_scan(root),
        "risk_summary": dict(Counter(x["category"] for x in risks)),
        "severity_summary": dict(Counter(x["severity"] for x in risks)),
        "knowledge": load_knowledge(root),
    }


def claim_template(component: str, version: str) -> dict[str, Any]:
    """Contrato de verificación upstream: no declarar COMPATIBLE desde extracción local."""
    return {
        "component": component, "version": version,
        "local_status": "EXTRACTED",
        "upstream_status": "UNVERIFIED",
        "required_sources": ["official documentation", "official repository release notes"],
        "rule": "Do not declare COMPATIBLE/INCOMPATIBLE from local version extraction alone.",
    }
