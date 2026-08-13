"""Escáneres de repositorio.

Sintaxis, riesgo, duplicados, hotspots, arquitectura, manifest Android, imports y
código muerto. Todo basado en evidencia, con clasificación CONFIRMED /
HYPOTHESIS_TO_VALIDATE según reglas de veracidad.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from nano_repo_guardian.constants import (
    ANDROID_DANGEROUS_PERMISSIONS,
    CODE_EXTS,
    ENTRY_OR_CALLBACK,
    FUNC_PATTERNS,
    IMPORT_PATTERNS,
    RISK_RULES,
    WORD_RE,
)
from nano_repo_guardian.constants import (
    fingerprint as _fingerprint,
)
from nano_repo_guardian.fsio import is_text_candidate, iter_files, read_text, safe_root


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    status: str
    confidence: float
    file: str
    line: int
    snippet: str
    rationale: str
    fingerprint: str


def syntax_scan(root: str | Path | None = None, only_files: list[str] | None = None) -> list[dict[str, Any]]:
    """Deterministic syntax/config checks where safe without external toolchains."""
    r = safe_root(root)
    only = set(only_files) if only_files else None
    out = []
    for p in iter_files(r, only):
        if not is_text_candidate(p):
            continue
        rel = str(p.relative_to(r))
        text = read_text(p)
        if not text:
            continue

        # Python syntax
        if p.suffix == ".py":
            try:
                ast.parse(text, filename=rel)
            except SyntaxError as e:
                out.append({
                    "severity": "P0", "status": "CONFIRMED", "category": "syntax_python",
                    "file": rel, "line": e.lineno or 1, "message": e.msg,
                })

        # JSON syntax
        if p.suffix == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError as e:
                out.append({
                    "severity": "P0", "status": "CONFIRMED", "category": "syntax_json",
                    "file": rel, "line": e.lineno, "message": e.msg,
                })

        # Merge conflicts
        for i, line in enumerate(text.splitlines(), 1):
            if line.startswith(("<<<<<<<", "=======", ">>>>>>>")):
                out.append({
                    "severity": "P0", "status": "CONFIRMED", "category": "merge_conflict",
                    "file": rel, "line": i, "message": line[:300],
                })
    return out


def _line_number(line_starts: list[int], pos: int) -> int:
    """Búsqueda binaria del número de línea para una posición de carácter."""
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def risk_scan(root: str | Path | None = None, max_findings: int = 1500, only_files: list[str] | None = None) -> list[dict[str, Any]]:
    r = safe_root(root)
    only = set(only_files) if only_files else None
    out: list[dict[str, Any]] = []
    seq = 0
    for p in iter_files(r, only):
        if not is_text_candidate(p):
            continue
        text = read_text(p)
        if not text:
            continue
        lines = text.splitlines()
        rel = str(p.relative_to(r))
        # Offsets de inicio de línea precomputados: evita O(n·m) de text.count() por cada match
        line_starts = [0]
        pos = text.find("\n")
        while pos != -1:
            line_starts.append(pos + 1)
            pos = text.find("\n", pos + 1)
        for category, severity, pattern, rationale in RISK_RULES:
            for m in pattern.finditer(text):
                seq += 1
                line_no = _line_number(line_starts, m.start())
                snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else m.group(0)
                # Los escaneos por patrón son hipótesis salvo que exista evidencia determinística (merge conflict)
                status = "CONFIRMED" if category == "merge_conflict" else "HYPOTHESIS_TO_VALIDATE"
                confidence = 1.0 if status == "CONFIRMED" else 0.45
                fp = _fingerprint(category, rel, re.sub(r"\s+", " ", snippet)[:200])
                out.append(asdict(Finding(
                    id=f"RISK-{seq:05d}", category=category, severity=severity, status=status,
                    confidence=confidence, file=rel, line=line_no, snippet=snippet[:500],
                    rationale=rationale, fingerprint=fp,
                )))
                if len(out) >= max_findings:
                    return out
    return out


def duplicate_scan(root: str | Path | None = None, min_lines: int = 6, max_groups: int = 100) -> list[dict[str, Any]]:
    """Find likely exact duplicated code blocks. Exact-match only to avoid aggressive false positives."""
    r = safe_root(root)
    buckets = defaultdict(list)
    for p in iter_files(r):
        if p.suffix.lower() not in CODE_EXTS:
            continue
        text = read_text(p)
        lines = text.splitlines()
        for i in range(0, max(0, len(lines) - min_lines + 1)):
            block = "\n".join(x.strip() for x in lines[i:i + min_lines] if x.strip())
            if len(block) < 80:
                continue
            digest = hashlib.sha1(block.encode()).hexdigest()
            buckets[digest].append((str(p.relative_to(r)), i + 1, block[:600]))
    groups = []
    for digest, locs in buckets.items():
        unique_files = {x[0] for x in locs}
        if len(locs) > 1 and len(unique_files) > 1:
            groups.append({
                "fingerprint": digest[:16],
                "occurrences": [{"file": f, "line": ln} for f, ln, _ in locs[:20]],
                "sample": locs[0][2],
                "status": "HYPOTHESIS_TO_VALIDATE",
                "severity": "P3",
                "category": "exact_duplicate_block",
            })
            if len(groups) >= max_groups:
                break
    return groups


def hotspot_scan(root: str | Path | None = None, top_n: int = 50) -> list[dict[str, Any]]:
    """Rank files by size + branch complexity proxy + risk-boundary count."""
    r = safe_root(root)
    risks = risk_scan(r, max_findings=5000)
    risk_counts = Counter(x["file"] for x in risks)
    rows: list[dict[str, Any]] = []
    for p in iter_files(r):
        if p.suffix.lower() not in CODE_EXTS:
            continue
        text = read_text(p)
        if not text:
            continue
        lines = text.splitlines()
        branches = len(re.findall(r"\b(if|else if|elif|switch|case|when|for|while|catch)\b", text))
        funcs = len(re.findall(r"\b(def|fun|fn|function|void|int|bool|String|Future<|suspend fun)\s+\w+", text))
        rel = str(p.relative_to(r))
        score = len(lines) * 0.1 + branches * 2.0 + risk_counts[rel] * 3.0
        rows.append({
            "file": rel,
            "lines": len(lines),
            "branch_proxy": branches,
            "function_proxy": funcs,
            "risk_boundaries": risk_counts[rel],
            "hotspot_score": round(score, 2),
            "status": "INFORMATIONAL",
        })
    return sorted(rows, key=lambda x: x["hotspot_score"], reverse=True)[:top_n]


def architecture_smells(root: str | Path | None = None) -> list[dict[str, Any]]:
    """Architecture-oriented heuristics with conservative classification."""
    out = []
    for row in hotspot_scan(root, top_n=200):
        if row["lines"] >= 1200:
            out.append({
                "category": "god_file_candidate", "severity": "P2", "status": "HYPOTHESIS_TO_VALIDATE",
                "file": row["file"], "evidence": f'{row["lines"]} líneas',
                "recommendation": "Inspeccionar número de responsabilidades, fan-in/fan-out y propiedad del ciclo de vida antes de refactorizar.",
            })
        if row["branch_proxy"] >= 100:
            out.append({
                "category": "high_branch_complexity", "severity": "P2", "status": "HYPOTHESIS_TO_VALIDATE",
                "file": row["file"], "evidence": f'branch proxy={row["branch_proxy"]}',
                "recommendation": "Inspeccionar descomposición de máquina de estados/ramas y cobertura de pruebas.",
            })
    return out


def search_code(query: str, root: str | Path | None = None, max_results: int = 100):
    if not query.strip():
        raise ValueError("query must not be empty")
    r = safe_root(root)
    q = query.lower()
    out = []
    for p in iter_files(r):
        if not is_text_candidate(p):
            continue
        for i, line in enumerate(read_text(p).splitlines(), 1):
            if q in line.lower():
                out.append({"file": str(p.relative_to(r)), "line": i, "text": line.strip()[:600]})
                if len(out) >= max_results:
                    return out
    return out


def _xml_bool(el, attr: str, ns: str) -> bool | None:
    val = el.get(f"{{{ns}}}{attr}")
    if val is None:
        return None
    return val.strip().lower() == "true"


def android_manifest_audit(root: str | Path | None = None) -> list[dict[str, Any]]:
    """Audita AndroidManifest.xml: permisos, componentes exportados, cleartext, backup, debuggable."""
    import xml.etree.ElementTree as ET
    r = safe_root(root)
    out: list[dict[str, Any]] = []
    NS = "http://schemas.android.com/apk/res/android"
    for p in iter_files(r):
        if p.name != "AndroidManifest.xml":
            continue
        rel = str(p.relative_to(r))
        try:
            tree = ET.parse(p)
        except ET.ParseError as e:
            out.append({"file": rel, "category": "manifest_malformed", "severity": "P0",
                        "status": "CONFIRMED", "message": f"XML malformado: {e}"})
            continue
        root_el = tree.getroot()
        # application flags
        app = root_el.find("application")
        if app is not None:
            for attr, cat, sev in (("debuggable", "manifest_debuggable", "P1"),
                                   ("allowBackup", "manifest_backup", "P2")):
                val = _xml_bool(app, attr, NS)
                if val is True:
                    out.append({"file": rel, "category": cat, "severity": sev,
                                "status": "CONFIRMED",
                                "message": f"application android:{attr}=\"true\""})
            if _xml_bool(app, "usesCleartextTraffic", NS) is True:
                out.append({"file": rel, "category": "manifest_cleartext", "severity": "P1",
                            "status": "CONFIRMED",
                            "message": 'application android:usesCleartextTraffic="true" — tráfico HTTP en claro permitido'})
        # permissions
        for perm in root_el.iter("uses-permission"):
            name = perm.get(f"{{{NS}}}name", "")
            if not name:
                continue
            sev = "P1" if name.split(".")[-1] in ANDROID_DANGEROUS_PERMISSIONS else "P2"
            out.append({"file": rel, "category": "manifest_permission", "severity": sev,
                        "status": "INFORMATIONAL" if sev == "P2" else "HYPOTHESIS_TO_VALIDATE",
                        "message": f"permiso declarado: {name}"})
        # exported components
        for tag in ("activity", "service", "receiver", "provider"):
            for el in root_el.iter(tag):
                name = el.get(f"{{{NS}}}name", "?")
                exported = _xml_bool(el, "exported", NS)
                has_filter = el.find("intent-filter") is not None
                if exported is True:
                    out.append({"file": rel, "category": "manifest_exported", "severity": "P1",
                                "status": "HYPOTHESIS_TO_VALIDATE",
                                "message": f"<{tag}> {name} android:exported=\"true\" — verificar superficie de ataque"})
                elif exported is None and has_filter:
                    out.append({"file": rel, "category": "manifest_exported", "severity": "P1",
                                "status": "HYPOTHESIS_TO_VALIDATE",
                                "message": f"<{tag}> {name} con intent-filter sin android:exported explícito — exportado implícitamente"})
        # providers with authorities
        for prov in root_el.iter("provider"):
            auth = prov.get(f"{{{NS}}}authorities")
            exported = _xml_bool(prov, "exported", NS)
            if auth and exported is True:
                out.append({"file": rel, "category": "manifest_provider_exported", "severity": "P0",
                            "status": "HYPOTHESIS_TO_VALIDATE",
                            "message": f"ContentProvider exportado con authorities={auth} — riesgo de fuga de datos"})
    return out


def imports_audit(root: str | Path | None = None) -> dict[str, Any]:
    """Audita imports: duplicados, wildcard y candidatos a no usados (heurística por nombre)."""
    r = safe_root(root)
    duplicates: list[dict[str, Any]] = []
    wildcards: list[dict[str, Any]] = []
    unused: list[dict[str, Any]] = []
    total_files = 0
    for p in iter_files(r):
        pat = IMPORT_PATTERNS.get(p.suffix.lower())
        if not pat:
            continue
        text = read_text(p)
        if not text:
            continue
        total_files += 1
        rel = str(p.relative_to(r))
        seen: dict[str, int] = {}
        line_starts = [0]
        pos = text.find("\n")
        while pos != -1:
            line_starts.append(pos + 1)
            pos = text.find("\n", pos + 1)
        for m in pat.finditer(text):
            # normalizar: usar el grupo más relevante
            imp = next((g for g in m.groups() if g and g != "static"), "")
            if not imp:
                continue
            line_no = _line_number(line_starts, m.start())
            if "*" in m.group(0).split()[-1] or imp.endswith("*"):
                wildcards.append({"file": rel, "line": line_no, "import": imp,
                                  "status": "HYPOTHESIS_TO_VALIDATE", "severity": "P3",
                                  "category": "wildcard_import"})
                continue
            if imp in seen:
                duplicates.append({"file": rel, "line": line_no, "import": imp,
                                   "status": "CONFIRMED", "severity": "P3",
                                   "category": "duplicate_import",
                                   "message": f"import duplicado (primera vez línea {seen[imp]})"})
            else:
                seen[imp] = line_no
        # candidatos no usados: último segmento del import no aparece fuera de la zona de imports
        lines = text.splitlines()
        body = "\n".join(line for line in lines if not line.strip().startswith("import"))
        body_lower = body.lower()
        for imp, ln in seen.items():
            simple = imp.rsplit(".", 1)[-1].rsplit("/", 1)[-1].lower()
            if len(simple) < 3:
                continue
            if simple not in body_lower:
                unused.append({"file": rel, "line": ln, "import": imp,
                               "status": "HYPOTHESIS_TO_VALIDATE", "severity": "P3",
                               "category": "unused_import_candidate",
                               "message": f"'{simple}' no aparece fuera de la zona de imports (heurística — verificar uso indirecto)"})
    return {
        "files_scanned": total_files,
        "duplicates": duplicates,
        "wildcards": wildcards,
        "unused_candidates": unused,
    }


def dead_code_scan(root: str | Path | None = None, max_files: int = 2000) -> list[dict[str, Any]]:
    """Candidatos a código muerto: funciones definidas sin menciones en el resto del repo.
    Heurística por nombre — siempre HYPOTHESIS_TO_VALIDATE.

    Complejidad O(archivos × símbolos): se indexa cada ocurrencia una sola vez, en lugar
    de re-escandear todos los archivos por cada definición (que era O(defs × archivos × líneas)).
    """
    r = safe_root(root)
    defs: list[tuple[str, str, int]] = []  # (archivo, nombre, línea)
    files: list[tuple[str, str]] = []  # (rel, texto)
    for p in iter_files(r):
        if p.suffix.lower() not in FUNC_PATTERNS:
            continue
        text = read_text(p)
        if not text:
            continue
        rel = str(p.relative_to(r))
        files.append((rel, text))
        for m in FUNC_PATTERNS[p.suffix.lower()].finditer(text):
            name = m.group(1)
            if name in ENTRY_OR_CALLBACK or len(name) < 3:
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            defs.append((rel, name, line_no))
        if len(files) >= max_files:
            break

    # Index único: solo los nombres definidos, mapeados a (archivo, línea).
    def_names = {name for _, name, _ in defs}
    index: dict[str, list[tuple[str, int]]] = {n: [] for n in def_names}
    for rel, text in files:
        for m in WORD_RE.finditer(text):
            w = m.group(0)
            if w in def_names:
                index[w].append((rel, text.count("\n", 0, m.start()) + 1))

    # mención = nombre aparece en cualquier archivo fuera de su propia línea de definición
    out: list[dict[str, Any]] = []
    for rel, name, line_no in defs:
        mentions = 0
        for rel2, ln in index.get(name, []):
            if rel2 == rel and ln == line_no:
                continue  # la propia definición no cuenta
            mentions += 1
            if mentions > 2:
                break
        if mentions <= 1:
            out.append({
                "file": rel, "line": line_no, "symbol": name,
                "mentions_in_repo": mentions,
                "category": "dead_code_candidate", "severity": "P3",
                "status": "HYPOTHESIS_TO_VALIDATE",
                "message": f"función '{name}' sin referencias verificables (heurística — verificar reflexión/callbacks/exports)",
            })
    return out


_ENTROPY_TOKEN = re.compile(r'["\']([A-Za-z0-9_\-+/=]{20,})["\']')


def _entropy(s: str) -> float:
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def entropy_scan(path: Path) -> list[dict[str, Any]]:
    """Candidatos a secretos por entropía alta en literales largos (heurístico)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for m in _ENTROPY_TOKEN.finditer(text):
        s = m.group(1)
        if _entropy(s) >= 4.0:
            out.append({
                "status": "HYPOTHESIS_TO_VALIDATE", "severity": "P1", "category": "high_entropy_secret_candidate",
                "line": text.count("\n", 0, m.start()) + 1, "length": len(s), "entropy": round(_entropy(s), 2),
            })
    return out
