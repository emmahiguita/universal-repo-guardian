"""Base de conocimiento adaptativa.

Solo aprende de resultados verificados explícitos (CONFIRMED / FALSE_POSITIVE /
FIX_PASS / FIX_FAIL / REGRESSION) y escribe únicamente .repo-guardian/knowledge.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nano_repo_guardian.fsio import safe_root


def knowledge_dir(root: str | Path | None = None) -> Path:
    r = safe_root(root)
    p = r / ".repo-guardian"
    p.mkdir(exist_ok=True)
    return p


def load_knowledge(root: str | Path | None = None) -> dict[str, Any]:
    p = knowledge_dir(root) / "knowledge.json"
    if not p.exists():
        return {"version": 1, "verified_patterns": {}, "false_positives": {}, "fix_outcomes": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {"version": 1, "verified_patterns": {}, "false_positives": {}, "fix_outcomes": []}


def record_verified_outcome(
    fingerprint: str,
    outcome: str,
    root: str | Path | None = None,
    root_cause: str = "",
    fix: str = "",
    evidence: str = "",
) -> dict[str, Any]:
    """Aprende solo de feedback explícito verificado. Escribe únicamente .repo-guardian/knowledge.json."""
    if not fingerprint or not fingerprint.strip():
        raise ValueError("fingerprint no puede estar vacío")
    if outcome not in {"CONFIRMED", "FALSE_POSITIVE", "FIX_PASS", "FIX_FAIL", "REGRESSION"}:
        raise ValueError("outcome inválido: usar CONFIRMED, FALSE_POSITIVE, FIX_PASS, FIX_FAIL o REGRESSION")
    data = load_knowledge(root)
    if outcome == "CONFIRMED":
        data["verified_patterns"][fingerprint] = data["verified_patterns"].get(fingerprint, 0) + 1
    elif outcome == "FALSE_POSITIVE":
        data["false_positives"][fingerprint] = data["false_positives"].get(fingerprint, 0) + 1
    data["fix_outcomes"].append({
        "fingerprint": fingerprint, "outcome": outcome, "root_cause": root_cause[:1000],
        "fix": fix[:2000], "evidence": evidence[:2000],
    })
    # Evitar crecimiento sin límite del historial de aprendizaje
    if len(data["fix_outcomes"]) > 500:
        data["fix_outcomes"] = data["fix_outcomes"][-500:]
    data["version"] = int(data.get("version", 1)) + 1
    p = knowledge_dir(root) / "knowledge.json"
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"status": "RECORDED", "knowledge_version": data["version"], "path": str(p)}


def apply_knowledge(findings: list[dict[str, Any]], root: str | Path | None = None) -> list[dict[str, Any]]:
    kb = load_knowledge(root)
    for f in findings:
        fp = f.get("fingerprint", "")
        confirmed = kb.get("verified_patterns", {}).get(fp, 0)
        false = kb.get("false_positives", {}).get(fp, 0)
        base = float(f.get("confidence", 0.45))
        adjusted = max(0.05, min(0.95, base + confirmed * 0.08 - false * 0.12))
        f["confidence"] = round(adjusted, 2)
        f["knowledge_confirmations"] = confirmed
        f["knowledge_false_positives"] = false
    return findings
