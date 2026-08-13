"""Puerta de corrección: límites anti-bucle y checkpoints humanos.

Previene la "corrección en bucle" (alucinación de fixes) con:
  - Límite de intentos por bug (por defecto 3) -> BLOQUEADO automático.
  - Checkpoint obligatorio cada N bugs corregidos -> rechaza seguir sin resolverlo.
  - Estado persistente en .repo-guardian/sprint_state.json (sobrevive reinicios).

La puerta es ESTRICTA: cuando el agente intenta exceder un límite, la tool
levanta ValueError (isError=True en MCP), de modo que el "parar y preguntar"
no es un consejo sino una puerta que no puede cruzar solo.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nano_repo_guardian.fsio import safe_root

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_MAX_BUGS_BEFORE_CHECKPOINT = 3
ALLOWED_VERDICTS = {"PASS", "PARTIAL", "FAIL", "UNVERIFIED"}
ALLOWED_ACTIONS = {"register_attempt", "finalize", "resolve_checkpoint", "reset", "status"}


def _default_state() -> dict[str, Any]:
    return {
        "version": 1,
        "max_attempts_per_bug": DEFAULT_MAX_ATTEMPTS,
        "max_bugs_before_checkpoint": DEFAULT_MAX_BUGS_BEFORE_CHECKPOINT,
        "bugs": {},
        "checkpoint_pending": False,
        "bugs_since_checkpoint": 0,
    }


def correction_state_file(root: str | Path | None = None) -> Path:
    r = safe_root(root)
    d = r / ".repo-guardian"
    d.mkdir(exist_ok=True)
    return d / "sprint_state.json"


def load_correction_state(root: str | Path | None = None) -> dict[str, Any]:
    p = correction_state_file(root)
    if not p.exists():
        return _default_state()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return _default_state()
    base = _default_state()
    base.update(data)
    base["bugs"] = {k: v for k, v in base.get("bugs", {}).items() if isinstance(v, dict)}
    return base


def _save(state: dict[str, Any], root: str | Path | None = None) -> dict[str, Any]:
    p = correction_state_file(root)
    p.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    return state


def _status_response(state: dict[str, Any]) -> dict[str, Any]:
    bugs = state.get("bugs", {})
    summary: dict[str, int] = {}
    for b in bugs.values():
        summary[b.get("status", "PENDIENTE")] = summary.get(b.get("status", "PENDIENTE"), 0) + 1
    if state.get("checkpoint_pending"):
        next_action = "resolve_checkpoint"
    elif "BLOQUEADO" in summary and not any(b.get("status") == "PENDIENTE" for b in bugs.values()):
        next_action = "report_blocked"
    elif any(b.get("status") in ("PENDIENTE", "EN_CORRECCION") for b in bugs.values()):
        next_action = "pick_next_pending"
    else:
        next_action = "done"
    return {
        "checkpoint_pending": bool(state.get("checkpoint_pending", False)),
        "bugs_since_checkpoint": int(state.get("bugs_since_checkpoint", 0)),
        "max_attempts_per_bug": int(state.get("max_attempts_per_bug", DEFAULT_MAX_ATTEMPTS)),
        "max_bugs_before_checkpoint": int(state.get("max_bugs_before_checkpoint", DEFAULT_MAX_BUGS_BEFORE_CHECKPOINT)),
        "summary": summary,
        "next_action": next_action,
        "bugs": bugs,
    }


def correction_gate(
    action: str,
    fingerprint: str = "",
    verdict: str = "",
    root: str | Path | None = None,
) -> dict[str, Any]:
    """Puerta de corrección con límites y checkpoints.

    Acciones:
      - register_attempt: registrar un intento de fix antes de aplicarlo.
        Rechaza si el bug está BLOQUEADO/APROBADO o si hay checkpoint pendiente.
      - finalize: cerrar la verificación con un veredicto (PASS/PARTIAL/FAIL/UNVERIFIED).
        PASS cuenta hacia el checkpoint; FAIL con el límite alcanzado => BLOQUEADO.
      - resolve_checkpoint: el usuario autoriza continuar; limpia el checkpoint.
      - reset: reinicia todo el sprint (equivale a "limpiar").
      - status: devuelve el estado completo (para el informe).
    """
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"action inválida: usar {sorted(ALLOWED_ACTIONS)}")
    state = load_correction_state(root)
    max_attempts = int(state.get("max_attempts_per_bug", DEFAULT_MAX_ATTEMPTS))
    max_bugs = int(state.get("max_bugs_before_checkpoint", DEFAULT_MAX_BUGS_BEFORE_CHECKPOINT))

    if action == "status":
        return _status_response(state)

    if action == "reset":
        _save(_default_state(), root)
        return _status_response(_default_state())

    if action == "resolve_checkpoint":
        state["checkpoint_pending"] = False
        state["bugs_since_checkpoint"] = 0
        _save(state, root)
        return _status_response(state)

    # register_attempt y finalize requieren fingerprint
    if not fingerprint or not fingerprint.strip():
        raise ValueError("fingerprint es obligatorio para register_attempt/finalize")
    fp = fingerprint.strip()
    bug = state["bugs"].get(fp)
    if bug is None:
        bug = {"attempts": 0, "status": "PENDIENTE", "verdict": None, "last_attempt": None}

    if action == "register_attempt":
        if state.get("checkpoint_pending"):
            raise ValueError("checkpoint pendiente: resuelve el checkpoint (resolve_checkpoint) antes de continuar")
        if bug.get("status") == "APROBADO":
            raise ValueError(f"bug {fp} ya está APROBADO; no se puede reintentar")
        if bug.get("status") == "BLOQUEADO":
            raise ValueError(f"bug {fp} ya está BLOQUEADO (límite de {max_attempts} intentos alcanzado)")
        bug["attempts"] = int(bug.get("attempts", 0)) + 1
        if bug["attempts"] > max_attempts:
            bug["status"] = "BLOQUEADO"
            bug["verdict"] = "FAIL"
            state["bugs"][fp] = bug
            _save(state, root)
            raise ValueError(f"límite de {max_attempts} intentos alcanzado para {fp}: BLOQUEADO")
        bug["status"] = "EN_CORRECCION"
        state["bugs"][fp] = bug
        _save(state, root)
        return _status_response(state)

    if action == "finalize":
        if verdict not in ALLOWED_VERDICTS:
            raise ValueError(f"veredicto inválido: usar {sorted(ALLOWED_VERDICTS)}")
        if bug.get("status") == "BLOQUEADO":
            raise ValueError(f"bug {fp} está BLOQUEADO; no se puede finalizar")
        bug["verdict"] = verdict
        if verdict == "PASS":
            bug["status"] = "APROBADO"
            state["bugs"][fp] = bug
            state["bugs_since_checkpoint"] = int(state.get("bugs_since_checkpoint", 0)) + 1
            if int(state.get("bugs_since_checkpoint", 0)) >= max_bugs:
                state["checkpoint_pending"] = True
        elif verdict == "FAIL":
            bug["status"] = "BLOQUEADO" if int(bug.get("attempts", 0)) >= max_attempts else "PENDIENTE"
        else:  # PARTIAL / UNVERIFIED
            bug["status"] = "PENDIENTE"
        state["bugs"][fp] = bug
        _save(state, root)
        return _status_response(state)

    raise ValueError(f"action no soportada: {action}")
