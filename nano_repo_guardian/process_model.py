"""Modelo de proceso para forensia de runtime (orquestación)."""

from __future__ import annotations


def process_record(name, owner="", created_by="", ready_signal="", stop_condition="", reaper=""):
    """Registro canónico de un proceso crítico: dueño, señal de ready, parada y reaping."""
    return {
        "process": name,
        "owner": owner,
        "created_by": created_by,
        "ready_signal": ready_signal,
        "stop_condition": stop_condition,
        "reaper": reaper,
        "checks": ["PID alive", "application-level readiness", "shutdown ownership", "reaping/cleanup"],
    }
