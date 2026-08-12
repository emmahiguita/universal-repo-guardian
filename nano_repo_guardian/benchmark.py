from __future__ import annotations
from pathlib import Path
from typing import Any
import json

def benchmark_expectations(root: Path) -> dict[str, Any]:
    manifest = root / "fixtures" / "manifest.json"
    if not manifest.exists():
        return {"status":"UNAVAILABLE","reason":"fixtures/manifest.json not found"}
    data = json.loads(manifest.read_text(encoding="utf-8"))
    return {"status":"READY","cases":data.get("cases",[]),"count":len(data.get("cases",[]))}
