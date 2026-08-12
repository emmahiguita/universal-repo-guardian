from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def benchmark_expectations(root: Path) -> dict[str, Any]:
    manifest = root / "fixtures" / "manifest.json"
    if not manifest.exists():
        return {"status":"UNAVAILABLE","reason":"fixtures/manifest.json not found"}
    data = json.loads(manifest.read_text(encoding="utf-8"))
    return {"status":"READY","cases":data.get("cases",[]),"count":len(data.get("cases",[]))}
