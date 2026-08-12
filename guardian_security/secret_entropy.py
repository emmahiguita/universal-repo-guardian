from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

TOKEN = re.compile(r'["\']([A-Za-z0-9_\-+/=]{20,})["\']')


def entropy(s):
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def scan(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for m in TOKEN.finditer(text):
        s = m.group(1)
        if entropy(s) >= 4.0:
            out.append({
                "status": "HYPOTHESIS_TO_VALIDATE", "severity": "P1", "category": "high_entropy_secret_candidate",
                "line": text.count("\n", 0, m.start()) + 1, "length": len(s), "entropy": round(entropy(s), 2),
            })
    return out
