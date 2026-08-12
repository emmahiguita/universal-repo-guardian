from __future__ import annotations
import re
from pathlib import Path

SOURCES = re.compile(r"\b(input|request|query|params|argv|stdin|readLine|readline|Intent\.get|extras)\b",re.I)
SINKS = re.compile(r"\b(exec|system|Runtime\.exec|ProcessBuilder|sh\s+-c|bash\s+-c|executeQuery|rawQuery|eval)\b",re.I)

def scan(path: Path):
    lines=path.read_text(encoding="utf-8",errors="replace").splitlines()
    source_lines=[i for i,l in enumerate(lines,1) if SOURCES.search(l)]
    sink_lines=[i for i,l in enumerate(lines,1) if SINKS.search(l)]
    findings=[]
    if source_lines and sink_lines:
        findings.append({
            "status":"HYPOTHESIS_TO_VALIDATE","severity":"P0",
            "category":"source_to_sink_candidate",
            "source_lines":source_lines[:20],"sink_lines":sink_lines[:20],
            "note":"Textual co-occurrence only. AST/dataflow must prove propagation before CONFIRMED."
        })
    return findings
