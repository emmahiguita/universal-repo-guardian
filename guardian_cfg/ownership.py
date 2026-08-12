from __future__ import annotations
from pathlib import Path
import re

PAIRS={"malloc":"free","calloc":"free","mmap":"munmap","socket":"close","open":"close","fopen":"fclose","new":"delete"}

def scan(path: Path):
    text=path.read_text(encoding="utf-8",errors="replace")
    out=[]
    for acq,rel in PAIRS.items():
        a=len(re.findall(rf"\b{re.escape(acq)}\b",text))
        r=len(re.findall(rf"\b{re.escape(rel)}\b",text))
        if a and r<a:
            out.append({"resource":acq,"release":rel,"acquire_mentions":a,"release_mentions":r,
                        "status":"HYPOTHESIS_TO_VALIDATE","severity":"P1"})
    return out
