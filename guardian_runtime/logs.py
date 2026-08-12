from __future__ import annotations
import re,hashlib
from collections import Counter
RULES=[
("native_crash","P0",re.compile(r"SIGSEGV|SIGABRT|SIGBUS|SIGILL|tombstone",re.I)),
("android_fatal","P0",re.compile(r"FATAL EXCEPTION|ANR in |OutOfMemoryError",re.I)),
("permission","P1",re.compile(r"Permission denied|EACCES|rc=126",re.I)),
("not_found","P1",re.compile(r"ENOENT|rc=127|No such file|not found",re.I)),
("linker","P1",re.compile(r"dlopen failed|undefined symbol|cannot locate symbol|linker",re.I)),
("network","P1",re.compile(r"connection refused|timeout|ECONNRESET|Broken pipe",re.I)),
("buffer","P1",re.compile(r"BufferQueue|BLASTBufferQueue|Already acquired max frames",re.I)),
]
def analyze(text):
    incidents=[]
    for i,line in enumerate(text.splitlines(),1):
        for cat,sev,pat in RULES:
            if pat.search(line):
                norm=re.sub(r"\d+","<n>",line)
                fp=hashlib.sha256(f"{cat}|{norm}".encode()).hexdigest()[:16]
                incidents.append({"line":i,"category":cat,"severity":sev,"fingerprint":fp,"text":line[:1000]})
    counts=Counter(x["fingerprint"] for x in incidents)
    groups=[]
    for x in incidents:
        if any(g["fingerprint"]==x["fingerprint"] for g in groups): continue
        groups.append({"fingerprint":x["fingerprint"],"category":x["category"],"severity":x["severity"],
                       "count":counts[x["fingerprint"]],"first_line":x["line"],"sample":x["text"]})
    return {"incidents":incidents,"groups":groups,
            "earliest_critical":next((g for g in sorted(groups,key=lambda z:z["first_line"]) if g["severity"] in ("P0","P1")),None)}
