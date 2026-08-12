from __future__ import annotations

import hashlib
import re
from pathlib import Path

RULES=[
("hardcoded_secret","P0",re.compile(r"\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]",re.I)),
("trust_all_tls","P0",re.compile(r"TrustAll|CERT_NONE|HostnameVerifier\s*\{\s*true|danger_accept_invalid_certs",re.I)),
("shell_command","P1",re.compile(r"Runtime\.exec|ProcessBuilder|subprocess\.|os\.system|system\(|popen\(",re.I)),
("dynamic_sql","P1",re.compile(r"\b(SELECT|UPDATE|DELETE|INSERT)\b.*(\+|\$\{|format\(|f\")",re.I)),
("cleartext_android","P1",re.compile(r'usesCleartextTraffic\s*=\s*"true"',re.I)),
("exported_android","P1",re.compile(r'android:exported\s*=\s*"true"',re.I)),
]
def scan_file(path: Path):
    text=path.read_text(encoding="utf-8",errors="replace")
    out=[]
    for cat,sev,pat in RULES:
        for m in pat.finditer(text):
            line=text.count("\n",0,m.start())+1
            fp=hashlib.sha256(f"{cat}|{path}|{m.group(0)}".encode()).hexdigest()[:16]
            out.append({"category":cat,"severity":sev,"status":"HYPOTHESIS_TO_VALIDATE",
                        "file":str(path),"line":line,"fingerprint":fp,"evidence":m.group(0)[:300]})
    return out
