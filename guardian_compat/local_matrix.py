from __future__ import annotations
from pathlib import Path
import re,json

def extract(root: Path):
    out={}
    for p in root.rglob("*"):
        if not p.is_file(): continue
        text=p.read_text(encoding="utf-8",errors="replace")
        name=p.name
        rel=str(p.relative_to(root))
        if name in ("build.gradle","build.gradle.kts"):
            out.setdefault("android",[]).append({
                "file":rel,
                "compileSdk":_x(r"compileSdk(?:Version)?\s*[= ]\s*(\d+)",text),
                "targetSdk":_x(r"targetSdk(?:Version)?\s*[= ]\s*(\d+)",text),
                "minSdk":_x(r"minSdk(?:Version)?\s*[= ]\s*(\d+)",text),
                "ndkVersion":_x(r'ndkVersion\s*=\s*"([^"]+)"',text),
            })
        elif name=="gradle-wrapper.properties":
            out["gradle"]={"file":rel,"version":_x(r"gradle-([0-9.]+)-",text)}
        elif name=="pubspec.yaml":
            out.setdefault("flutter",[]).append({"file":rel,"dart":_x(r"sdk:\s*['\"]?([^'\"\n]+)",text)})
        elif name=="Cargo.toml":
            out.setdefault("rust",[]).append({"file":rel,"edition":_x(r'edition\s*=\s*"([^"]+)"',text)})
        elif name=="package.json":
            try:
                obj=json.loads(text); out.setdefault("node",[]).append({"file":rel,"engines":obj.get("engines"),"packageManager":obj.get("packageManager")})
            except Exception: pass
    return out

def _x(p,t):
    m=re.search(p,t,re.M); return m.group(1) if m else None
