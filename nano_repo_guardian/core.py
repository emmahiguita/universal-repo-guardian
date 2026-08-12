from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import ast
import json
import os
import re
import subprocess
import hashlib
from collections import Counter, defaultdict
from typing import Any, Iterable

VERSION = "2.0.0"

SKIP_DIRS = {
    ".git", ".gradle", ".dart_tool", ".idea", ".vscode", "build", "dist",
    "node_modules", "target", ".venv", "venv", "__pycache__", ".next",
    "Pods", "DerivedData", ".terraform", "vendor/bundle"
}

TEXT_EXTS = {
    ".kt", ".kts", ".java", ".dart", ".rs", ".c", ".cc", ".cpp", ".cxx",
    ".h", ".hh", ".hpp", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs",
    ".json", ".toml", ".yaml", ".yml", ".xml", ".gradle", ".properties",
    ".md", ".sh", ".bash", ".zsh", ".ps1", ".cmake", ".txt", ".go",
    ".cs", ".swift", ".sql"
}

CODE_EXTS = {
    ".kt", ".java", ".dart", ".rs", ".c", ".cc", ".cpp", ".cxx", ".h",
    ".hpp", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".cs", ".swift"
}

BUILD_NAMES = {
    "Cargo.toml", "Cargo.lock", "pubspec.yaml", "pubspec.lock",
    "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "gradle.properties", "gradle-wrapper.properties", "CMakeLists.txt",
    "Android.mk", "Application.mk", "package.json", "package-lock.json",
    "pnpm-lock.yaml", "yarn.lock", "pyproject.toml", "requirements.txt",
    "go.mod", "go.sum", "pom.xml", "Podfile", "Package.swift",
    "AndroidManifest.xml", "Dockerfile", "docker-compose.yml"
}

SEVERITY_WEIGHTS = {
    "P0": 100,
    "P1": 60,
    "P2": 25,
    "P3": 10,
}

RISK_RULES = [
    # Syntax / malformed markers
    ("merge_conflict", "P0", re.compile(r"^(<<<<<<<|=======|>>>>>>>)", re.M),
     "Unresolved merge conflict marker"),
    ("todo_fixme", "P3", re.compile(r"\b(TODO|FIXME|HACK|XXX)\b"),
     "Incomplete/temporary implementation marker"),
    # Error handling
    ("empty_catch", "P1", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}", re.S),
     "Exception is swallowed without handling"),
    ("broad_catch", "P2", re.compile(r"catch\s*\(\s*(?:Exception|Throwable|dynamic|e)\b"),
     "Broad exception handling may hide root cause"),
    ("ignored_result", "P2", re.compile(r"\blet\s+_\s*=\s*[^;]+;|(?:^|\s)_\s*=\s*[^;\n]+", re.M),
     "Result intentionally ignored; verify error propagation"),
    # Blocking / orchestration
    ("fixed_sleep", "P2", re.compile(r"\b(Thread\.sleep|sleep\(|usleep\(|Future\.delayed)\b"),
     "Fixed delay used; verify it is not a readiness/synchronization substitute"),
    ("infinite_loop", "P1", re.compile(r"\bwhile\s*\(\s*true\s*\)|\bwhile\s+true\b|\bfor\s*\(\s*;\s*;\s*\)"),
     "Potential unbounded loop"),
    ("process_spawn", "P1", re.compile(r"\b(fork|execve|execl|execvp|waitpid|setsid|ProcessBuilder|Runtime\.exec|subprocess\.)\b"),
     "Process lifecycle boundary"),
    ("kill_force", "P2", re.compile(r"\b(SIGKILL|kill\s+-9|pkill\s+-9)\b"),
     "Forceful process termination; verify graceful shutdown and reaping"),
    # Native memory / FFI
    ("native_alloc", "P1", re.compile(r"\b(malloc|calloc|realloc|free|new\s+|delete\s+|mmap|munmap)\b"),
     "Native memory ownership boundary"),
    ("unsafe_copy", "P1", re.compile(r"\b(strcpy|strcat|sprintf|gets|memcpy)\b"),
     "Unsafe or size-sensitive native memory operation"),
    ("native_loader", "P1", re.compile(r"\b(dlopen|dlsym|dlclose|System\.loadLibrary|System\.load)\b"),
     "Dynamic native loading boundary"),
    ("jni_boundary", "P1", re.compile(r"\b(JNIEnv|JNIEXPORT|JNI_OnLoad|external\s+fun|@JvmStatic\s+external)\b"),
     "JNI ownership/error boundary"),
    ("ffi_boundary", "P1", re.compile(r"\b(DynamicLibrary\.open|Pointer<|ffi\.|Foreign Function|extern \"C\")\b"),
     "FFI ownership/ABI boundary"),
    # Concurrency
    ("lock_usage", "P2", re.compile(r"\b(Mutex|mutex|synchronized|Semaphore|ReentrantLock|pthread_mutex|RwLock|Arc<Mutex)\b"),
     "Locking/concurrency boundary"),
    ("global_mutable", "P2", re.compile(r"\b(static\s+mut|var\s+\w+\s*=\s*mutable|late\s+var|companion object)\b"),
     "Potential shared mutable state"),
    # Networking
    ("network_local", "P2", re.compile(r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0|5901|6000|DISPLAY)\b"),
     "Network/display endpoint; verify ownership, exposure, timeout and cleanup"),
    ("network_retry", "P2", re.compile(r"\b(retry|reconnect|backoff|keepalive)\b", re.I),
     "Reconnect/retry policy boundary"),
    ("trust_all_tls", "P0", re.compile(r"(danger_accept_invalid_certs|TrustAll|HostnameVerifier\s*\{\s*true|CERT_NONE)", re.I),
     "TLS verification may be disabled"),
    # Paths / permissions
    ("hardcoded_android_path", "P2", re.compile(r"/data/(?:data|user/0)/[\w.\-]+"),
     "Hardcoded Android sandbox path"),
    ("hardcoded_absolute_path", "P3", re.compile(r"(?:^|[\"'])(/[A-Za-z0-9_.-]+/|[A-Za-z]:\\\\)"),
     "Absolute path may reduce portability"),
    ("shell_injection", "P0", re.compile(r"(?:sh\s+-c|bash\s+-c|Runtime\.exec|ProcessBuilder)[^\n]*(?:\+|\$\{|format\(|f\")"),
     "Potential command construction from dynamic input"),
    # UI / Flutter / Android
    ("flutter_dispose", "P2", re.compile(r"\b(StreamController|AnimationController|TextEditingController|FocusNode)\b"),
     "Disposable Flutter resource; verify dispose/close"),
    ("android_context", "P2", re.compile(r"\b(Activity|Context)\b"),
     "Android lifecycle/context ownership boundary"),
    ("surface_pipeline", "P2", re.compile(r"\b(SurfaceView|TextureView|PlatformView|SurfaceTexture|ImageReader|BufferQueue)\b"),
     "Surface/render lifecycle boundary"),
    # SQL / data
    ("sql_dynamic", "P0", re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(?:\+|\$\{|format\(|f\")", re.I),
     "Potential dynamic SQL construction"),
    ("transaction", "P2", re.compile(r"\b(transaction|BEGIN TRANSACTION|commit\(|rollback\()\b", re.I),
     "Transactional data consistency boundary"),
]

LOG_RULES = [
    ("native_crash", "P0", re.compile(r"\b(SIGSEGV|SIGABRT|SIGBUS|SIGILL|tombstone)\b", re.I)),
    ("android_fatal", "P0", re.compile(r"FATAL EXCEPTION|ANR in |OutOfMemoryError", re.I)),
    ("permission_exec", "P1", re.compile(r"Permission denied|EACCES|rc=126", re.I)),
    ("not_found", "P1", re.compile(r"rc=127|ENOENT|not found|No such file", re.I)),
    ("linker", "P1", re.compile(r"dlopen failed|cannot locate symbol|undefined symbol|linker", re.I)),
    ("jni_abort", "P0", re.compile(r"JNI DETECTED ERROR|JNI ERROR|CheckJNI", re.I)),
    ("surface_backpressure", "P1", re.compile(r"Can't acquire next buffer|Already acquired max frames|BLASTBufferQueue|BufferQueue", re.I)),
    ("xkb", "P1", re.compile(r"xkbcomp|XKB", re.I)),
    ("vnc", "P2", re.compile(r"\b(Xvnc|VNC|RFB|5901)\b", re.I)),
    ("x11", "P2", re.compile(r"\b(XSDL|X11|DISPLAY|6000)\b", re.I)),
    ("network", "P1", re.compile(r"connection refused|timed? out|timeout|ECONNRESET|Broken pipe", re.I)),
    ("oom", "P0", re.compile(r"\b(OOM|Out of memory|low memory|malloc failed)\b", re.I)),
    ("deadlock", "P0", re.compile(r"\b(deadlock|blocked forever|lock timeout)\b", re.I)),
]

@dataclass
class Finding:
    id: str
    category: str
    severity: str
    status: str
    confidence: float
    file: str
    line: int
    snippet: str
    rationale: str
    fingerprint: str

def safe_root(root: str | Path | None = None) -> Path:
    raw = root or os.environ.get("NANO_REPO_ROOT") or os.getcwd()
    p = Path(raw).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        raise ValueError(f"Invalid repository root: {p}")
    return p

def iter_files(root: Path, only: set[str] | None = None) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        rel = str(p.relative_to(root))
        if only is not None and rel not in only:
            continue
        yield p

def read_text(path: Path, max_bytes: int = 3_000_000) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

def is_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTS or path.name in BUILD_NAMES

def _fingerprint(*parts: str) -> str:
    raw = "|".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]

def inventory(root: str | Path | None = None) -> dict[str, Any]:
    r = safe_root(root)
    fs = list(iter_files(r))
    ext_counts = Counter()
    builds, critical, tests = [], [], []
    for p in fs:
        ext_counts[p.suffix.lower() or "<none>"] += 1
        rel = str(p.relative_to(r))
        low = rel.lower()
        if p.name in BUILD_NAMES:
            builds.append(rel)
        if any(k in low for k in ("jni", "ffi", "worker", "service", "bridge", "runtime", "vnc", "x11", "cmake", "gradle")):
            critical.append(rel)
        if any(k in low for k in ("/test/", "/tests/", "_test.", "test_", "integration_test")):
            tests.append(rel)
    languages = {
        "kotlin": ext_counts[".kt"] + ext_counts[".kts"],
        "java": ext_counts[".java"],
        "dart": ext_counts[".dart"],
        "rust": ext_counts[".rs"],
        "c_cpp": sum(ext_counts[e] for e in (".c",".cc",".cpp",".cxx",".h",".hpp")),
        "python": ext_counts[".py"],
        "typescript_js": sum(ext_counts[e] for e in (".ts",".tsx",".js",".jsx",".mjs")),
        "go": ext_counts[".go"],
        "csharp": ext_counts[".cs"],
        "swift": ext_counts[".swift"],
    }
    return {
        "guardian_version": VERSION,
        "root": str(r),
        "files_scanned": len(fs),
        "languages": {k:v for k,v in languages.items() if v},
        "extensions": dict(ext_counts.most_common()),
        "build_files": sorted(builds),
        "critical_files": sorted(critical)[:1000],
        "test_files": sorted(tests)[:1000],
        "graphify_available": (r / "graphify-out/graph.json").exists(),
        "graphify_wiki": (r / "graphify-out/wiki/index.md").exists(),
        "agents_md": (r / "AGENTS.md").exists(),
    }

def syntax_scan(root: str | Path | None = None, only_files: list[str] | None = None) -> list[dict[str, Any]]:
    """Deterministic syntax/config checks where safe without external toolchains."""
    r = safe_root(root)
    only = set(only_files) if only_files else None
    out = []
    for p in iter_files(r, only):
        if not is_text_candidate(p):
            continue
        rel = str(p.relative_to(r))
        text = read_text(p)
        if not text:
            continue

        # Python syntax
        if p.suffix == ".py":
            try:
                ast.parse(text, filename=rel)
            except SyntaxError as e:
                out.append({
                    "severity":"P0","status":"CONFIRMED","category":"syntax_python",
                    "file":rel,"line":e.lineno or 1,"message":e.msg
                })

        # JSON syntax
        if p.suffix == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError as e:
                out.append({
                    "severity":"P0","status":"CONFIRMED","category":"syntax_json",
                    "file":rel,"line":e.lineno,"message":e.msg
                })

        # Merge conflicts
        for i,line in enumerate(text.splitlines(),1):
            if line.startswith(("<<<<<<<", "=======", ">>>>>>>")):
                out.append({
                    "severity":"P0","status":"CONFIRMED","category":"merge_conflict",
                    "file":rel,"line":i,"message":line[:300]
                })
    return out

def risk_scan(root: str | Path | None = None, max_findings: int = 1500, only_files: list[str] | None = None) -> list[dict[str, Any]]:
    r = safe_root(root)
    only = set(only_files) if only_files else None
    out: list[dict[str, Any]] = []
    seq = 0
    for p in iter_files(r, only):
        if not is_text_candidate(p):
            continue
        text = read_text(p)
        if not text:
            continue
        lines = text.splitlines()
        rel = str(p.relative_to(r))
        for category, severity, pattern, rationale in RISK_RULES:
            for m in pattern.finditer(text):
                seq += 1
                line_no = text.count("\n", 0, m.start()) + 1
                snippet = lines[line_no-1].strip() if 0 < line_no <= len(lines) else m.group(0)
                # Pattern scans are hypotheses unless deterministic (merge conflict)
                status = "CONFIRMED" if category == "merge_conflict" else "HYPOTHESIS_TO_VALIDATE"
                confidence = 1.0 if status == "CONFIRMED" else 0.45
                fp = _fingerprint(category, rel, re.sub(r"\s+"," ",snippet)[:200])
                out.append(asdict(Finding(
                    id=f"RISK-{seq:05d}", category=category, severity=severity, status=status,
                    confidence=confidence, file=rel, line=line_no, snippet=snippet[:500],
                    rationale=rationale, fingerprint=fp
                )))
                if len(out) >= max_findings:
                    return out
    return out

def duplicate_scan(root: str | Path | None = None, min_lines: int = 6, max_groups: int = 100) -> list[dict[str, Any]]:
    """Find likely exact duplicated code blocks. Exact-match only to avoid aggressive false positives."""
    r = safe_root(root)
    buckets = defaultdict(list)
    for p in iter_files(r):
        if p.suffix.lower() not in CODE_EXTS:
            continue
        text = read_text(p)
        lines = text.splitlines()
        for i in range(0, max(0, len(lines)-min_lines+1)):
            block = "\n".join(x.strip() for x in lines[i:i+min_lines] if x.strip())
            if len(block) < 80:
                continue
            digest = hashlib.sha1(block.encode()).hexdigest()
            buckets[digest].append((str(p.relative_to(r)), i+1, block[:600]))
    groups = []
    for digest, locs in buckets.items():
        unique_files = {x[0] for x in locs}
        if len(locs) > 1 and len(unique_files) > 1:
            groups.append({
                "fingerprint": digest[:16],
                "occurrences": [{"file":f,"line":ln} for f,ln,_ in locs[:20]],
                "sample": locs[0][2],
                "status": "HYPOTHESIS_TO_VALIDATE",
                "severity": "P3",
                "category": "exact_duplicate_block",
            })
            if len(groups) >= max_groups:
                break
    return groups

def hotspot_scan(root: str | Path | None = None, top_n: int = 50) -> list[dict[str, Any]]:
    """Rank files by size + branch complexity proxy + risk-boundary count."""
    r = safe_root(root)
    risks = risk_scan(r, max_findings=5000)
    risk_counts = Counter(x["file"] for x in risks)
    rows = []
    for p in iter_files(r):
        if p.suffix.lower() not in CODE_EXTS:
            continue
        text = read_text(p)
        if not text:
            continue
        lines = text.splitlines()
        branches = len(re.findall(r"\b(if|else if|elif|switch|case|when|for|while|catch)\b", text))
        funcs = len(re.findall(r"\b(def|fun|fn|function|void|int|bool|String|Future<|suspend fun)\s+\w+", text))
        rel = str(p.relative_to(r))
        score = len(lines) * 0.1 + branches * 2.0 + risk_counts[rel] * 3.0
        rows.append({
            "file": rel,
            "lines": len(lines),
            "branch_proxy": branches,
            "function_proxy": funcs,
            "risk_boundaries": risk_counts[rel],
            "hotspot_score": round(score,2),
            "status":"INFORMATIONAL",
        })
    return sorted(rows, key=lambda x:x["hotspot_score"], reverse=True)[:top_n]

def architecture_smells(root: str | Path | None = None) -> list[dict[str, Any]]:
    """Architecture-oriented heuristics with conservative classification."""
    out = []
    for row in hotspot_scan(root, top_n=200):
        if row["lines"] >= 1200:
            out.append({
                "category":"god_file_candidate","severity":"P2","status":"HYPOTHESIS_TO_VALIDATE",
                "file":row["file"],"evidence":f'{row["lines"]} lines',
                "recommendation":"Inspect responsibility count, fan-in/fan-out and lifecycle ownership before refactoring."
            })
        if row["branch_proxy"] >= 100:
            out.append({
                "category":"high_branch_complexity","severity":"P2","status":"HYPOTHESIS_TO_VALIDATE",
                "file":row["file"],"evidence":f'branch proxy={row["branch_proxy"]}',
                "recommendation":"Inspect state machine/branch decomposition and test coverage."
            })
    return out

def _extract(pattern: str, text: str):
    m = re.search(pattern, text, re.M)
    return m.group(1) if m else None

def build_compatibility_matrix(root: str | Path | None = None) -> dict[str, Any]:
    r = safe_root(root)
    matrix: dict[str, Any] = {}
    for p in iter_files(r):
        if p.name not in BUILD_NAMES:
            continue
        text = read_text(p)
        rel = str(p.relative_to(r))
        if p.name in ("build.gradle", "build.gradle.kts"):
            matrix.setdefault("android_gradle", []).append({
                "file": rel,
                "compileSdk": _extract(r"compileSdk(?:Version)?\s*[= ]\s*(\d+)", text),
                "targetSdk": _extract(r"targetSdk(?:Version)?\s*[= ]\s*(\d+)", text),
                "minSdk": _extract(r"minSdk(?:Version)?\s*[= ]\s*(\d+)", text),
                "ndkVersion": _extract(r'ndkVersion\s*=\s*"([^"]+)"', text),
                "jvmTarget": _extract(r'jvmTarget\s*=\s*["\']?([^"\'\s]+)', text),
            })
        elif p.name == "gradle-wrapper.properties":
            matrix["gradle_wrapper"] = {
                "file":rel,
                "distribution":_extract(r"distributionUrl=.*gradle-([0-9.]+)-", text)
            }
        elif p.name == "pubspec.yaml":
            matrix.setdefault("flutter", []).append({
                "file": rel,
                "dart_constraint": _extract(r"sdk:\s*[\"']?([^\"'\n]+)", text),
                "flutter_sdk": "declared" if "flutter:" in text else None,
            })
        elif p.name == "Cargo.toml":
            matrix.setdefault("rust", []).append({
                "file": rel,
                "edition": _extract(r'edition\s*=\s*"([^"]+)"', text),
                "rust_version": _extract(r'rust-version\s*=\s*"([^"]+)"', text),
            })
        elif p.name == "CMakeLists.txt":
            matrix.setdefault("cmake", []).append({
                "file": rel,
                "minimum": _extract(r"cmake_minimum_required\s*\(\s*VERSION\s+([0-9.]+)", text),
            })
        elif p.name == "package.json":
            try:
                obj = json.loads(text)
                matrix.setdefault("node", []).append({
                    "file": rel,
                    "engines": obj.get("engines"),
                    "packageManager": obj.get("packageManager"),
                    "dependencies": obj.get("dependencies", {}),
                    "devDependencies": obj.get("devDependencies", {}),
                })
            except Exception:
                pass
        elif p.name == "pyproject.toml":
            matrix.setdefault("python", []).append({
                "file": rel,
                "requires_python": _extract(r'requires-python\s*=\s*"([^"]+)"', text),
            })
        elif p.name == "go.mod":
            matrix.setdefault("go", []).append({
                "file":rel, "go_version":_extract(r"^go\s+([0-9.]+)", text)
            })
        elif p.name == "AndroidManifest.xml":
            matrix.setdefault("android_manifest", []).append({"file": rel})
    return matrix

def dependency_inventory(root: str | Path | None = None) -> list[dict[str, Any]]:
    """Extract dependency declarations without resolving remote registries."""
    r = safe_root(root)
    deps = []
    for p in iter_files(r):
        text = read_text(p)
        rel = str(p.relative_to(r))
        if p.name == "package.json":
            try:
                obj = json.loads(text)
                for scope in ("dependencies","devDependencies","peerDependencies"):
                    for name,ver in (obj.get(scope) or {}).items():
                        deps.append({"ecosystem":"npm","file":rel,"scope":scope,"name":name,"version":ver})
            except Exception:
                pass
        elif p.name == "pubspec.yaml":
            current = None
            for line in text.splitlines():
                if re.match(r"^(dependencies|dev_dependencies):\s*$", line):
                    current = line.split(":")[0]
                    continue
                if current and re.match(r"^\S", line):
                    current = None
                if current:
                    m = re.match(r"^\s{2}([A-Za-z0-9_\-]+):\s*(.*)$", line)
                    if m:
                        deps.append({"ecosystem":"pub","file":rel,"scope":current,"name":m.group(1),"version":m.group(2).strip() or "<complex>"})
        elif p.name in ("build.gradle","build.gradle.kts"):
            for m in re.finditer(r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*["']([^:"']+):([^:"']+):([^"']+)["']""", text):
                deps.append({"ecosystem":"gradle","file":rel,"scope":"dependency","name":f"{m.group(1)}:{m.group(2)}","version":m.group(3)})
        elif p.name == "requirements.txt":
            for line in text.splitlines():
                s=line.strip()
                if s and not s.startswith("#"):
                    deps.append({"ecosystem":"pip","file":rel,"scope":"runtime","name":s,"version":"<inline>"})
    return deps

def analyze_log_text(text: str, max_per_category: int = 50) -> dict[str, Any]:
    categories: dict[str,list[dict[str,Any]]] = {}
    incidents = []
    lines = text.splitlines()
    for idx,line in enumerate(lines,1):
        for category,severity,pattern in LOG_RULES:
            if pattern.search(line):
                bucket = categories.setdefault(category,[])
                if len(bucket) < max_per_category:
                    fp = _fingerprint(category, re.sub(r"\d+","<n>", line)[:400])
                    item = {"line":idx,"text":line[:1200],"severity":severity,"fingerprint":fp}
                    bucket.append(item)
                    incidents.append({"category":category, **item})
    # group fingerprints
    fp_counts = Counter(x["fingerprint"] for x in incidents)
    groups = []
    seen = set()
    for x in incidents:
        fp=x["fingerprint"]
        if fp in seen: continue
        seen.add(fp)
        groups.append({
            "fingerprint":fp,
            "category":x["category"],
            "severity":x["severity"],
            "count":fp_counts[fp],
            "first_line":x["line"],
            "sample":x["text"],
        })
    groups.sort(key=lambda x:(-SEVERITY_WEIGHTS.get(x["severity"],0), x["first_line"]))
    return {
        "categories":categories,
        "incident_groups":groups,
        "earliest_high_severity": next((g for g in sorted(groups,key=lambda x:x["first_line"]) if g["severity"] in ("P0","P1")), None),
    }

def git_changed_files(root: str | Path | None = None, staged: bool = False) -> list[str]:
    r=safe_root(root)
    cmd=["git","diff","--name-only"]
    if staged:
        cmd.insert(2,"--cached")
    try:
        cp=subprocess.run(cmd,cwd=r,shell=False,capture_output=True,text=True,timeout=20)
        if cp.returncode != 0:
            return []
        return [x.strip() for x in cp.stdout.splitlines() if x.strip()]
    except Exception:
        return []

def incremental_scan(root: str | Path | None = None, staged: bool = False) -> dict[str,Any]:
    files=git_changed_files(root, staged=staged)
    return {
        "changed_files":files,
        "syntax":syntax_scan(root, files),
        "risks":risk_scan(root, only_files=files, max_findings=1000),
    }

def search_code(query: str, root: str | Path | None = None, max_results: int = 100):
    if not query.strip():
        raise ValueError("query must not be empty")
    r = safe_root(root)
    q=query.lower()
    out=[]
    for p in iter_files(r):
        if not is_text_candidate(p):
            continue
        for i,line in enumerate(read_text(p).splitlines(),1):
            if q in line.lower():
                out.append({"file":str(p.relative_to(r)),"line":i,"text":line.strip()[:600]})
                if len(out)>=max_results:
                    return out
    return out

def knowledge_dir(root: str | Path | None = None) -> Path:
    r=safe_root(root)
    p=r/".repo-guardian"
    p.mkdir(exist_ok=True)
    return p

def load_knowledge(root: str | Path | None = None) -> dict[str,Any]:
    p=knowledge_dir(root)/"knowledge.json"
    if not p.exists():
        return {"version":1,"verified_patterns":{},"false_positives":{},"fix_outcomes":[]}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"version":1,"verified_patterns":{},"false_positives":{},"fix_outcomes":[]}

def record_verified_outcome(
    fingerprint: str,
    outcome: str,
    root: str | Path | None = None,
    root_cause: str = "",
    fix: str = "",
    evidence: str = "",
) -> dict[str,Any]:
    """Learn only from explicit verified feedback. Writes only .repo-guardian/knowledge.json."""
    if outcome not in {"CONFIRMED","FALSE_POSITIVE","FIX_PASS","FIX_FAIL","REGRESSION"}:
        raise ValueError("invalid outcome")
    data=load_knowledge(root)
    if outcome=="CONFIRMED":
        data["verified_patterns"][fingerprint]=data["verified_patterns"].get(fingerprint,0)+1
    elif outcome=="FALSE_POSITIVE":
        data["false_positives"][fingerprint]=data["false_positives"].get(fingerprint,0)+1
    data["fix_outcomes"].append({
        "fingerprint":fingerprint,"outcome":outcome,"root_cause":root_cause[:1000],
        "fix":fix[:2000],"evidence":evidence[:2000]
    })
    data["version"]=int(data.get("version",1))+1
    p=knowledge_dir(root)/"knowledge.json"
    p.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
    return {"status":"RECORDED","knowledge_version":data["version"],"path":str(p)}

def apply_knowledge(findings: list[dict[str,Any]], root: str | Path | None = None) -> list[dict[str,Any]]:
    kb=load_knowledge(root)
    for f in findings:
        fp=f.get("fingerprint","")
        confirmed=kb.get("verified_patterns",{}).get(fp,0)
        false=kb.get("false_positives",{}).get(fp,0)
        base=float(f.get("confidence",0.45))
        adjusted=max(0.05,min(0.95,base + confirmed*0.08 - false*0.12))
        f["confidence"]=round(adjusted,2)
        f["knowledge_confirmations"]=confirmed
        f["knowledge_false_positives"]=false
    return findings

ALLOWED_VERIFY = {
    "git_diff_check": ["git","diff","--check"],
    "cargo_check": ["cargo","check","--workspace"],
    "cargo_fmt_check": ["cargo","fmt","--all","--","--check"],
    "cargo_clippy": ["cargo","clippy","--workspace","--all-targets","--","-D","warnings"],
    "dart_analyze": ["dart","analyze"],
    "flutter_analyze": ["flutter","analyze"],
    "go_test": ["go","test","./..."],
}

def verify(check: str, root: str | Path | None = None, timeout: int = 180) -> dict[str,Any]:
    if check not in ALLOWED_VERIFY:
        raise ValueError(f"check not allowed: {check}")
    r=safe_root(root)
    cmd=ALLOWED_VERIFY[check]
    try:
        cp=subprocess.run(cmd,cwd=r,shell=False,capture_output=True,text=True,timeout=timeout)
        return {
            "check":check,"command":cmd,"returncode":cp.returncode,
            "stdout":cp.stdout[-30000:],"stderr":cp.stderr[-30000:],
            "status":"PASS" if cp.returncode==0 else "FAIL"
        }
    except FileNotFoundError as e:
        return {"check":check,"status":"UNVERIFIED","error":str(e)}
    except subprocess.TimeoutExpired:
        return {"check":check,"status":"FAIL","error":f"timeout after {timeout}s"}

def deep_snapshot(root: str | Path | None = None) -> dict[str,Any]:
    risks=apply_knowledge(risk_scan(root,max_findings=3000),root)
    return {
        "inventory":inventory(root),
        "compatibility":build_compatibility_matrix(root),
        "dependencies":dependency_inventory(root)[:3000],
        "syntax":syntax_scan(root),
        "architecture_smells":architecture_smells(root),
        "hotspots":hotspot_scan(root),
        "risk_summary":dict(Counter(x["category"] for x in risks)),
        "severity_summary":dict(Counter(x["severity"] for x in risks)),
        "knowledge":load_knowledge(root),
    }
