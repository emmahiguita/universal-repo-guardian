from __future__ import annotations
import os
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:
    raise SystemExit("Install the MCP SDK: pip install -e .") from exc

from .core import (
    analyze_log_text, apply_knowledge, architecture_smells, build_compatibility_matrix,
    deep_snapshot, dependency_inventory, duplicate_scan, hotspot_scan, incremental_scan,
    inventory, load_knowledge, record_verified_outcome, risk_scan, search_code,
    syntax_scan, verify,
)

ROOT = Path(os.environ.get("NANO_REPO_ROOT", os.getcwd())).resolve()
mcp = FastMCP("universal-repo-guardian")

@mcp.tool()
def repo_inventory() -> dict:
    """Discover languages, builds, tests, critical runtime files and Graphify support."""
    return inventory(ROOT)

@mcp.tool()
def syntax_and_malformed_scan() -> list[dict]:
    """Deterministic syntax/config scan for supported in-process parsers and merge-conflict markers."""
    return syntax_scan(ROOT)

@mcp.tool()
def repo_search(query: str, max_results: int = 100) -> list[dict]:
    """Search code/config text without arbitrary shell execution."""
    return search_code(query, ROOT, max_results)

@mcp.tool()
def risk_boundaries(max_findings: int = 1500) -> list[dict]:
    """Find risk boundaries. Results are hypotheses unless deterministic evidence exists."""
    return apply_knowledge(risk_scan(ROOT, max_findings), ROOT)

@mcp.tool()
def architecture_risks() -> list[dict]:
    """Find high-complexity/god-file candidates requiring architectural review."""
    return architecture_smells(ROOT)

@mcp.tool()
def duplicate_code_scan(min_lines: int = 6, max_groups: int = 100) -> list[dict]:
    """Find exact duplicated code blocks across files."""
    return duplicate_scan(ROOT, min_lines, max_groups)

@mcp.tool()
def hotspot_files(top_n: int = 50) -> list[dict]:
    """Rank likely engineering hotspots by size, branching and risk-boundary density."""
    return hotspot_scan(ROOT, top_n)

@mcp.tool()
def compatibility_matrix() -> dict:
    """Extract local SDK/toolchain/dependency declarations. Remote compatibility still needs authoritative verification."""
    return build_compatibility_matrix(ROOT)

@mcp.tool()
def dependencies() -> list[dict]:
    """Inventory declared dependencies across npm/pub/Gradle/pip when detectable."""
    return dependency_inventory(ROOT)

@mcp.tool()
def analyze_log(log_text: str) -> dict:
    """Cluster runtime log errors by fingerprint and identify the earliest high-severity signal."""
    return analyze_log_text(log_text)

@mcp.tool()
def scan_changed_files(staged: bool = False) -> dict:
    """Fast incremental scan over git-diff changed files."""
    return incremental_scan(ROOT, staged=staged)

@mcp.tool()
def repository_deep_snapshot() -> dict:
    """Combined repository engineering snapshot for a deep audit."""
    return deep_snapshot(ROOT)

@mcp.tool()
def knowledge_status() -> dict:
    """Read the local verified-learning database."""
    return load_knowledge(ROOT)

@mcp.tool()
def learn_verified_outcome(
    fingerprint: str,
    outcome: str,
    root_cause: str = "",
    fix: str = "",
    evidence: str = "",
) -> dict:
    """Versioned learning from explicitly verified outcomes only. Writes only .repo-guardian/knowledge.json."""
    return record_verified_outcome(fingerprint, outcome, ROOT, root_cause, fix, evidence)

@mcp.tool()
def run_verification(check: str, timeout: int = 180) -> dict:
    """Run a strict allow-listed verification command; arbitrary shell execution is not exposed."""
    return verify(check, ROOT, timeout)

@mcp.prompt()
def universal_deep_audit() -> str:
    return """Act as a principal engineering QA/code-forensics auditor.

Mandatory order:
1. repo_inventory
2. if graphify-out/graph.json exists, use Graphify before broad raw browsing
3. syntax_and_malformed_scan
4. compatibility_matrix + dependencies
5. architecture_risks + hotspot_files + duplicate_code_scan
6. risk_boundaries
7. targeted repo_search around P0/P1 candidates
8. correlate supplied logs with analyze_log
9. reconstruct runtime/lifecycle/ownership graphs
10. classify every claim:
   CONFIRMED / HYPOTHESIS_TO_VALIDATE / DISCARDED / INFORMATIONAL
11. separate symptom from root cause
12. create bug dependency graph
13. generate bug-correction sprints
14. propose minimal correction before structural refactor
15. define before/after verification, regression and rollback

Never call a pattern a confirmed bug without evidence.
Never call a fix PASS because build alone succeeds.
"""

@mcp.prompt()
def bug_sprint_report() -> str:
    return """Generate an engineering bug-correction report:
- executive health matrix
- confirmed P0/P1/P2/P3
- bug dependency graph
- Sprint 0 baseline
- build blockers
- crashes/security/data integrity
- logic/state/lifecycle
- processes/memory/concurrency
- connectivity/compatibility
- performance
- architecture/cleanup
- final regression

For every bug include:
ID, evidence, file/symbol, root cause, impact, minimal fix, structural fix,
files to modify, files not to touch, test, lifecycle verification,
resource cleanup, regression, rollback and closure gate.
"""

@mcp.prompt()
def verify_fix() -> str:
    return """Verification Gate:
baseline -> reproduce -> root cause -> minimal patch -> static checks ->
build -> focused test -> runtime -> lifecycle -> resource cleanup ->
adjacent regression -> diff review.
Final status is only PASS / PARTIAL / FAIL / UNVERIFIED.
"""

def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
