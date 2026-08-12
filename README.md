# Universal Repo Guardian Pro v2

A repository-agnostic engineering QA, code-forensics and bug-correction MCP + Skills bundle.

## What v2 adds
- deterministic Python/JSON syntax checks
- malformed merge-conflict detection
- universal risk-boundary scanning
- exact duplicate block detection
- hotspot ranking
- architecture smell candidates
- dependency inventory
- SDK/toolchain compatibility extraction
- log fingerprinting and incident clustering
- earliest high-severity log signal
- incremental git-diff scanning
- evidence-gated self-improving local knowledge
- bug-sprint and verification prompts
- playbooks for common bug families
- strict allow-listed verification commands

## Skills
- `nano-repo-surgeon` — now universal repository guardian
- `android-native-runtime-debugger`
- `verification-gatekeeper`
- `adaptive-bug-intelligence`

## MCP tools
- repo_inventory
- syntax_and_malformed_scan
- repo_search
- risk_boundaries
- architecture_risks
- duplicate_code_scan
- hotspot_files
- compatibility_matrix
- dependencies
- analyze_log
- scan_changed_files
- repository_deep_snapshot
- knowledge_status
- learn_verified_outcome
- run_verification

## Safety model
The MCP does not expose arbitrary shell execution.
Verification commands are allow-listed.
Adaptive learning writes only `.repo-guardian/knowledge.json`.
Pattern matches remain hypotheses unless deterministic evidence proves them.

## Installation
```powershell
cd nano_repo_guardian_pro_v2
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
$env:NANO_REPO_ROOT="C:\path\to\repository"
nano-repo-guardian
```

## Suggested workflow
1. `repo_inventory`
2. Graphify if present
3. `syntax_and_malformed_scan`
4. `compatibility_matrix`
5. `dependencies`
6. `architecture_risks`
7. `hotspot_files`
8. `duplicate_code_scan`
9. `risk_boundaries`
10. targeted `repo_search`
11. `analyze_log`
12. reconstruct root cause
13. generate correction sprint
14. patch minimally
15. `run_verification`
16. runtime/regression validation
17. record only verified outcomes with `learn_verified_outcome`

## Important
This tool improves detection ranking from verified history. It does not claim to mathematically guarantee that every possible software defect will be found.
