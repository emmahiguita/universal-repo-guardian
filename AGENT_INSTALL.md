# Agent integration

Install/copy the Skills:
- nano-repo-surgeon
- android-native-runtime-debugger
- verification-gatekeeper
- adaptive-bug-intelligence

Recommended AGENTS.md policy:

```md
## Engineering QA / bug forensics
For repository-wide debugging:
1. Use Graphify first when `graphify-out/graph.json` exists.
2. Run Universal Repo Guardian inventory/syntax/compatibility/hotspot/risk scans.
3. Distinguish CONFIRMED from HYPOTHESIS_TO_VALIDATE.
4. Reconstruct runtime, lifecycle and ownership before patching.
5. Produce bug dependency graph + correction sprints.
6. Prefer minimal root-cause fixes.
7. Run verification gates and adjacent regression.
8. Record learning only from verified outcomes.
9. Update Graphify after code changes.
```
