# Universal Repo Guardian Pro v2

Bundle de QA de ingeniería, forensia de código y corrección de bugs, agnóstico de repositorio: MCP server + 4 skills para agentes (Claude Code).

## Qué añade v2
- Checks determinísticos de sintaxis Python (ast) y JSON (parseo real)
- Detección de marcadores de merge conflict sin resolver
- Escaneo universal de fronteras de riesgo (33 reglas: errores, procesos, memoria nativa, JNI/FFI, concurrencia, red, TLS, shell/SQL, Flutter/Android)
- Detección de bloques duplicados exactos entre archivos
- Ranking de hotspots de ingeniería
- Candidatos a smells de arquitectura (god-file, complejidad de ramas)
- Inventario de dependencias (npm/pub/Gradle/pip)
- Extracción de matriz de compatibilidad SDK/toolchain
- Fingerprinting de logs y agrupación de incidentes
- Señal de alta severidad más temprana en logs
- Escaneo incremental sobre git diff
- Aprendizaje local con evidencia (`learn_verified_outcome`)
- Prompts de sprints de bugs y verificación
- Playbooks para familias comunes de bugs
- Comandos de verificación con allow-list estricta

## Skills
- `nano-repo-surgeon` — auditoría QA profunda de cualquier repo (30 dimensiones), sprints de corrección
- `android-native-runtime-debugger` — diagnóstico de fallos nativos Android/JNI/Xvnc/VNC
- `verification-gatekeeper` — 16 gates de verificación, nunca PASS solo por build
- `adaptive-bug-intelligence` — aprendizaje versionado con evidencia

## Herramientas MCP
- `repo_inventory`
- `syntax_and_malformed_scan`
- `repo_search`
- `risk_boundaries`
- `architecture_risks`
- `duplicate_code_scan`
- `hotspot_files`
- `compatibility_matrix`
- `dependencies`
- `analyze_log`
- `scan_changed_files`
- `repository_deep_snapshot`
- `knowledge_status`
- `learn_verified_outcome`
- `run_verification`

## Modelo de seguridad
- El MCP NO expone ejecución de shell arbitraria
- Comandos de verificación con allow-list (git diff, cargo, dart/flutter analyze, go test)
- El aprendizaje adaptativo escribe únicamente `.repo-guardian/knowledge.json`
- Los matches por patrón son hipótesis salvo evidencia determinística (ej. merge conflict)

## Instalación

### MCP server (Claude Code)
1. Instalar SDK: `pip install mcp`
2. Copiar `nano_repo_guardian/` a una ubicación estable (ej. `~/.claude/mcp-servers/nano-repo-guardian/`)
3. Registrar en `~/.claude/.claude.json` bajo la clave raíz `mcpServers`:
```json
"nano-repo-guardian": {
  "type": "stdio",
  "command": "python",
  "args": ["C:\\Users\\<usuario>\\.claude\\mcp-servers\\nano-repo-guardian\\nano_repo_guardian\\server.py"],
  "env": {}
}
```
4. Reiniciar Claude Code y verificar con `/mcp` → debe mostrar `nano-repo-guardian √ Connected`.

El server soporta ejecución como script (`python server.py`) o módulo (`python -m nano_repo_guardian.server`) y fuerza UTF-8 en stdout para Windows.

### Skills
Copiar cada carpeta de `skills/` a `~/.claude/skills/` (Claude Code) — quedan activas en la siguiente sesión.

### Como paquete pip (opcional)
```powershell
cd nano_repo_guardian_pro_v2
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
nano-repo-guardian
```

## Flujo de trabajo sugerido
1. `repo_inventory`
2. Graphify si `graphify-out/graph.json` existe
3. `syntax_and_malformed_scan`
4. `compatibility_matrix`
5. `dependencies`
6. `architecture_risks`
7. `hotspot_files`
8. `duplicate_code_scan`
9. `risk_boundaries`
10. `repo_search` dirigido sobre candidatos
11. `analyze_log` con logs del runtime
12. reconstruir causa raíz
13. generar sprint de corrección
14. patch mínimo
15. `run_verification`
16. validación de runtime/regresión
17. registrar SOLO resultados verificados con `learn_verified_outcome`

## Importante
Esta herramienta mejora el ranking de detección con historial verificado. No garantiza matemáticamente encontrar todos los defectos de software posibles.
