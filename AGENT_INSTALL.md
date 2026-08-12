# Integración con agentes

## Skills
Instalar/copiar a la carpeta de skills del agente (ej. `~/.claude/skills/`):
- nano-repo-surgeon
- android-native-runtime-debugger
- verification-gatekeeper
- adaptive-bug-intelligence

## MCP server
Ver `README.md` → Instalación → MCP server.

## Política recomendada para AGENTS.md

```md
## QA de ingeniería / forensia de bugs
Para depuración a nivel de repositorio:
1. Usa Graphify primero cuando exista graphify-out/graph.json.
2. Ejecuta los escaneos de Universal Repo Guardian: inventory/syntax/compatibility/hotspot/risk.
3. Distingue CONFIRMED de HYPOTHESIS_TO_VALIDATE.
4. Reconstruye runtime, ciclo de vida y propiedad antes de parchear.
5. Produce grafo de dependencias de bugs + sprints de corrección.
6. Prefiere fixes mínimos de causa raíz.
7. Ejecuta gates de verificación y regresión adyacente.
8. Registra aprendizaje SOLO de resultados verificados.
9. Actualiza Graphify después de cambios de código.
```
