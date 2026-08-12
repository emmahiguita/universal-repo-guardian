---
name: adaptive-bug-intelligence
description: Usar al registrar o rankear resultados verificados de bugs entre auditorías — bugs confirmados, falsos positivos, fixes aprobados/fallidos, memoria de regresión, promoción/degradación de reglas, versionado de conocimiento en .repo-guardian/knowledge.json.
---

# ADAPTIVE BUG INTELLIGENCE

## Propósito
Mejorar la calidad de detección con el tiempo sin auto-modificación insegura.

## Entradas de aprendizaje
- bugs confirmados
- falsos positivos
- fixes aprobados/fallidos
- regresiones
- fingerprints de incidentes
- resultados de compatibilidad verificados

## Principios de aprendizaje
- con evidencia
- versionado
- reversible
- local al repositorio
- explicable

## Nunca aprender de
- una suposición no verificada del modelo
- un warning de build por sí solo
- un match de patrón único
- un test fallido con causa desconocida

## Campos de conocimiento
fingerprint
categoría
contexto
causa raíz
fix
verificación
conteo de falsos positivos
conteo de confirmaciones
enlaces de regresión

## Ranking adaptativo
Subir confianza levemente con patrones verificados repetidos.
Bajar confianza con falsos positivos verificados.
Nunca convertir confianza en prueba.

## Memoria de regresión
Si el componente X causó antes la regresión Y, cambios futuros en X deben recomendar Y como chequeo de regresión dirigido.

## Memoria de fixes fallidos
Registrar correcciones fallidas para no repetirlas sin evidencia nueva.

## Promoción de reglas
EXPERIMENTAL → OBSERVED → RELIABLE
solo tras múltiples casos verificados independientemente.

## Degradación de reglas
RELIABLE → REVIEW → LOW_CONFIDENCE
cuando suben los falsos positivos.

## Versionado
Cada mutación de conocimiento incrementa la versión de conocimiento.
Cada auditoría debe registrar commit del repositorio + versión del guardian + versión de conocimiento.
