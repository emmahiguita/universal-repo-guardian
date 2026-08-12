# Playbook: Zombies / huérfanos / sockets obsoletos

## Síntomas
- Procesos `<defunct>` en `ps` que nunca desaparecen
- Duplicados del mismo daemon tras reinicios
- `Too many open files` / puertos en TIME_WAIT acumulados
- Sockets/locks/PID files obsoletos que bloquean el arranque

## Diagnóstico
1. Mapea padre/hijo: quién crea cada proceso, quién guarda el PID, quién lo para, quién lo reapa.
2. Captura PID + exit code + señal de cada hijo al morir.
3. Verifica `waitpid`/`SIGCHLD` ownership: si nadie reapa, todo hijo muerto = zombie.
4. Ciclos stop/start repetidos → ¿nuevo proceso sin matar el anterior?
5. Revisa archivos de estado: socket Unix, lockfile, PID file — ¿se limpian al parar?

## Causas raíz comunes
- `waitpid` nunca llamado (o llamado en el sitio equivocado)
- Orphan: padre muere antes que el hijo → reparent a init, sin supervisión
- Doble start sin stop: daemon arrancado dos veces (dos dueños)
- Wrapper vs proceso real: se mata el wrapper, el proceso interno sigue vivo
- Señal enviada a PID obsoleto tras reuso

## Fix mínimo
- Dueño único por proceso con `waitpid(-1, ..., WNOHANG)` en bucle o manejador `SIGCHLD`
- Antes de start: comprobar liveness del PID previo; si vivo, no duplicar
- Matar en orden correcto: proceso interno primero, wrapper después
- Limpiar socket/lock/pid file en el camino de parada (finally)
- Verificar que el proceso invocado directamente no se daemoniza (algunos lo hacen — revisar flags)

## Verificación
1. Stop/start × 20 → cero zombies (`ps | grep defunct`)
2. Matar hijo manualmente → padre lo reapa en <1s
3. Matar padre → hijos no quedan huérfanos vivos
4. FDs y sockets estables tras 100 ciclos
5. Tras parada: sin socket/lock residual que bloquee el siguiente arranque

## Errores típicos
- Asumir que `kill` limpia todo — kill no reapa nada
- Probar solo un arranque — los zombies aparecen con los ciclos
- Confundir daemonización: `Xvnc` directo queda en foreground, el wrapper `vncserver` es quien forkea
