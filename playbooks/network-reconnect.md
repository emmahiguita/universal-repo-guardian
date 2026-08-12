# Playbook: Reconexión de red / sockets locales

## Síntomas
- Tras caída de red, el servicio nunca vuelve
- Bucles de reconexión duplicados (2-3 intentos por tick)
- Socket local (localhost) conectado pero protocolo muerto
- `ECONNRESET` / `Broken pipe` / `connection refused` en cascada

## Diagnóstico
1. Mapea el dueño de la conexión: quién conecta, quién reconecta, quién limpia.
2. Verifica timeouts en TODA operación de socket (connect/read/write).
3. Detecta bucles duplicados: ¿reconnect scheduled desde más de un sitio?
4. Backoff: ¿exponencial con cota? ¿o reintento inmediato infinito?
5. Distingue estados: TCP abierto ≠ protocolo listo (PORT_OPEN != PROTOCOL_READY) — sondear salud real (handshake/header).

## Causas raíz comunes
- Un solo hilo de reconexión sin backoff → martilleo
- Handler/reconnect programado dos veces (onDisconnect + watchdog)
- Sin timeout de read → hilo colgado para siempre
- Reinicio que no cierra el socket anterior → FDs y puertos acumulados
- Health check por ping TCP cuando el protocolo requiere handshake (RFB, Binder, etc.)

## Fix mínimo
- Backoff exponencial con jitter y cota (ej. 1s→2s→4s… máx 30s)
- Rebind/retry programado desde UNA sola ruta (quitar callbacks del camino viejo antes de reprogramar)
- Timeout en connect + read/write con cancelación limpia
- Cerrar socket/FD viejo antes de abrir el nuevo
- Readiness = señal de salud de la capa de aplicación, no TCP open

## Verificación
1. Matar el peer → reconexión en <5s con backoff visible en logs
2. Apagar/encender red (o `adb shell svc wifi disable`) → recuperación acotada
3. 100 ciclos de caída → sin FDs acumulados, sin bucles duplicados
4. Peer que acepta TCP pero no habla protocolo → timeout dispara, no cuelgue
5. Regresión: latencia normal sin reintentos espurios

## Errores típicos
- Probar solo el happy path — la reconexión nunca se ejercita
- Añadir reintento infinito sin backoff "para que no falle"
- Confundir puerto abierto con protocolo listo (clásico con VNC/Xvnc)
