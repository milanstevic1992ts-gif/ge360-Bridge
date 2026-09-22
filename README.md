# GE360 Universal Bridge

Versione corrente: **v0.15 — Fase 13 completata: Auto discovery backend**. La Fase 14 — Agent Linux è la prossima e non è stata avviata.

La fonte di verità resta `docs/ROADMAP.md`.

## Backend auto discovery

I backend GE360 possono dichiararsi tramite:

```text
GET /.well-known/ge360
```

Il Bridge rileva soltanto backend locali loopback, valida rigidamente il manifest e li propone senza importarli automaticamente.

CLI:

```bash
ge360-bridge resource-discover
sudo ge360-bridge resource-import 9888
```

Dashboard autenticata:

```text
http://127.0.0.1:8789/discovery
```

Il Resource Registry esistente resta autoritativo e `services.json` continua a essere il mirror di compatibilità.

## Android automatic connection

Il modulo `ge360-bridge-android` mantiene WireGuard Android ufficiale, GoBackend, VpnService, reconnect, backoff, auto-restore e persistenza cifrata Android Keystore.

Il tunnel resta limitato a:

```text
10.88.0.1/32
```

## Limite di rete

L'auto-discovery non risolve CGNAT. Se non esiste IPv4 pubblico raggiungibile o IPv6 globale raggiungibile, la connessione diretta da Internet non può essere garantita senza un futuro nodo pubblico/relay/rendezvous.

Vedi `docs/BACKEND_DISCOVERY.md`.
