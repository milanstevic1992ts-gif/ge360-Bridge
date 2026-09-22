# GE360 Universal Bridge

Versione corrente: **v0.16 — Fase 14: Linux Agent in verifica CI**.

La fonte di verità resta `docs/ROADMAP.md`.

## Linux Agent

La Fase 14 aggiunge un Agent Linux leggero e read-only per host aggiuntivi.

Dati disponibili:

- stato host;
- Resource GE360 locali;
- health;
- indirizzi IP;
- metriche CPU/load, memoria, disco e rete.

Installazione separata su un host Linux:

```bash
sudo ./install-agent.sh
```

API locale predefinita:

```text
http://127.0.0.1:8791
```

Snapshot locale:

```bash
sudo ge360-agent snapshot
```

Gli endpoint `/v1/*` richiedono Bearer token. Il bind predefinito resta loopback.

La Fase 14 **non** implementa self-healing, routing di Resource remote, NAT traversal o control plane multi-server.

## Backend auto discovery

I backend GE360 dichiarano la propria identità tramite:

```text
GET /.well-known/ge360
```

Il discovery continua a essere confinato al loopback e non effettua scansioni LAN.

## Android automatic connection

Il modulo `ge360-bridge-android` mantiene WireGuard Android ufficiale, GoBackend, VpnService, reconnect, backoff, auto-restore e persistenza cifrata Android Keystore.

Il tunnel resta limitato a:

```text
10.88.0.1/32
```

## Limite di rete

Linux Agent e auto-discovery non risolvono CGNAT. La connessione diretta da Internet continua a richiedere un endpoint pubblico raggiungibile; NAT discovery/traversal e relay restano nelle fasi future.

Vedi:

```text
docs/LINUX_AGENT.md
docs/BACKEND_DISCOVERY.md
```
