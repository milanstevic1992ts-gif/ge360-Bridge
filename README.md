# GE360 Universal Bridge

Versione corrente: **v0.7 — Fase 5: Health Engine**.

La fonte di verità resta `docs/ROADMAP.md`.

## Health Engine

Il Bridge controlla ogni Resource con lo stesso motore usato da dashboard, CLI e `/v1/status`.

Stati:

```text
ONLINE
DEGRADED
OFFLINE
TIMEOUT
UNAUTHORIZED
BAD_RESPONSE
```

Controlli disponibili in Fase 5:

- TCP;
- latenza;
- HTTP/HTTPS;
- status code;
- validazione JSON;
- TLS;
- timeout per Resource.

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

## Rilievi

Assicurati che la Resource abbia il suo health endpoint:

```bash
sudo ge360-bridge resource-update rilievi \
  --protocol http \
  --health-url /healthz \
  --timeout 2
```

Poi:

```bash
ge360-bridge health-check rilievi --no-cache
```

## Dashboard

```text
http://127.0.0.1:8789
```

Mostra per ogni Resource:

- stato;
- latenza;
- TCP;
- HTTP status;
- JSON;
- TLS;
- eventuale errore.

API health autenticata:

```text
GET /api/health
```

## Importante

La Fase 5 non introduce diagnostica avanzata. Ping, DNS, traceroute, test PDF e Connection Doctor appartengono alle Fasi 6 e 7.

Vedi `docs/HEALTH_ENGINE.md`.
