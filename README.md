# GE360 Universal Bridge

Versione corrente: **v0.11 — Fase 9 completata: Metriche e grafici**. La Fase 10 è la prossima e non è ancora stata avviata.

La fonte di verità resta `docs/ROADMAP.md`.

## Metriche

Campionamento ogni 60 secondi con retention 35 giorni.

```text
RX / TX
handshake
latenza
uptime
errori
connessioni
```

Finestre:

```text
1h · 24h · 7d · 30d
```

## CLI

```bash
ge360-bridge metrics --window 24h
ge360-bridge metrics --window 7d --resource rilievi
```

## Dashboard

```text
http://127.0.0.1:8789/metrics
```

API:

```text
GET /api/metrics?window=24h
```

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

Vedi `docs/METRICS.md`.
