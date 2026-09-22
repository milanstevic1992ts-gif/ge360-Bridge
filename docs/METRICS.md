# Metriche e grafici — Fase 9

La Fase 9 aggiunge serie temporali leggere al GE360 Universal Bridge.

## Storage

Database:

```text
/etc/ge360-bridge/metrics.db
```

SQLite WAL, permessi `0600`.

Campionamento automatico: ogni 60 secondi.

Retention: 35 giorni, sufficiente alla finestra massima di 30 giorni.

## Metriche Device

Per ogni device:

- RX WireGuard;
- TX WireGuard;
- età handshake;
- stato connesso.

RX/TX nel database sono contatori WireGuard cumulativi. Le serie mostrate all'utente calcolano delta positivi tra campioni.

## Metriche Resource

Per ogni Resource:

- latenza Health Engine;
- stato;
- errori;
- rapporto ONLINE.

## Metriche Bridge

- uptime sistema;
- nuove connessioni Resource;
- nuovi errori tecnici.

Connessioni/errori sono derivati dai contatori Audit Log e trasformati in delta per finestra.

## Finestre

```text
1h
24h
7d
30d
```

Per evitare migliaia di punti, le serie vengono aggregate automaticamente:

- 1h → bucket 1 minuto;
- 24h → bucket 5 minuti;
- 7d → bucket 30 minuti;
- 30d → bucket 2 ore.

## CLI

```bash
ge360-bridge metrics --window 1h
ge360-bridge metrics --window 24h --resource rilievi
ge360-bridge metrics --window 7d --device telefono-milan
```

Forzare un campione:

```bash
sudo ge360-bridge metrics-sample
```

## Dashboard

Pagina:

```text
/metrics
```

Grafici SVG senza dipendenze JavaScript esterne:

- RX;
- TX;
- handshake;
- latenza Resource;
- errori;
- connessioni;
- uptime corrente.

API autenticata:

```text
GET /api/metrics?window=24h
```

## Fuori scope

La Fase 9 non introduce il launcher delle applicazioni. Quello appartiene alla Fase 10.
