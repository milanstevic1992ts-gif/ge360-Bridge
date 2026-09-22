# Audit Log — Fase 8

La Fase 8 introduce uno storico persistente degli eventi tecnici del GE360 Universal Bridge.

## Privacy by design

L'audit **non salva payload applicativi**.

Lo schema contiene soltanto:

- timestamp;
- tipo evento;
- device_id;
- nome device;
- Resource;
- azione;
- risultato;
- IP VPN;
- latenza;
- errore tecnico.

Non esistono colonne `payload`, `body`, contenuto PDF, risposta API o dati delle applicazioni.

## Storage

Database:

```text
/etc/ge360-bridge/audit.db
```

Formato: SQLite con WAL e permessi `0600`.

## Eventi

Eventi ammessi:

```text
DEVICE_CONNECTED
DEVICE_DISCONNECTED
RESOURCE_ACCESS
RESOURCE_ONLINE
RESOURCE_OFFLINE
ACL_CHANGED
```

### Device connected/disconnected

Il daemon osserva l'handshake WireGuard.

Un peer è considerato connesso quando ha un handshake recente entro la stessa soglia usata dal Bridge. Vengono registrate solo le transizioni, non ogni polling.

### Resource online/offline

Il daemon usa il Health Engine e registra soltanto transizioni:

```text
non ONLINE -> ONLINE
ONLINE -> non ONLINE
```

Il dettaglio dello stato Health Engine viene salvato nel campo risultato/errore, non il body HTTP.

### Resource access

Ogni nuova connessione TCP a una Resource registra:

- device;
- Resource;
- ALLOW / DENY / ERROR;
- IP VPN;
- latenza di apertura backend;
- errore tecnico se presente.

Non vengono ispezionati né salvati i byte trasportati.

### ACL changed

Modifiche a override device, membership gruppo e permessi gruppo producono `ACL_CHANGED`.

## CLI

Ultimi eventi:

```bash
ge360-bridge audit-list
```

Filtri:

```bash
ge360-bridge audit-list --limit 50 --resource rilievi
ge360-bridge audit-list --device telefono-milan
ge360-bridge audit-list --event ACL_CHANGED
```

## Dashboard/API

La dashboard mostra gli ultimi eventi.

API autenticata:

```text
GET /api/audit
```

## Fuori scope

Grafici, aggregazioni temporali e retention metriche appartengono alla Fase 9.
