# GE360 Universal Bridge

Versione corrente: **v0.10 — Fase 8: Audit Log**.

La fonte di verità resta `docs/ROADMAP.md`.

## Audit Log

GE360 Bridge registra eventi tecnici persistenti senza salvare i contenuti delle applicazioni.

Eventi:

```text
DEVICE_CONNECTED
DEVICE_DISCONNECTED
RESOURCE_ACCESS
RESOURCE_ONLINE
RESOURCE_OFFLINE
ACL_CHANGED
```

Database:

```text
/etc/ge360-bridge/audit.db
```

## CLI

```bash
ge360-bridge audit-list
ge360-bridge audit-list --resource rilievi --limit 50
ge360-bridge audit-list --device telefono-milan
```

## Dashboard

```text
http://127.0.0.1:8789
```

Mostra gli ultimi eventi e rende disponibile l'API autenticata:

```text
GET /api/audit
```

## Privacy

L'audit registra metadati tecnici, non payload, body HTTP, PDF o dati interni delle app.

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

Vedi `docs/AUDIT_LOG.md`.
