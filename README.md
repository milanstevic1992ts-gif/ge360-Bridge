# GE360 Universal Bridge

Versione corrente: **v0.9 — Fase 7: Connection Doctor**.

La fonte di verità resta `docs/ROADMAP.md`.

## Connection Doctor

Il Doctor usa Health Engine, Diagnostica, WireGuard e ACL per classificare i problemi senza inventare cause.

Categorie:

```text
VPN_DOWN
BRIDGE_DOWN
DEVICE_NOT_AUTHORIZED
SERVICE_NOT_ALLOWED
BACKEND_DOWN
HTTP_ERROR
PDF_URL_INVALID
TIMEOUT
PORT_CONFLICT
ENDPOINT_INVALID
OK
```

## Rilievi

```bash
ge360-bridge doctor rilievi \
  --device telefono-milan \
  --api-path /healthz \
  --pdf-path /api/report/123.pdf
```

Il risultato include categoria primaria, finding secondari ed evidenze.

## Dashboard

```text
http://127.0.0.1:8789
```

Apri una Resource e usa Diagnostica. Inserendo anche il device, il Doctor può distinguere problemi VPN/ACL da problemi backend.

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

Vedi `docs/CONNECTION_DOCTOR.md`.
