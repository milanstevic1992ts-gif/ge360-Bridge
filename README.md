# GE360 Universal Bridge

Versione corrente: **v0.12 — Fase 10: Resource Launcher**.

La fonte di verità resta `docs/ROADMAP.md`.

## GE360 HUB

Da un device collegato al Bridge:

```text
http://10.88.0.1:8788/hub
```

Il device vede solamente le Resource autorizzate dalle proprie ACL e gruppi.

API:

```text
GET http://10.88.0.1:8788/v1/resources
```

Le Resource HTTP/HTTPS hanno il pulsante **Apri**; quelle TCP mostrano l'endpoint.

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

Vedi `docs/RESOURCE_LAUNCHER.md`.
