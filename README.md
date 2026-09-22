# GE360 Universal Bridge

Versione corrente: **v0.6 — Fase 4: Resource Registry**.

La fonte di verità resta `docs/ROADMAP.md`.

## Resource Registry

Da v0.6 il registro autoritativo dei backend è:

```text
/etc/ge360-bridge/resources.json
```

Ogni Resource descrive nome, icona, descrizione, protocollo, bridge port, target locale, health URL, timeout e ACL.

Il vecchio `services.json` resta come mirror di compatibilità e i comandi `service-*` continuano a funzionare.

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

L'installer migra automaticamente i servizi v0.5 senza perdere porte, target, ACL o gruppi.

## Esempio Rilievi

```bash
sudo ge360-bridge resource-add rilievi \
  --port 9888 \
  --target-host 127.0.0.1 \
  --target-port 9888 \
  --protocol http \
  --icon ruler \
  --description "GE360 Rilievi" \
  --health-url /healthz \
  --timeout 2
```

Se `rilievi` esiste già dopo la migrazione:

```bash
sudo ge360-bridge resource-update rilievi \
  --protocol http \
  --icon ruler \
  --description "GE360 Rilievi" \
  --health-url /healthz
```

## Importante

La Fase 4 **non implementa ancora il Health Engine**. Health URL e timeout vengono soltanto registrati e validati. Il proxy rimane TCP e stabile come nelle fasi precedenti.

Il Health Engine vero è la Fase 5.

Vedi `docs/RESOURCE_REGISTRY.md`.
