# GE360 Universal Bridge

Versione corrente: **v0.4 — Fase 2 completata: Gruppi e ACL semplificate**. La Fase 3 è la prossima e non è ancora stata avviata.

La fonte di verità è `docs/ROADMAP.md`. Non vengono anticipate funzioni delle fasi successive.

## Fase 2

I device possono essere organizzati in gruppi persistenti. I gruppi autorizzano i servizi già registrati e le ACL dirette restano disponibili come override.

Precedenza:

```text
deny diretto
  ↓
allow diretto
  ↓
permesso ereditato dal gruppo
  ↓
nessun accesso
```

Le membership usano il `device_id`, quindi rinominare un dispositivo non rompe il gruppo.

## Esempio

```bash
sudo ge360-bridge group-create amministratori --description "Accesso completo"
sudo ge360-bridge group-device-add amministratori telefono-milan
sudo ge360-bridge group-service-grant amministratori rilievi
```

Override singolo device:

```bash
sudo ge360-bridge service-grant rilievi telefono-milan
sudo ge360-bridge service-revoke rilievi telefono-milan
sudo ge360-bridge service-inherit rilievi telefono-milan
```

`service-revoke` in Fase 2 è un **deny diretto**. `service-inherit` rimuove l'override e torna alla policy del gruppo.

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

L'installer crea `groups.json` e migra i servizi v0.3 aggiungendo `denied_devices`, senza cancellare le ACL dirette esistenti.

## Dashboard

- locale: `http://127.0.0.1:8789`
- via Bridge: `http://10.88.0.1:8789`

La dashboard permette di creare/disabilitare gruppi, assegnare device, assegnare servizi e impostare override allow/deny/inherit.

## Pairing

Resta **pairing v1**. Il pairing sicuro monouso v2 appartiene esclusivamente alla Fase 3.

## Diagnostica base

```bash
ge360-bridge list
ge360-bridge status
sudo wg show
curl http://127.0.0.1:8789/healthz
```
