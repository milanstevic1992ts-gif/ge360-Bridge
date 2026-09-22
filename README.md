# GE360 Universal Bridge

Versione corrente: **v0.17 — Fase 15 completata: Self-healing**. La Fase 16 — Backup configurazione è la prossima e non è stata avviata.

La fonte di verità resta `docs/ROADMAP.md`.

## Self-healing controllato

Il self-healing è disattivato per default e deve essere abilitato per singola Resource.

Configurazione:

```bash
sudo ge360-bridge resource-update rilievi \
  --systemd-unit ge360-rilievi.service \
  --self-heal true
```

Controllo senza eseguire restart:

```bash
sudo ge360-bridge self-heal-run --dry-run
```

Stato:

```bash
ge360-bridge self-heal-status
```

Regole principali:

```text
trigger: OFFLINE / TIMEOUT
limite: 3 restart / 10 minuti per Resource
post-restart: health-check fino a ONLINE
```

Il motore usa un lock esclusivo e uno stato persistente per impedire loop anche tra esecuzioni concorrenti.

Timer:

```text
ge360-bridge-self-heal.timer
```

## Linux Agent

Il Linux Agent della Fase 14 resta read-only. Il self-healing della Fase 15 opera soltanto sul server Bridge locale e non riavvia host remoti.

## Backend auto discovery

I backend GE360 continuano a dichiararsi tramite `/.well-known/ge360`; il discovery resta confinato al loopback.

## Limite di rete

Il self-healing non modifica CGNAT, NAT traversal o connettività remota.

Vedi:

```text
docs/SELF_HEALING.md
docs/LINUX_AGENT.md
docs/BACKEND_DISCOVERY.md
```
