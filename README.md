# GE360 Universal Bridge

Versione corrente: **v0.18 — Fase 16 completata: Backup configurazione**. La Fase 17 — Update Engine è la prossima e non è stata avviata.

La fonte di verità resta `docs/ROADMAP.md`.

## Backup configurazione

GE360 Bridge conserva snapshot root-only della configurazione necessaria al disaster recovery.

Default:

```text
frequenza: 1 backup al giorno
retention: 10 copie
directory: /etc/ge360-bridge/backups
archivi: 0600
```

Comandi:

```bash
sudo ge360-bridge backup-create
sudo ge360-bridge backup-list
sudo ge360-bridge backup-verify <backup>
sudo ge360-bridge backup-restore <backup>
sudo ge360-bridge backup-restore <backup> --apply
```

Ogni archivio usa manifest + SHA-256 e viene validato prima del restore.

Sono inclusi registry/ACL, configurazione Bridge, identità server, certificati/token server e configurazione WireGuard. Sono esclusi audit, metriche, pairing temporanei e stato runtime self-healing.

Le private key client non vengono esportate. Il Pairing v2 non le conserva sul server e il backup blocca eventuali campi sospetti in `devices.json`.

Timer:

```text
ge360-bridge-backup.timer
ogni giorno alle 03:20
```

## Self-healing

Il self-healing v0.17 resta opt-in per singola Resource e mantiene il limite massimo 3 restart / 10 minuti.

## Linux Agent

Il Linux Agent resta read-only e separato dal backup locale del Bridge.

## Limite di rete

Backup e restore non modificano CGNAT, NAT traversal o connettività remota.

Vedi:

```text
docs/BACKUP_CONFIG.md
docs/SELF_HEALING.md
docs/LINUX_AGENT.md
docs/BACKEND_DISCOVERY.md
```
