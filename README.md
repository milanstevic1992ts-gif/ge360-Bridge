# GE360 Universal Bridge

Versione corrente: **v0.19 — Fase 17 completata: Update Engine**. La Fase 18 — NAT Discovery è la prossima e non è stata avviata.

La fonte di verità resta `docs/ROADMAP.md`.

## Update Engine

GE360 Bridge può ora applicare pacchetti software controllati con:

```text
HTTPS download
SHA-256 obbligatorio
preflight
backup configurazione
snapshot software rollback
installazione atomica
health check
rollback automatico
```

Comando completo:

```bash
sudo ge360-bridge update-run \
  https://server.example/ge360-update-vNEXT.tar.gz \
  --sha256 <SHA256>
```

Verifica senza installare:

```bash
sudo ge360-bridge update-verify /percorso/update.tar.gz
```

Stato:

```bash
sudo ge360-bridge update-status
```

L'Update Engine non esegue `install.sh` scaricati e non permette al manifest di scegliere percorsi arbitrari sul server.

Se l'health check post-update fallisce, vengono ripristinati software precedente e backup configurazione pre-update, poi viene verificata nuovamente la salute del Bridge.

## Creazione pacchetto

```bash
python scripts/build-update-package.py \
  --source . \
  --output /tmp/ge360-update.tar.gz
```

Il builder restituisce anche lo SHA-256 da distribuire insieme al pacchetto.

## Backup configurazione

La Fase 16 resta attiva con un backup al giorno e retention 10 copie.

## Self-healing

Il self-healing resta opt-in per Resource con limite 3 restart / 10 minuti.

## Nessun auto-update

La Fase 17 non controlla né installa automaticamente nuove release. URL e SHA-256 devono essere forniti esplicitamente.

Vedi:

```text
docs/UPDATE_ENGINE.md
docs/BACKUP_CONFIG.md
docs/SELF_HEALING.md
```
