# GE360 Universal Bridge

Versione corrente: **v0.21 — Fase 19: NAT Traversal P2P in verifica CI**.

La fonte di verità resta `docs/ROADMAP.md`.

## NAT Traversal P2P

GE360 Bridge può tentare un handshake WireGuard diretto usando candidate exchange STUN.

Lato server:

```bash
sudo ge360-bridge p2p-status
```

Dashboard:

```text
/p2p
/api/p2p
```

Control API autenticata:

```text
POST /v3/traversal/prepare
POST /v3/traversal/status
```

Il control path riusa HTTPS pairing sulla porta 8790 e lo stesso certificate pinning del QR v2.

## Android

Il SDK aggiunge:

```kotlin
val plan = session.connectPreferP2P(provisioned)
```

Il client scopre il proprio candidato STUN usando una porta locale stabile, poi avvia WireGuard con la stessa `ListenPort`.

Se STUN/control falliscono prima del tentativo, il SDK usa automaticamente il direct endpoint originale.

Stato successivo:

```kotlin
val status = session.traversalStatus(provisioned, plan)
```

Fallback manuale dopo un tentativo fallito:

```kotlin
session.fallbackToDirect(provisioned)
```

## Sicurezza

```text
AllowedIPs = 10.88.0.1/32
session TTL = 90s
rate limit = 6 prepare/min/device
relay = false
endpoint peer = runtime only
```

Il Bridge non scrive il candidato in `devices.json` o `wg0.conf`.

Le sessioni redatte visibili a CLI/dashboard stanno soltanto in:

```text
/run/ge360-bridge/p2p-sessions.json
```

e non contengono token, PSK o private key.

## Limite CGNAT

STUN non fornisce signaling.

Se server e client non hanno alcun control path HTTPS/IPv6/direct raggiungibile, Fase 19 non può scambiare i candidati e non può avviare il hole-punch.

Il fallback relay appartiene alla **Fase 20** e non è stato introdotto.

## NAT Discovery, Update e Backup

Fase 18 NAT Discovery, Fase 17 Update Engine e Fase 16 Backup restano attive e separate.

Vedi:

```text
docs/P2P_TRAVERSAL.md
docs/NAT_DISCOVERY.md
docs/UPDATE_ENGINE.md
docs/BACKUP_CONFIG.md
```
