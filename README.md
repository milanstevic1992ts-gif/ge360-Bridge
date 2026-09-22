# GE360 Universal Bridge

Versione corrente: **v0.20 — Fase 18: NAT Discovery in verifica CI**.

La fonte di verità resta `docs/ROADMAP.md`.

## NAT Discovery

GE360 Bridge può ora osservare la rete Internet del server senza modificare NAT o firewall.

Comando:

```bash
ge360-bridge nat-discover
```

Il report include:

```text
IPv4 pubblico osservato via STUN
mapped UDP endpoint diagnostico
IPv6 globali
WAN IPv4 router via UPnP read-only
indizi CGNAT
mapping behavior NAT
filtering behavior quando verificabile via RFC 5780
```

Dashboard:

```text
/nat
/api/nat
```

La classificazione evita di inventare un NAT type quando i dati non bastano. Con una sola destinazione STUN il tipo resta `UNKNOWN`; mapping che cambia tra destinazioni viene indicato come `SYMMETRIC_LIKE_MAPPING`, non come prova assoluta di NAT simmetrico.

## Guardrail Fase 18

```text
wireguard_port_inferred=false
phase19_traversal_attempted=false
port_mapping_changed=false
```

La Fase 18 non esegue hole punching, non crea port forwarding e non modifica `PUBLIC_ENDPOINT`.

## Server STUN

Default:

```text
stun.cloudflare.com:3478
stun.cloudflare.com:53
```

Override CLI:

```bash
ge360-bridge nat-discover --server stun.example.net:3478
```

oppure in `/etc/ge360-bridge/bridge.env`:

```text
STUN_SERVERS=stun.example.net:3478,stun2.example.net:3478
```

## Update Engine e backup

Fase 17 Update Engine e Fase 16 Backup configurazione restano attivi e separati dalla diagnostica NAT.

Vedi:

```text
docs/NAT_DISCOVERY.md
docs/UPDATE_ENGINE.md
docs/BACKUP_CONFIG.md
```
