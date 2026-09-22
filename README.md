# GE360 Universal Bridge

Ponte privato e riutilizzabile per collegare i frontend GE360 ai backend Linux anche fuori dalla LAN, senza esporre direttamente le API applicative.

## Stato progetto

Versione corrente: **v0.3 — Fase 1: Device Registry**.

La roadmap ufficiale è in `docs/ROADMAP.md`. Le fasi sono implementate in ordine; funzioni di fasi future non vengono anticipate.

## Device Registry v0.3

Ogni peer ha ora un'identità stabile separata dal nome:

- `device_id`;
- nome modificabile;
- tipo dispositivo;
- proprietario;
- IP VPN;
- data creazione;
- scadenza opzionale;
- note;
- tag;
- enabled/disabled.

L'aggiornamento da v0.2 migra automaticamente `devices.json` preservando chiavi WireGuard, VPN IP e ACL.

La scadenza non elimina il dispositivo: lo esclude dal runtime e un timer giornaliero sincronizza WireGuard.

## Dashboard

- server locale: `http://127.0.0.1:8789`
- tramite WireGuard: `http://10.88.0.1:8789`
- health: `http://127.0.0.1:8789/healthz`
- stato JSON autenticato: `/api/status`

Token:

```bash
sudo cat /etc/ge360-bridge/dashboard.token
```

## Installazione / aggiornamento Debian 13

```bash
git clone https://github.com/milanstevic1992ts-gif/ge360-Bridge.git
cd ge360-Bridge
sudo ./install.sh
```

Repo già installata:

```bash
cd ge360-Bridge
git pull
sudo ./install.sh
```

## Device CLI

Creazione:

```bash
sudo ge360-bridge device-add telefono-milan \
  --type android \
  --owner Milan \
  --tags personale,android
```

Gestione:

```bash
ge360-bridge device-show telefono-milan
sudo ge360-bridge device-rename telefono-milan telefono-principale
sudo ge360-bridge device-update telefono-principale --expires 2026-12-31
sudo ge360-bridge device-disable telefono-principale
sudo ge360-bridge device-enable telefono-principale
```

`device-revoke` resta come alias compatibile di disable.

## Pairing

Il pairing resta **v1** in questa fase. Il pairing monouso con chiave privata generata sul client appartiene alla Fase 3 e non è stato anticipato.

```bash
sudo ge360-bridge device-add telefono-milan --type android
```

## Collegare GE360 Rilievi

Backend preferibilmente su:

```text
127.0.0.1:9888
```

Registrazione:

```bash
sudo ge360-bridge service-add rilievi \
  --port 9888 \
  --target-host 127.0.0.1 \
  --target-port 9888 \
  --allow telefono-milan
```

Frontend: `http://10.88.0.1:9888`

Health Bridge: `http://10.88.0.1:8788/v1/status`

## Diagnostica base

```bash
ge360-bridge status
ge360-bridge list
sudo wg show
systemctl status wg-quick@wg0 ge360-bridge ge360-bridge-dashboard ge360-bridge-firewall ge360-bridge-expiry.timer
curl http://127.0.0.1:8789/healthz
```

## Sicurezza

- chiave WireGuard e PSK distinti per device;
- backend locali soltanto su loopback;
- ACL per dispositivo;
- device scaduti/disabilitati esclusi dall'accesso runtime;
- traffico da `wg0` non inoltrato alla LAN;
- dashboard limitata a localhost/IP WireGuard;
- file sensibili `0600`;
- pairing QR temporaneo protetto.

## CGNAT

Senza IPv4 pubblica/port-forward oppure IPv6 globale raggiungibile, una connessione diretta da Internet non può funzionare. NAT discovery e traversal appartengono alle Fasi 18-19 e non fanno parte della Fase 1.
