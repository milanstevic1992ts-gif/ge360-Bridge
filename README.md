# GE360 Universal Bridge

Versione corrente: **v0.5 — Fase 3: Pairing sicuro v2**.

La fonte di verità resta `docs/ROADMAP.md`.

## Cosa cambia in v0.5

Per i nuovi device il Bridge non genera più la private key WireGuard.

```text
Dashboard / CLI
      ↓
token monouso + QR v2
      ↓
client genera private key
      ↓
HTTPS :8790
      ↓
invia solo public key
      ↓
Bridge crea il device
```

Il token viene salvato solo come HMAC/hash e diventa inutilizzabile dopo il primo enrollment valido.

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

L'installer preserva device, gruppi, ACL, server key, dashboard token e genera una sola volta:

- `/etc/ge360-bridge/enrollment.key`
- `/etc/ge360-bridge/pairing-tls.key`
- `/etc/ge360-bridge/pairing-tls.crt`

Nuovo servizio:

```bash
systemctl status ge360-bridge-enrollment --no-pager
curl -k https://127.0.0.1:8790/healthz
```

## Creare un pairing v2

```bash
sudo ge360-bridge device-add telefono-milan \
  --type android \
  --owner Milan \
  --groups amministratori \
  --ttl 600
```

Oppure:

```bash
sudo ge360-bridge pairing-create telefono-milan --ttl 600
ge360-bridge pairing-list
```

Il QR non contiene la private key del client.

## Porte

- UDP 51820: WireGuard
- TCP 8790: HTTPS enrollment v2
- TCP 8788: health interno via WireGuard
- TCP 8789: dashboard locale/WireGuard

La 8790 è riservata al pairing e non può essere usata come porta applicativa.

## Dashboard

- locale: `http://127.0.0.1:8789`
- via Bridge: `http://10.88.0.1:8789`

La dashboard genera il QR v2 monouso e permette di scegliere TTL e gruppi iniziali.

## Sicurezza pairing

- token ad alta entropia;
- token in chiaro mai persistito;
- certificate pinning tramite fingerprint SHA-256 nel QR;
- public key client validata;
- private key generata e conservata solo sul client;
- replay rifiutato;
- token scaduto rifiutato;
- un solo invito pending per nome device;
- endpoint enrollment separato dalla dashboard.

Vedi `docs/PAIRING_PROTOCOL.md`.

## Nota CGNAT

Il pairing remoto diretto richiede che TCP 8790 sia raggiungibile. L'installer prova UPnP quando disponibile. In presenza di CGNAT senza IPv6 globale il limite resta invariato; NAT traversal non viene anticipato prima delle Fasi 18-19.
