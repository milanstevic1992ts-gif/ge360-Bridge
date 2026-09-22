# GE360 Universal Bridge

Versione corrente: **v0.23 — Fase 21 completata: Multi-server GE360**.

La fonte di verità resta `docs/ROADMAP.md`.

## Ordine connessione

```text
Direct WireGuard
  ↓ fallisce
NAT Traversal P2P
  ↓ fallisce / non disponibile
Relay self-hosted opzionale
```

Il relay non diventa il percorso predefinito.

## Relay pubblico

Su una macchina Linux pubblica:

```bash
sudo ./install-relay.sh --public-host relay.example.com
```

Servizi/rete default:

```text
HTTPS control: TCP 8792
UDP sessioni: 40000-40199
service: ge360-relay.service
```

L'installer **non apre automaticamente firewall**.

Il relay inoltra datagrammi WireGuard cifrati e non possiede private key, PSK, Resource o payload applicativi in chiaro.

## Bridge

Configurazione:

```text
RELAY_ENABLED=true
RELAY_URL=https://relay.example.com:8792
RELAY_CERT_SHA256=<fingerprint>
```

Il token admin del relay va in:

```text
/etc/ge360-bridge/relay.token
```

Poi:

```bash
sudo chmod 600 /etc/ge360-bridge/relay.token
sudo systemctl enable --now ge360-bridge-relay-monitor.service
```

Il monitor è installato dagli update ma resta disabilitato per default.

Stato:

```bash
sudo ge360-bridge relay-status
sudo ge360-bridge relay-status --remote
```

## Android

Fallback esplicito:

```kotlin
session.connectViaRelayAfterFailure(
    provisioned,
    RelayFallbackReason.P2P_FAILED
)
```

Dopo riavvio, usando la configurazione già cifrata con Android Keystore:

```kotlin
runtime.connectStoredViaRelayAfterFailure(
    RelayFallbackReason.CONTROL_UNREACHABLE
)
```

Motivi ammessi:

```text
DIRECT_FAILED
P2P_FAILED
CONTROL_UNREACHABLE
```

P2P e relay usano configurazioni transient, quindi l'endpoint direct originale resta persistito.

`AllowedIPs` rimane:

```text
10.88.0.1/32
```

## CGNAT

Android contatta il relay pubblico direttamente.

Il Bridge interroga il relay tramite HTTPS **outbound**.

Quindi il fallback relay non richiede un control endpoint Internet inbound sul Bridge e può essere usato quando il Bridge è dietro CGNAT.

## Dashboard

```text
/relay
/api/relay
```

Il link relay viene mostrato nella dashboard soltanto dopo un P2P FAILED/ERROR o quando esiste una sessione relay attiva.

## Single Bridge

Fase 20 supporta un relay per un singolo Bridge.

Il relay non aggrega server o Resource.

Il control plane multi-server appartiene alla **Fase 21** e non è stato avviato.

Vedi:

```text
docs/RELAY.md
docs/P2P_TRAVERSAL.md
docs/NAT_DISCOVERY.md
docs/UPDATE_ENGINE.md
docs/BACKUP_CONFIG.md
```


## Multi-server GE360

Fase 21 aggiunge un control plane read-only:

```bash
sudo ge360-bridge server-export --public-host server2.example.com
sudo ge360-bridge server-add server2 --server-id srv_xxx --url https://server2.example.com:8793 --pin <SHA256> --token <TOKEN>
ge360-bridge server-status
ge360-bridge server-catalog
```

Catalogo device-facing:

```text
http://10.88.0.1:8788/v1/catalog
```

Le Resource sono identificate come `server_id:resource_name`.

Il control plane non esegue mutazioni remote e non proxy-a il traffico applicativo.

Vedi `docs/MULTI_SERVER.md`.
