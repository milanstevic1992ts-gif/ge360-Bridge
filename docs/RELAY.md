# Relay opzionale self-hosted — Fase 20

GE360 Bridge v0.22 aggiunge un fallback relay WireGuard self-hosted, opzionale e separato dal control plane GE360.

## Principio

Ordine previsto:

    direct WireGuard
        ↓ fallisce
    NAT Traversal P2P Fase 19
        ↓ fallisce / non è disponibile
    Relay Fase 20

Il relay non deve diventare il percorso predefinito.

## Cosa inoltra

Il relay inoltra datagrammi UDP WireGuard già cifrati.

Non possiede:

- private key WireGuard;
- PSK;
- Resource Registry;
- ACL GE360;
- database audit/metriche;
- payload applicativo in chiaro.

Stato relay esplicito:

    payload_decryption=false
    resource_catalog=false
    multi_server_control_plane=false

## Architettura

Sono presenti tre componenti.

### Nodo relay pubblico

Installato con:

    sudo ./install-relay.sh --public-host relay.example.com

Servizio:

    ge360-relay.service

Control HTTPS:

    TCP 8792

Pool UDP sessioni:

    UDP 40000-40199

L'installer NON modifica automaticamente firewall/router/VPS.

L'operatore deve consentire esplicitamente:

    TCP 8792
    UDP 40000-40199

### Bridge GE360

Il Bridge mantiene una connessione di controllo outbound verso il relay.

Servizio opzionale:

    ge360-bridge-relay-monitor.service

Il servizio viene installato dalla normale installazione GE360 ma NON viene abilitato automaticamente.

### Android

Android contatta direttamente il control endpoint pubblico del relay usando:

- device_id;
- device_token;
- certificate pinning del relay.

Il token amministrativo del relay non viene mai inviato all'APK.

## Installazione relay

Sul nodo Linux pubblico:

    git clone <repository GE360 Bridge>
    cd ge360-Bridge
    sudo ./install-relay.sh --public-host relay.example.com

Sono generati:

    /etc/ge360-relay/admin.token
    /etc/ge360-relay/tls.key
    /etc/ge360-relay/tls.crt
    /etc/ge360-relay/relay.env
    /etc/ge360-relay/devices.json

Permessi sensibili:

    directory 0700
    admin.token 0600
    tls.key 0600
    relay.env 0600
    devices.json 0600

Il certificato self-signed viene pin-nato, quindi non richiede una CA pubblica.

Fase 20 supporta DNS o IPv4 pubblico per l'endpoint UDP relay.

IPv6 diretto rimane nel percorso Fase 18/19.

## Configurazione Bridge

L'installer relay stampa:

    RELAY_ENABLED=true
    RELAY_URL=https://relay.example.com:8792
    RELAY_CERT_SHA256=<fingerprint>

Questi valori vanno in:

    /etc/ge360-bridge/bridge.env

Il token amministrativo stampato dal relay va copiato soltanto in:

    /etc/ge360-bridge/relay.token

Poi:

    sudo chmod 600 /etc/ge360-bridge/relay.token
    sudo systemctl enable --now ge360-bridge-relay-monitor.service

Stato:

    sudo ge360-bridge relay-status
    sudo ge360-bridge relay-status --remote

Sincronizzazione manuale:

    sudo ge360-bridge relay-sync

Ciclo singolo diagnostico:

    sudo ge360-bridge relay-run-once

## Registry relay

Il Bridge NON sincronizza i device token grezzi.

Invia soltanto:

    device_id
    SHA-256(device_token)
    enabled

Il relay usa il digest per autenticare una richiesta device.

Un device revocato/disabilitato viene sincronizzato come non attivo o rimosso al successivo sync completo.

Sync periodico monitor:

    ogni 60 secondi

Dopo un nuovo enrollment, il Bridge prova anche un sync immediato.

## Control API relay

Health pubblico:

    GET /healthz

Admin, Bearer token:

    GET  /v1/admin/status
    POST /v1/admin/sync
    POST /v1/admin/requests
    POST /v1/admin/activate

Device:

    POST /v1/device/request
    POST /v1/device/status

I motivi fallback device sono limitati a:

    direct_failed
    p2p_failed
    control_unreachable

Non esiste un motivo "always".

## TLS

Il relay genera un certificato self-signed.

Il Bridge e Android verificano SHA-256 del certificato.

Bridge:

    RELAY_CERT_SHA256

Android riceve dal pairing soltanto:

    relay.enabled
    relay.url
    relay.tls_cert_sha256

Il token admin non appare nel pairing.

## Sessione UDP

Ogni sessione riceve due porte UDP casuali e distinte:

    relay bridge-facing port
    relay client-facing port

Il Bridge manda WireGuard soltanto alla porta bridge-facing.

Android manda WireGuard soltanto alla porta client-facing.

Questo evita di dover dedurre il ruolo dal primo pacchetto.

Il relay registra l'endpoint sorgente visto su ciascuna porta e inoltra il datagramma attraverso l'altra socket.

Il contenuto non viene analizzato o modificato.

## Source-IP guard

Il client-facing side viene limitato, quando possibile, all'IPv4 osservato sulla richiesta HTTPS device.

Il bridge-facing side viene limitato, quando possibile, all'IPv4 osservato sulla richiesta HTTPS admin di activate.

Questa è una protezione aggiuntiva al fatto che le due porte sessione sono casuali e separate.

## Vita sessione

Sessione WAITING_BRIDGE senza attivazione:

    massimo 120 secondi

Sessione ACTIVE:

    idle timeout 90 secondi

Lifetime massimo:

    24 ore

WireGuard PersistentKeepalive=25 mantiene normalmente viva una sessione attiva.

Capacità default:

    50 sessioni

## Flusso fallback

1. direct/P2P fallisce;
2. Android chiama /v1/device/request sul relay;
3. relay crea due porte UDP;
4. relay espone la richiesta al Bridge;
5. ge360-bridge-relay-monitor la legge via HTTPS outbound;
6. Bridge esegue soltanto runtime:

       wg set wg0 peer <peer> endpoint <relay-bridge-port> persistent-keepalive 25

7. Bridge genera traffico WireGuard minimo verso il device;
8. Bridge chiama /v1/admin/activate;
9. Android vede stato ACTIVE;
10. Android avvia WireGuard verso relay client-facing endpoint;
11. il relay inoltra soltanto pacchetti WireGuard cifrati.

## CGNAT

Questo meccanismo non richiede un control endpoint inbound sul Bridge.

Il Bridge deve poter effettuare HTTPS outbound verso il relay.

Android deve poter raggiungere il relay pubblico.

Per questo il relay può funzionare anche quando il Bridge è dietro CGNAT e la Fase 19 non riesce a iniziare il candidate exchange diretto.

## Android SDK

Metodo esplicito:

    session.connectViaRelayAfterFailure(
        provisioned,
        RelayFallbackReason.P2P_FAILED
    )

Per configurazioni già salvate:

    runtime.connectStoredViaRelayAfterFailure(
        RelayFallbackReason.CONTROL_UNREACHABLE
    )

Motivi ammessi:

    DIRECT_FAILED
    P2P_FAILED
    CONTROL_UNREACHABLE

Il fallback relay usa startTransient.

Quindi l'endpoint relay non sostituisce nello store cifrato l'endpoint direct originale.

Anche P2P Fase 19 è stato portato a startTransient per preservare la configurazione direct.

## Store Android

Nel blob già cifrato con Android Keystore vengono salvati anche:

- device_id;
- device_token;
- relay URL;
- relay certificate pin.

WireGuardConfig.toString continua a redigere:

- private key;
- PSK;
- device token.

## Dashboard

Endpoint:

    /relay
    /api/relay

Il link Relay non appare normalmente nella dashboard.

Diventa visibile soltanto quando:

- una sessione P2P recente è FAILED/ERROR; oppure
- esiste una sessione relay runtime.

Questo mantiene il relay visivamente come fallback.

## Audit

Eventi Bridge:

    RELAY_ACTIVE
    RELAY_FAILED

Non vengono salvati token o pacchetti inoltrati.

## Backup

Se esiste:

    /etc/ge360-bridge/relay.token

la Fase 16 lo include come server secret opzionale.

I backup storici senza relay.token restano validi.

## Update Engine

Il pacchetto Bridge include i moduli Python relay e la unit:

    ge360-bridge-relay-monitor.service

Il nodo relay pubblico resta un componente separato installato con install-relay.sh.

La Fase 20 non introduce un sistema di update remoto dei relay.

## Limite single-Bridge

Il registry del relay Fase 20 appartiene a un singolo Bridge GE360.

Non aggrega più server e non espone Resource di server diversi.

Questa separazione è intenzionale.

La gestione multi-server appartiene alla Fase 21.

## Fuori scope

Fase 20 NON implementa:

- multi-server control plane;
- catalogo Resource sul relay;
- routing applicativo HTTP/TCP attraverso un control plane;
- decrypt WireGuard;
- TURN di terze parti;
- relay cloud proprietario;
- auto-provisioning VPS;
- apertura automatica firewall;
- modifica persistente di wg0.conf;
- sostituzione del direct/P2P come percorso primario.
