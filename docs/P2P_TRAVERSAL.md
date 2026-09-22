# NAT Traversal P2P — Fase 19

GE360 Bridge v0.21 aggiunge un tentativo P2P WireGuard diretto che riusa STUN, device registry e pairing HTTPS esistenti.

## Obiettivo

Provare a stabilire un handshake WireGuard diretto quando client e server sono dietro NAT compatibili, senza introdurre relay.

Il meccanismo usa:

- candidato UDP client osservato via STUN;
- una porta locale client stabile;
- la stessa porta come WireGuard ListenPort Android;
- candidate server da PUBLIC_ENDPOINT configurato e/o IPv6 globale;
- control path HTTPS già pin-nato del pairing;
- autenticazione device_id + device_token;
- aggiornamento endpoint peer WireGuard soltanto runtime;
- traffico minimo WireGuard per provocare il handshake;
- verifica latest-handshakes;
- fallback al direct endpoint noto lato Android quando la preparazione P2P non può partire.

## Non è un relay

Campi stato:

    relay_available=false
    relay_used=false
    phase20_started=false

Nessun pacchetto applicativo viene inoltrato da un terzo server.

## Control path

Il coordinamento riusa la porta HTTPS pairing:

    8790/tcp

Endpoint:

    POST /v3/traversal/prepare
    POST /v3/traversal/status

TLS usa lo stesso certificato self-signed già pin-nato nel QR pairing v2.

La porta 8790 non viene aggiunta alla lista Resource e non viene aperta da nuove regole nftables GE360.

## Autenticazione

Ogni richiesta traversal richiede:

    device_id
    device_token

Il token viene confrontato in constant-time con il Device Registry.

Il device deve inoltre essere attivo e non scaduto.

I token non vengono scritti nelle sessioni P2P, nel mirror runtime o nell'audit.

## Sessioni

TTL:

    90 secondi

Rate limit:

    6 prepare / minuto / device

ID:

    p2p_<random>

Le sessioni complete restano in memoria del processo HTTPS.

Una copia redatta viene scritta in:

    /run/ge360-bridge/p2p-sessions.json

Permessi:

    directory 0700
    file 0600

Il mirror runtime non contiene:

- device_token;
- peer WireGuard public key;
- PSK;
- private key.

Il file è runtime e sparisce al reboot.

## Candidato client

Android prova porte locali:

    51821..51830

Su una porta disponibile:

1. apre una DatagramSocket UDP;
2. esegue STUN Binding Request;
3. legge XOR-MAPPED-ADDRESS;
4. chiude la socket;
5. pubblica mapped IP/port al Bridge;
6. avvia immediatamente WireGuard con la stessa ListenPort locale.

Il candidato STUN deve essere un IP globale.

Indirizzi privati, loopback, link-local e RFC6598 non vengono accettati come peer candidate Internet.

## Candidati server

Ordine:

1. PUBLIC_ENDPOINT configurato;
2. IPv6 globale locale.

Un PUBLIC_ENDPOINT lasciato a CHANGE_ME non viene usato.

Il motore non assume che la mapped port della socket diagnostica della Fase 18 sia la porta WireGuard.

## Tentativo server

Dopo prepare il Bridge attende circa 350 ms per dare al client il tempo di chiudere STUN e avviare WireGuard.

Poi, soltanto runtime:

    wg set wg0 peer <public-key> endpoint <client-candidate> persistent-keepalive 5

Il Bridge invia traffico minimo verso il VPN IP del device per provocare il handshake.

Tentativi:

    5

Intervallo:

    0.8 s

Successo:

    nuovo latest-handshake WireGuard osservato

Dopo successo:

    persistent-keepalive 25

## Fallimento

Se esisteva un endpoint peer runtime precedente:

- viene ripristinato;
- viene ripristinato anche il persistent keepalive precedente.

Se il peer non aveva endpoint precedente, il candidato resta soltanto nel runtime WireGuard con keepalive 0.

Questo evita un reset globale di wg0 e degli altri peer.

WireGuard può comunque correggere l'endpoint automaticamente quando riceve un pacchetto autenticato valido grazie al roaming nativo.

## Android SDK

Nuovo metodo:

    session.connectPreferP2P(provisioned)

Comportamento:

- scopre candidato STUN;
- chiama prepare via HTTPS pin-nato;
- riceve recommended_endpoint;
- crea una copia WireGuardConfig con endpoint P2P e ListenPort stabile;
- avvia il tunnel.

Se STUN o prepare falliscono prima del tentativo:

    connectPreferP2P() -> null

e il SDK avvia automaticamente il direct WireGuardConfig originale.

Per interrogare il tentativo:

    session.traversalStatus(provisioned, plan)

Stati server:

    PREPARED
    PUNCHING
    SUCCEEDED
    FAILED
    ERROR

Se il tentativo è FAILED/ERROR:

    session.fallbackToDirect(provisioned)

riusa la configurazione direct originaria.

## AllowedIPs

Il traversal non cambia:

    AllowedIPs = 10.88.0.1/32

Non viene instradato traffico Internet generale attraverso il tunnel.

## Audit

Nuovi eventi:

    P2P_PREPARED
    P2P_SUCCEEDED
    P2P_FAILED

L'audit conserva solo metadati tecnici e IP candidato, senza token o payload applicativi.

## Dashboard e CLI

Dashboard autenticata:

    /p2p
    /api/p2p

CLI:

    sudo ge360-bridge p2p-status

Mostrano:

- traversal enabled/disabled;
- candidate server;
- sessioni runtime redatte;
- tentativi;
- stato handshake;
- limitazioni;
- relay non disponibile.

## Configurazione

bridge.env:

    TRAVERSAL_ENABLED=true

Per disabilitare:

    TRAVERSAL_ENABLED=false

## Limite fondamentale: cold start sotto CGNAT

STUN scopre endpoint, ma non fornisce un canale di signaling.

Per avviare Fase 19 deve esistere almeno un control path raggiungibile per:

- autenticare il device;
- pubblicare il candidato client;
- ricevere il candidato server.

Esempi:

- pairing HTTPS già raggiungibile;
- PUBLIC_ENDPOINT già raggiungibile;
- IPv6 globale utilizzabile.

Se server e client sono entrambi dietro CGNAT/NAT restrittivo e nessun control path è raggiungibile, Fase 19 non può iniziare il candidate exchange.

Questo caso non viene falsamente classificato come successo.

Il fallback con un canale relay appartiene alla Fase 20.

## Nessun port forwarding automatico

Fase 19 non esegue:

    upnpc -a
    upnpc -d

e non modifica:

    PUBLIC_ENDPOINT
    wg0.conf
    devices.json

Le modifiche endpoint sono runtime tramite wg set.

## Fuori scope Fase 19

- relay;
- TURN;
- server rendezvous esterno;
- control plane multi-server;
- auto port-forwarding UPnP/NAT-PMP/PCP;
- modifica persistente degli endpoint peer;
- modifica automatica PUBLIC_ENDPOINT.

Queste funzioni non vengono anticipate.
