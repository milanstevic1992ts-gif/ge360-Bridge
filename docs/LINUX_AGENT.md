# GE360 Linux Agent — Fase 14

GE360 Bridge v0.16 introduce un Agent Linux leggero e read-only da installare su host Linux aggiuntivi.

La Fase 14 non crea ancora un control plane multi-server e non modifica il routing del Bridge. L'Agent espone soltanto informazioni locali verificabili che le future fasi potranno consumare.

## Dati esposti

L'Agent raccoglie:

- stato host;
- hostname, sistema operativo, kernel e architettura;
- uptime;
- indirizzi IP locali;
- Resource GE360 locali rilevate tramite il discovery della Fase 13;
- stato health delle Resource;
- load average;
- memoria;
- spazio disco root;
- RX/TX per interfaccia di rete.

Non raccoglie payload applicativi.

## Discovery Resource

L'Agent riusa il contratto:

    GET /.well-known/ge360

e le stesse regole di sicurezza della Fase 13.

Il discovery automatico resta confinato ai listener IPv4 esattamente su 127.0.0.1. Non viene effettuata alcuna scansione LAN.

## API

Porta predefinita:

    8791

Bind predefinito:

    127.0.0.1

Endpoint pubblici minimi:

    GET /healthz
    GET /.well-known/ge360-agent

Endpoint protetti da Bearer token:

    GET /v1/status
    GET /v1/resources
    GET /v1/health
    GET /v1/metrics

Esempio:

    curl -H "Authorization: Bearer $TOKEN"       http://127.0.0.1:8791/v1/status

Il token viene generato durante l'installazione e salvato con permessi 0600 in:

    /etc/ge360-agent/token

## Installazione su un host Linux aggiuntivo

Dalla repository GE360 Bridge:

    sudo ./install-agent.sh

Verifiche:

    systemctl status ge360-agent --no-pager
    sudo ge360-agent snapshot
    curl http://127.0.0.1:8791/healthz

Configurazione:

    /etc/ge360-agent/agent.env

Default:

    GE360_AGENT_BIND=127.0.0.1
    GE360_AGENT_PORT=8791
    GE360_AGENT_DISCOVERY_TIMEOUT=0.6

## Sicurezza rete

Il bind di default è loopback.

Se in futuro l'Agent deve essere interrogato da un'altra macchina, cambiare il bind soltanto quando il trasporto tra le due macchine è già protetto, per esempio da una rete privata o da un tunnel cifrato già esistente.

La Fase 14 non crea automaticamente firewall, VPN tra server, NAT traversal, relay o esposizioni Internet.

Il Bearer token non sostituisce la cifratura del trasporto: su HTTP non protetto può essere intercettato.

## Metriche

Le metriche Agent sono snapshot correnti e non vengono persistite in un nuovo database.

Questo evita di anticipare il control plane e lo storico multi-server.

## Cache

Lo snapshot può essere mantenuto in memoria per pochi secondi per evitare discovery e health check duplicati. Non viene scritto su disco.

## Fuori scope Fase 14

Non sono implementati:

- restart automatico dei backend;
- self-healing;
- registrazione centralizzata di più server;
- modifica del Resource Registry del Bridge da remoto;
- routing delle Resource remote;
- backup;
- update engine;
- NAT discovery;
- P2P;
- relay;
- control plane multi-server.

Queste funzioni restano nelle rispettive fasi future della roadmap.
