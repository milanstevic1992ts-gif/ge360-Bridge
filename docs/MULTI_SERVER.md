# Multi-server GE360 — Fase 21

GE360 Bridge v0.23 introduce un control plane read-only capace di presentare più server GE360 e le loro Resource in un catalogo unico.

## Obiettivo

Un'app GE360 non deve più ragionare soltanto in termini di "questa macchina fisica".

Il catalogo usa identificatori stabili:

    <server_id>:<resource_name>

Esempio:

    srv_casa:rilievi
    srv_officina:firefly
    srv_nas:documenti

Due server possono quindi avere una Resource con lo stesso nome senza collisione.

## Ruoli

### Control Bridge

È il Bridge a cui sono collegati i device.

Mantiene:

    /etc/ge360-bridge/servers.json

e aggrega inventario/stato dei server remoti.

### Server GE360 remoto

Espone una API HTTPS read-only sulla porta 8793:

    GET /healthz
    GET /v1/control/snapshot

L'API richiede Bearer token e usa certificate pinning.

### Linux Agent

L'Agent Fase 14 rimane read-only.

Fase 21 aggiunge TLS opzionale all'Agent, ma non aggiunge endpoint di modifica.

## Identità server

Ogni Bridge genera:

    /etc/ge360-bridge/server-id
    /etc/ge360-bridge/server.token
    /etc/ge360-bridge/multi-server-tls.key
    /etc/ge360-bridge/multi-server-tls.crt

Permessi sensibili:

    server-id            0600
    server.token         0600
    multi-server-tls.key 0600
    multi-server-tls.crt 0644
    servers.json         0600

Il token non viene mai restituito da server-list, dashboard, status o catalogo.

## Control API

Servizio:

    ge360-bridge-multi-server.service

Porta default:

    TCP 8793

Configurabile tramite:

    GE360_MULTI_SERVER_BIND
    GE360_MULTI_SERVER_PORT

La API restituisce lo snapshot read-only del server:

- host;
- IP;
- Resource scoperte;
- health corrente;
- versione Agent.

Non espone:

- token;
- PSK;
- private key WireGuard;
- ACL;
- audit DB;
- metrics DB;
- payload applicativi.

## Registrare un server

Sul server remoto:

    sudo ge360-bridge server-export --public-host server2.example.com

Il risultato contiene:

- server_id;
- name;
- control_url;
- TLS SHA-256 pin;
- token.

Il token va trattato come segreto amministrativo.

Sul Control Bridge:

    sudo ge360-bridge server-add server2 \
      --server-id srv_xxx \
      --url https://server2.example.com:8793 \
      --pin <SHA256> \
      --token <TOKEN>

Poi:

    ge360-bridge server-list
    ge360-bridge server-status
    ge360-bridge server-catalog

Disabilitazione non distruttiva:

    sudo ge360-bridge server-disable server2
    sudo ge360-bridge server-enable server2

Rimozione:

    sudo ge360-bridge server-remove server2

## Catalogo aggregato

Schema:

    ge360-multi-server-catalog/v1

Contiene:

- control_server_id;
- server online/offline;
- hostname;
- IP osservati;
- Resource per server;
- health Resource;
- resource_id namespaced.

Un server remoto offline non rende indisponibili gli altri server.

Il catalogo continua a essere prodotto indicando quel server come offline.

## App / Resource Launcher

Endpoint device-facing:

    http://10.88.0.1:8788/v1/catalog

Schema:

    ge360-resource-launcher-multi/v1

Per il server locale vengono applicate le ACL esistenti del device.

Le Resource remote vengono presentate come inventario read-only del server di origine.

Fase 21 non inventa un proxy applicativo remoto: il campo

    remote_resource_proxy=false

è intenzionale.

## Dashboard

Nuove pagine:

    /servers
    /api/servers
    /api/catalog

La dashboard mostra:

- server online;
- Resource aggregate;
- server di origine;
- health;
- resource_id stabile.

## Sicurezza

Il fetch server remoto richiede:

1. HTTPS;
2. Bearer token;
3. certificate pin SHA-256;
4. limite risposta 1 MiB;
5. sanitizzazione rigida dello snapshot.

Campi remoti non riconosciuti vengono scartati.

target_host remoto non viene importato nel catalogo.

Il Control Bridge non esegue comandi sull'Agent remoto.

## Backup

La Fase 16 include opzionalmente:

    servers.json
    server-id
    server.token
    multi-server-tls.key
    multi-server-tls.crt

I vecchi backup senza questi file restano validi.

## Update Engine

La Fase 17 include il nuovo modulo Python e la unit:

    ge360-bridge-multi-server.service

Dopo update la unit viene riavviata e inclusa nei servizi core del health check.

## Linux Agent TLS

install-agent.sh genera:

    /etc/ge360-agent/tls.key
    /etc/ge360-agent/tls.crt

Quando entrambi esistono, l'Agent serve HTTPS.

Il bind resta 127.0.0.1 per default.

Esporre l'Agent su una rete richiede una scelta esplicita dell'operatore.

## Fuori scope

Fase 21 NON implementa:

- restart remoto;
- self-healing remoto;
- modifica Resource remota;
- ACL globali distribuite;
- proxy TCP/HTTP tra server;
- mesh WireGuard server-to-server;
- replica database;
- sincronizzazione audit/metriche;
- orchestrazione container;
- discovery LAN indiscriminata;
- provisioning cloud;
- consenso automatico ad azioni distruttive.

Il control plane Fase 21 è volutamente read-only.
