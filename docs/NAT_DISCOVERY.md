# NAT Discovery — Fase 18

GE360 Bridge v0.20 aggiunge diagnostica NAT/CGNAT senza aprire porte e senza iniziare il traversal P2P.

## Obiettivo

Raccogliere segnali utili sulla connettività Internet del server:

- indirizzo IPv4 pubblico osservato via STUN;
- endpoint UDP mapped della socket diagnostica;
- IPv6 globali locali;
- indirizzo WAN router letto via UPnP in sola lettura;
- indizi CGNAT;
- comportamento di mapping NAT;
- comportamento di filtering quando il server STUN espone RFC 5780.

La Fase 18 non modifica NAT, firewall, WireGuard o port forwarding.

## Server STUN

Default:

    stun.cloudflare.com:3478
    stun.cloudflare.com:53

È possibile sovrascriverli da CLI:

    ge360-bridge nat-discover       --server stun.example.net:3478       --server stun2.example.net:3478

oppure in /etc/ge360-bridge/bridge.env:

    STUN_SERVERS=stun.example.net:3478,stun2.example.net:3478

Massimo:

    6 server

La diagnostica IPv4 usa UDP STUN Binding Request.

## CLI

    ge360-bridge nat-discover

Timeout personalizzato:

    ge360-bridge nat-discover --timeout 1.5

Output schema:

    ge360-nat-discovery/v1

## Dashboard

Pagina autenticata:

    /nat

API autenticata:

    /api/nat

La dashboard usa una cache solo in memoria di 30 secondi per evitare probe STUN ripetuti durante refresh ravvicinati.

## STUN

Il client implementa il Binding Request RFC 5389 e legge:

- XOR-MAPPED-ADDRESS;
- MAPPED-ADDRESS fallback;
- RESPONSE-ORIGIN;
- OTHER-ADDRESS.

Se OTHER-ADDRESS è presente viene tentato un CHANGE-REQUEST diagnostico RFC 5780.

Nessun TURN viene utilizzato.

## Mapping NAT

La classificazione evita di chiamare "full cone", "restricted cone" o "port restricted" una rete quando i dati disponibili non lo dimostrano.

Valori principali:

    NO_NAT
    ENDPOINT_INDEPENDENT_MAPPING
    SYMMETRIC_LIKE_MAPPING
    UNKNOWN

### NO_NAT

Solo quando l'IPv4 locale è globale e coincide con endpoint IP/porta osservato da STUN.

### ENDPOINT_INDEPENDENT_MAPPING

Quando due destinazioni STUN distinte osservano lo stesso mapped endpoint.

### SYMMETRIC_LIKE_MAPPING

Quando il mapped endpoint cambia in funzione della destinazione STUN.

Il termine "symmetric-like" è intenzionalmente prudente: descrive il comportamento osservato senza sostenere di aver misurato tutte le regole di filtering.

### UNKNOWN

Se c'è una sola osservazione valida o dati insufficienti.

## Filtering NAT

Se RFC 5780 OTHER-ADDRESS è disponibile e una risposta arriva dopo CHANGE-REQUEST IP+port da un'origine differente:

    ENDPOINT_INDEPENDENT

Altrimenti:

    UNKNOWN

La mancata risposta non viene interpretata automaticamente come filtering restrittivo, perché il server potrebbe semplicemente non implementare RFC 5780.

## Port preservation

Il report confronta la porta UDP locale diagnostica con la porta mapped STUN.

Questo dato riguarda soltanto la socket STUN usata dal test.

Non dimostra che:

    UDP 51820 WireGuard

sia raggiungibile dall'esterno.

## IPv6 globale

Il Bridge legge gli indirizzi:

    ip -6 -j address show scope global

e conserva nel report soltanto indirizzi IPv6 globalmente instradabili.

La presenza di IPv6 globale è un candidato utile per connettività diretta futura, ma la Fase 18 non apre firewall né verifica inbound reachability.

## UPnP read-only

La sola operazione UPnP della Fase 18 è:

    upnpc -s

Non vengono mai eseguiti:

    upnpc -a
    upnpc -d

quindi NAT Discovery non crea, modifica o elimina port mapping.

## CGNAT

Output:

    YES
    LIKELY
    POSSIBLE
    NO_EVIDENCE
    UNKNOWN

### YES / HIGH

Quando il WAN IPv4 del router o il mapped STUN ricade nello spazio condiviso RFC 6598:

    100.64.0.0/10

### LIKELY / MEDIUM

Quando UPnP vede un WAN IPv4 non globale ma STUN vede un IPv4 pubblico globale.

Questo indica un NAT ulteriore a monte del router; può essere CGNAT o altra forma di double NAT.

### NO_EVIDENCE / HIGH

Quando WAN IPv4 globale del router e IPv4 pubblico STUN coincidono.

Non significa che una porta specifica sia aperta: significa solo che non c'è evidenza di CGNAT dai segnali disponibili.

### POSSIBLE / LOW

Quando router WAN e STUN mostrano IPv4 globali differenti.

### UNKNOWN

Quando UPnP non espone WAN address o i segnali sono insufficienti.

## Endpoint pubblico

Il report espone:

- IPv4 pubblico osservato;
- mapped UDP port diagnostica;
- IPv6 globali;
- WAN IPv4 UPnP se disponibile.

Campo di sicurezza:

    wireguard_port_inferred=false

e:

    phase19_traversal_attempted=false
    port_mapping_changed=false

Questi campi rendono esplicito che la Fase 18 non ha tentato connessioni P2P o port forwarding.

## Fuori scope Fase 18

Non vengono implementati:

- hole punching;
- rendezvous;
- endpoint exchange tra peer;
- modifica automatica PUBLIC_ENDPOINT;
- port forwarding UPnP;
- NAT-PMP/PCP mapping;
- WireGuard traversal;
- relay;
- control plane multi-server.

Queste funzioni appartengono alle fasi successive.
