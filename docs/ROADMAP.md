# GE360 Universal Bridge — Roadmap ufficiale

Questa roadmap è la fonte di verità del progetto. Le fasi vanno implementate in ordine.

## Regola di lavoro

- Non anticipare funzioni appartenenti a fasi future.
- Non sostituire componenti funzionanti senza necessità della fase corrente.
- Ogni fase deve mantenere compatibilità e installazione aggiornabile.
- La fase successiva parte solo dopo test e CI verdi della fase corrente.

## Fase 0 — Base stabile — COMPLETATA

WireGuard, rete privata 10.88.0.0/24, ACL per device, proxy TCP locale, firewall nftables, pairing QR v1, revoca, dashboard, health, handshake, RX/TX, controllo backend, installer Debian, systemd, boot verify e CI.

## Fase 1 — Device Registry — COMPLETATA

device_id stabile, metadati, rename, enable/disable, scadenza, note, tag e migrazione compatibile dei device esistenti.

## Fase 2 — Gruppi e ACL semplificate — COMPLETATA

Gruppi persistenti, membership tramite device_id, servizi concessi ai gruppi e override allow/deny/inherit per singolo device.

## Fase 3 — Pairing sicuro v2 — COMPLETATA

Token monouso, TTL, private key generata sul client, HTTPS bootstrap con certificate pinning e protezione replay.

## Fase 4 — Resource Registry — COMPLETATA

Obiettivo: sostituire il modello generico Service con un registro Resource autoritativo senza rompere backend, ACL, gruppi o pairing esistenti.

Scope obbligatorio:
- file autoritativo resources.json;
- migrazione automatica services.json → resources.json;
- mirror services.json di compatibilità;
- Resource con nome, icona, descrizione, protocollo, bridge port, target host/port, health URL, timeout, enabled e ACL;
- protocolli ammessi tcp/http/https;
- bridge port univoca e porte di sistema riservate;
- target ancora limitato a loopback;
- health URL validata ma non eseguita;
- timeout registrato ma non usato dal futuro Health Engine;
- ACL dirette Fase 2 preservate;
- associazioni gruppo preservate;
- allowed_resources esposto insieme al legacy allowed_services;
- CLI resource-add/update/remove/list;
- comandi service-* mantenuti come alias compatibili;
- dashboard per creare, visualizzare, modificare e rimuovere Resource;
- daemon/proxy alimentato dal Resource Registry;
- firewall alimentato da resources.json;
- pairing/status espongono Resource mantenendo il campo services di compatibilità.

Fuori scope Fase 4:
- Health Engine attivo;
- HTTP status check;
- latenza e stato DEGRADED;
- diagnostica;
- audit;
- Resource Launcher;
- NAT discovery/traversal.

Criterio di chiusura: test e CI verdi, migrazione v0.5 senza perdita di porta/target/ACL/gruppi e compatibilità service-* verificata.

## Fase 5 — Health Engine — COMPLETATA

Obiettivo: misurare lo stato attuale di ogni Resource con un unico motore condiviso da dashboard, CLI e status Bridge.

Scope obbligatorio:
- check TCP target host/port;
- latenza TCP e totale;
- GET HTTP/HTTPS quando health_url è configurata;
- status code HTTP;
- validazione body JSON senza interpretare semantica applicativa;
- verifica TLS standard per HTTPS con versione/cipher quando disponibili;
- timeout per Resource;
- stati ONLINE, DEGRADED, OFFLINE, TIMEOUT, UNAUTHORIZED e BAD_RESPONSE;
- limite body health;
- controlli paralleli;
- piccola cache solo in memoria per evitare check duplicati;
- CLI health-check;
- endpoint dashboard autenticato /api/health;
- stato health incluso nel /v1/status per le Resource accessibili al device;
- dashboard con stato, latenza e sotto-controlli TCP/HTTP/JSON/TLS.

Fuori scope Fase 5:
- ping ICMP;
- DNS diagnostico;
- traceroute;
- test PDF/API specifici;
- Connection Doctor;
- storico metriche;
- audit;
- self-healing.

Criterio di chiusura: test e CI verdi per tutti gli stati previsti e nessuna regressione sul proxy Resource.

## Fase 6 — Diagnostica avanzata — COMPLETATA

Obiettivo: fornire test manuali, separati e non persistenti per localizzare un problema di comunicazione senza anticipare il Connection Doctor.

Scope obbligatorio:
- ping Bridge 10.88.0.1;
- ping backend target;
- test TCP target host/port;
- test API HTTP/HTTPS su percorso della Resource;
- test PDF con status, Content-Type, Content-Length e firma %PDF-;
- DNS tramite resolver di sistema;
- traceroute target;
- timeout controllati;
- API/PDF confinati al target registrato della Resource;
- CLI diagnose-resource;
- pannello diagnostica nella pagina Resource;
- risultati JSON strutturati;
- nessuna persistenza dei risultati.

Fuori scope Fase 6:
- classificazione automatica della causa;
- categorie Connection Doctor;
- storico;
- metriche temporali;
- audit;
- self-healing;
- NAT discovery/traversal.

Criterio di chiusura: test e CI verdi per TCP/API/PDF/DNS/ping/traceroute e nessun accesso API/PDF fuori dal target Resource.

## Fase 7 — Connection Doctor — PROSSIMA, NON AVVIATA

Classificazione automatica dei problemi: VPN_DOWN, BRIDGE_DOWN, DEVICE_NOT_AUTHORIZED, SERVICE_NOT_ALLOWED, BACKEND_DOWN, HTTP_ERROR, PDF_URL_INVALID, TIMEOUT, PORT_CONFLICT, ENDPOINT_INVALID.

## Fase 8 — Audit log

Storico eventi del Bridge senza salvare payload personali delle applicazioni.

## Fase 9 — Metriche e grafici

RX/TX, latenza, handshake, uptime, errori e connessioni.

## Fase 10 — Resource Launcher

Home GE360 con le applicazioni accessibili al dispositivo.

## Fase 11 — Frontend SDK Android

Modulo riutilizzabile per scan QR, enrollment, VPN, health, discovery e diagnostica.

## Fase 12 — Connessione automatica Android

VPNService/WireGuard, reconnect e stati connessione integrati nelle APK.

## Fase 13 — Auto discovery backend

Endpoint /.well-known/ge360 e proposta automatica di nuovi backend.

## Fase 14 — Agent Linux

Agent leggero per server aggiuntivi con stato, servizi, health, IP e metriche.

## Fase 15 — Self-healing

Restart controllato systemd con limiti anti-loop.

## Fase 16 — Backup configurazione

Backup versionati di device, resource, gruppi, ACL e configurazione Bridge.

## Fase 17 — Update Engine

Backup, download, test, installazione, health check e rollback.

## Fase 18 — NAT Discovery

STUN, endpoint discovery, rilevamento CGNAT e tipo NAT.

## Fase 19 — NAT Traversal P2P

Tentativo di connessione WireGuard diretta tramite discovery/NAT traversal.

## Fase 20 — Relay opzionale

Fallback self-hosted, opzionale e visibile solo quando direct/P2P falliscono.

## Fase 21 — Multi-server GE360

Control plane GE360 con più server e risorse presentate alle app senza dipendere dalla macchina fisica.
