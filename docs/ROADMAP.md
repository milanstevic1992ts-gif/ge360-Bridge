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

## Fase 2 — Gruppi e ACL semplificate — CORRENTE

Obiettivo: amministrare l'accesso ai servizi tramite gruppi senza perdere le ACL dirette esistenti.

Scope obbligatorio:
- Group Registry persistente in groups.json;
- gruppi con nome, descrizione, stato enabled/disabled;
- appartenenza device tramite device_id stabile;
- un device può appartenere a più gruppi;
- assegnazione dei servizi esistenti ai gruppi;
- accesso effettivo ereditato dai gruppi;
- override diretto per singolo device: allow, deny, inherit;
- deny diretto con precedenza sull'accesso di gruppo;
- allow diretto indipendente dai gruppi;
- rename device compatibile con ACL dirette e membership di gruppo;
- rimozione servizio pulita dai gruppi;
- dashboard e CLI per gruppi/ACL;
- health endpoint coerente con l'accesso effettivo;
- migrazione automatica delle ACL v0.3 senza perdita di allowed_devices.

Fuori scope Fase 2:
- pairing v2;
- Resource Registry;
- Health Engine avanzato;
- diagnostica avanzata;
- audit;
- NAT discovery/traversal.

Criterio di chiusura: test e CI verdi, upgrade da v0.3 senza perdita di device, servizi o ACL dirette, e verifica precedenza deny > allow diretto > gruppo > nessun accesso.

## Fase 3 — Pairing sicuro v2

Token monouso, TTL, private key generata sul client, protezione replay e invalidazione dopo enrollment.

## Fase 4 — Resource Registry

Entità Resource con nome, icona, descrizione, protocollo, bridge port, target, health URL, timeout e ACL.

## Fase 5 — Health Engine

Controlli TCP/HTTP, status code, latenza, risposta JSON, TLS e stati ONLINE/DEGRADED/OFFLINE/TIMEOUT/UNAUTHORIZED/BAD_RESPONSE.

## Fase 6 — Diagnostica avanzata

Ping Bridge/backend, test TCP/API/PDF, DNS e traceroute.

## Fase 7 — Connection Doctor

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
