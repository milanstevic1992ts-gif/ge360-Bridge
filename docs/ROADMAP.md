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

## Fase 7 — Connection Doctor — COMPLETATA

Obiettivo: classificare automaticamente e in modo deterministico i problemi usando soltanto segnali già verificati dalle fasi precedenti.

Scope obbligatorio:
- categorie VPN_DOWN, BRIDGE_DOWN, DEVICE_NOT_AUTHORIZED, SERVICE_NOT_ALLOWED, BACKEND_DOWN, HTTP_ERROR, PDF_URL_INVALID, TIMEOUT, PORT_CONFLICT, ENDPOINT_INVALID;
- stato OK quando non emerge un problema;
- verifica runtime wg0 e ge360-bridge.service;
- verifica listener bridge port;
- validazione PUBLIC_ENDPOINT;
- device opzionale con stato, ACL e handshake;
- utilizzo Health Engine Fase 5;
- utilizzo Diagnostica Fase 6;
- categoria primaria con precedenza deterministica;
- finding secondari con evidenze;
- CLI doctor;
- integrazione dashboard nel flusso diagnostica;
- nessuna persistenza.

Fuori scope Fase 7:
- audit log;
- storico;
- metriche/grafici;
- self-healing;
- NAT discovery/traversal.

Criterio di chiusura: test dedicato per ogni categoria e CI verde.

## Fase 8 — Audit log — COMPLETATA

Obiettivo: conservare uno storico tecnico del Bridge senza salvare payload delle applicazioni.

Scope obbligatorio:
- SQLite /etc/ge360-bridge/audit.db con WAL e permessi 0600;
- eventi DEVICE_CONNECTED e DEVICE_DISCONNECTED da transizioni handshake WireGuard;
- RESOURCE_ACCESS con allow/deny/error, device, Resource, IP e latenza;
- RESOURCE_ONLINE e RESOURCE_OFFLINE da transizioni Health Engine;
- ACL_CHANGED per override device e ACL/gruppi;
- campi timestamp, device, resource, action, result, IP, latency, error;
- nessuna colonna payload/body;
- CLI audit-list con filtri;
- dashboard ultimi eventi;
- API autenticata /api/audit;
- audit non bloccante rispetto alle modifiche ACL;
- nessuna raccolta di contenuto applicativo.

Fuori scope Fase 8:
- grafici;
- metriche temporali RX/TX;
- analytics;
- self-healing.

Criterio di chiusura: test storage/filtri/privacy/ACL e CI verdi.

## Fase 9 — Metriche e grafici — COMPLETATA

Obiettivo: conservare e visualizzare serie temporali leggere del Bridge.

Scope obbligatorio:
- metrics.db SQLite WAL con permessi 0600;
- campionamento ogni 60 secondi;
- retention 35 giorni;
- RX/TX WireGuard con delta per periodo;
- handshake age e connected ratio;
- latenza e online ratio Resource;
- uptime sistema;
- connessioni ed errori derivati dall'audit;
- finestre 1h, 24h, 7d, 30d;
- bucket automatici per limitare i punti;
- CLI metrics e metrics-sample;
- dashboard grafici SVG;
- API autenticata /api/metrics.

Fuori scope Fase 9:
- Resource Launcher;
- SDK Android;
- self-healing.

Criterio di chiusura: test delta/aggregazione/retention/permessi e CI verdi.

## Fase 10 — Resource Launcher — COMPLETATA

Obiettivo: offrire a ogni device una home GE360 con soltanto le Resource che può realmente usare.

Scope obbligatorio:
- HUB su http://10.88.0.1:8788/hub;
- API device-facing /v1/resources;
- identificazione tramite peer VPN registrato e attivo;
- ACL effettive device/gruppi;
- Resource non autorizzate completamente escluse;
- card con icona, descrizione e stato Health Engine;
- pulsante Apri per HTTP/HTTPS;
- endpoint testuale per TCP;
- launcher_url nel /v1/status e pairing v2;
- nessun segreto device nel markup/payload.

Fuori scope Fase 10:
- SDK Android;
- VPNService/reconnect;
- backend auto-discovery.

Criterio di chiusura: test ACL/launcher/segreti e CI verdi.

## Fase 11 — Frontend SDK Android — COMPLETATA

Obiettivo: fornire un modulo Android riutilizzabile per integrare GE360 Bridge senza duplicare protocolli nelle singole APK.

Scope obbligatorio:
- modulo android-sdk/ge360-bridge-android;
- decode QR da Bitmap;
- parser pairing v2;
- enrollment HTTPS con certificate pinning;
- private key mai inviata/loggata;
- WireGuardKeyProvider riutilizzabile;
- WireGuardConfig;
- contratto VpnController e ConnectionState;
- BridgeSession;
- client status/health;
- Resource discovery /v1/resources;
- diagnostica SDK leggera;
- redazione token/PSK/private key nei toString;
- unit test Kotlin;
- workflow GitHub Android che compila il modulo.

Fuori scope Fase 11:
- implementazione VpnService automatica;
- reconnect Android;
- persistenza automatica tunnel;
- backend auto-discovery.

Criterio di chiusura: CI Python verde + CI Android verde e test parser/configurazione.

## Fase 12 — Connessione automatica Android — COMPLETATA

Obiettivo: trasformare i contratti Android della Fase 11 in una connessione WireGuard realmente utilizzabile e ripristinabile dalle APK.

Scope obbligatorio:
- libreria WireGuard Android ufficiale;
- GoBackend userspace senza root;
- AndroidWireGuardKeyProvider;
- AndroidWireGuardController;
- consenso Android VpnService tramite intent di sistema;
- stati DISCONNECTED, WAITING_PERMISSION, CONNECTING, CONNECTED, RECONNECTING, ERROR;
- reconnect su perdita/cambio rete;
- backoff limitato;
- recupero da distruzione del VpnService;
- supporto Always-On callback del backend;
- persistenza cifrata della configurazione con Android Keystore;
- ripristino automatico quando desiredConnected=true;
- disconnect senza perdita configurazione;
- forget con eliminazione configurazione;
- AllowedIPs rigidamente limitato a 10.88.0.1/32;
- Network Security Config per accesso HTTP al Bridge privato;
- factory Ge360AndroidBridge per integrazione semplice nelle APK;
- test Kotlin per chiavi, configurazione WireGuard, stati, backoff e codec;
- CI Python e Android verdi.

Fuori scope Fase 12:
- /.well-known/ge360;
- backend auto-discovery;
- Linux Agent;
- self-healing server;
- NAT discovery/traversal.

Criterio di chiusura: CI Python verde + CI Android verde, configurazione accettata dal parser WireGuard ufficiale e nessuna funzione Fase 13 anticipata.

## Fase 13 — Auto discovery backend — COMPLETATA

Obiettivo: rilevare e proporre backend GE360 locali senza ripetere configurazioni manuali e senza introdurre scansioni LAN.

Scope:
- contratto GET /.well-known/ge360 con schema v1;
- validazione rigida di name, type, version, health, icon e description;
- discovery automatico limitato ai listener IPv4 esattamente su 127.0.0.1;
- porte specifiche opzionali per discovery controllato;
- nessuna scansione di subnet o LAN;
- proposta non distruttiva con rilevamento conflitti;
- import esplicito attraverso il Resource Registry esistente;
- resources.json autoritativo e services.json mirror invariati;
- CLI resource-discover e resource-import;
- dashboard autenticata /discovery e /api/discovery;
- test dedicati a schema, loopback, conflitti, import e guardrail.

Fuori scope Fase 13:
- Agent Linux;
- scansione LAN;
- import automatico senza conferma;
- self-healing;
- NAT discovery/traversal;
- relay e multi-server.

Criterio di chiusura: CI Python verde, compatibilità Resource Registry verificata, rilettura scope e nessuna funzione Fase 14 anticipata.

Chiusura verificata:
- commit funzionale 0e93c63552fa2dbdff6c2c5b95cd711ebf89df8e;
- CI Python completata con successo, inclusi compileall, unittest e bash -n;
- workflow Android non modificato e ultimo run Fase 12 su main verde;
- Resource Registry esistente riusato senza modifica dello schema;
- nessun Agent Linux, self-healing, NAT discovery, relay o multi-server introdotto.

## Fase 14 — Agent Linux — COMPLETATA

Obiettivo: fornire un Agent Linux leggero e read-only installabile su host aggiuntivi, senza anticipare il control plane multi-server.

Scope:
- comando separato ge360-agent;
- installer dedicato install-agent.sh;
- servizio systemd ge360-agent.service;
- bind predefinito 127.0.0.1:8791;
- token Bearer generato localmente e salvato con permessi 0600;
- endpoint pubblici minimi /healthz e /.well-known/ge360-agent;
- API protette /v1/status, /v1/resources, /v1/health e /v1/metrics;
- stato host con hostname, OS, kernel, architettura e uptime;
- indirizzi IP locali;
- Resource locali tramite il discovery controllato della Fase 13;
- Health Engine riusato per le Resource rilevate;
- metriche correnti load, memoria, disco e rete;
- cache breve soltanto in memoria;
- nessuna persistenza di payload o metriche Agent;
- test dedicati a metriche, Resource, token e autenticazione API.

Fuori scope Fase 14:
- restart automatico dei backend;
- self-healing;
- registrazione centralizzata dei server;
- routing di Resource remote;
- scansione LAN;
- modifica remota del Resource Registry;
- backup/update engine;
- NAT discovery/traversal;
- relay;
- control plane multi-server.

Criterio di chiusura: CI Python verde, installer sintatticamente valido, API read-only autenticata verificata, rilettura scope e nessuna funzione Fase 15 anticipata.

Chiusura verificata:
- commit funzionale cb96a0ca0c006391b780c58e614f48dfc6480d56;
- CI Python completata con successo, inclusi compileall, unittest e bash -n;
- test Agent verdi per metriche, Resource, token e autenticazione API;
- install-agent.sh e ge360-agent verificati sintatticamente;
- workflow Android non modificato e ultimo run su main verde;
- Agent read-only: nessun restart backend o modifica Resource remota;
- nessun self-healing, NAT discovery, relay o control plane multi-server introdotto.

## Fase 15 — Self-healing — COMPLETATA

Obiettivo: rilevare una Resource backend locale realmente non disponibile e tentare un restart systemd controllato senza creare loop di riavvio.

Scope:
- self-healing disattivato per default;
- campi Resource retrocompatibili systemd_unit e self_heal_enabled;
- validazione rigida delle unit systemd;
- protezione delle unit infrastrutturali GE360 Bridge, WireGuard e Linux Agent;
- trigger soltanto per stati Health Engine OFFLINE e TIMEOUT;
- nessun restart per ONLINE, DEGRADED, UNAUTHORIZED o BAD_RESPONSE;
- verifica LoadState=loaded prima del restart;
- systemctl restart con argv separati;
- limite rigido massimo 3 restart per Resource in 10 minuti;
- tentativo registrato prima del restart e restart fallito conteggiato;
- stato anti-loop persistente /etc/ge360-bridge/self_heal_state.json con permessi 0600;
- lock esclusivo per impedire race tra timer e avvio manuale;
- fino a 10 health-check post-restart, con successo soltanto quando la Resource torna ONLINE;
- audit SELF_HEAL_RESTART, SELF_HEAL_BLOCKED e SELF_HEAL_RECOVERED;
- CLI self-heal-run, self-heal-run --dry-run e self-heal-status;
- configurazione self-healing dalla pagina Resource della dashboard;
- timer systemd ogni 60 secondi;
- test dedicati a compatibilità, stati trigger, restart, recupero e rate limit.

Fuori scope Fase 15:
- backup configurazione;
- update engine;
- gestione o restart di host remoti tramite Linux Agent;
- NAT discovery/traversal;
- relay;
- control plane multi-server.

Criterio di chiusura: CI Python verde, test anti-loop 3/10 minuti verde, installer aggiornato, timer systemd presente, compatibilità Resource Registry verificata e nessuna funzione Fase 16 anticipata.

Chiusura verificata:
- commit funzionale 600ce9515f03a929ce0ac14f9f5ca0422f39639e;
- fix validazione unit systemd f55975635747f4f2e11d8ae97177300cd38fe5ed;
- CI Python completata con successo sul fix, inclusi compileall, 109 test e bash -n;
- test anti-loop verificato: quarto restart bloccato entro 10 minuti;
- restart fallito conteggiato nel limite;
- dry-run non consuma tentativi e non esegue restart;
- timer ge360-bridge-self-heal.timer presente con intervallo 60 secondi;
- Resource preesistenti migrate in modo conservativo con self-healing disattivato;
- workflow Android non modificato e ultimo run su main verde;
- nessun backup engine, update engine, NAT discovery, relay o multi-server introdotto.

## Fase 16 — Backup configurazione — COMPLETATA

Obiettivo: creare snapshot versionati e ripristinabili della configurazione autoritativa del Bridge, con retention corta e senza esportare private key client.

Scope:
- directory root-only /etc/ge360-bridge/backups;
- archivio tar.gz root-only 0600;
- manifest ge360-bridge-config-backup/v1 con versione, data, file, dimensioni e SHA-256;
- whitelist esplicita dei file configurazione;
- backup di devices, resources, services mirror, groups/ACL e bridge.env;
- backup dell'identità e dei segreti server necessari al disaster recovery;
- backup della configurazione WireGuard server;
- esclusione audit.db, metrics.db, pairing temporanei e stato runtime self-healing;
- scansione devices.json che blocca eventuali private key client;
- validazione registry e mirror resources/services;
- verifica anti path-traversal, symlink e file extra;
- retention predefinita 10 copie con eliminazione automatica del più vecchio;
- timer giornaliero con massimo un backup scheduled al giorno;
- backup-create, backup-list, backup-verify e backup-restore;
- restore in modalità verifica/piano per default e applicazione soltanto con --apply;
- safety backup pre-restore quando lo stato corrente è valido;
- restore consentito da archivio verificato anche se lo stato corrente è già corrotto;
- scrittura atomica file-by-file con temp + fsync + rename;
- rigenerazione/reload runtime dopo restore tramite CLI;
- test dedicati a retention, permessi, esclusioni, checksum, traversal, private key client e restore.

Fuori scope Fase 16:
- download/installazione aggiornamenti;
- rollback software automatico;
- backup audit/metriche;
- backup dati applicativi dei backend;
- cloud backup;
- NAT discovery/traversal;
- relay;
- multi-server control plane.

Criterio di chiusura: CI Python verde, retention 10 verificata, backup giornaliero verificato, restore da archivio valido verificato, corruzione/traversal/private key client rifiutati, installer/timer aggiornati e nessuna funzione Fase 17 anticipata.

Chiusura verificata:
- commit funzionale 8b2fd7732332e973af190975a38e153ccf41e882;
- CI Python completata con successo, inclusi compileall, 118 test e bash -n;
- test retention verificato: conservate esattamente 10 copie e rimossi i backup più vecchi;
- test scheduled verificato: massimo un backup daily per giorno;
- test restore verificato con safety backup pre-restore;
- test dry-run restore verificato senza modifica della configurazione;
- checksum alterati e path inattesi/traversal rifiutati;
- campo private_key client in devices.json blocca il backup;
- audit.db, metrics.db, pairing temporanei e stato runtime self-healing esclusi;
- archivi e directory backup con permessi root-only;
- timer ge360-bridge-backup.timer installato e abilitato;
- workflow Android non modificato e ultimo run su main verde;
- nessun download/update, rollback software, NAT discovery, relay o multi-server introdotto.

## Fase 17 — Update Engine — COMPLETATA

Obiettivo: installare aggiornamenti software GE360 in modo controllato con backup pre-update, verifica forte, health check e rollback automatico.

Scope:
- pacchetto ge360-bridge-update/v1 con manifest e payload;
- target di installazione calcolati localmente da whitelist, mai scelti liberamente dal manifest;
- download consentito soltanto via HTTPS;
- SHA-256 atteso obbligatorio per download;
- redirect verso protocolli non HTTPS rifiutato;
- limiti su dimensione archivio, numero file, dimensione membro e totale decompresso;
- rifiuto symlink, path traversal e file non gestiti;
- versione manifest validata e pacchetto più recente della versione installata;
- corrispondenza versione manifest / ge360_bridge.__version__;
- preflight compileall Python, bash -n script e validazione minima unit systemd;
- nessuna esecuzione di install.sh o codice arbitrario dal pacchetto;
- backup configurazione Fase 16 obbligatorio prima dell'installazione;
- snapshot software rollback root-only con retention 3;
- installazione file atomica temp + fsync + chmod + rename;
- systemctl daemon-reload e restart controllato runtime;
- health check servizi principali, dashboard e pairing HTTPS;
- fino a 10 tentativi health post-update;
- rollback software automatico se install/restart/health falliscono;
- restore backup configurazione pre-update durante rollback;
- health check dopo rollback;
- errore esplicito se anche il rollback fallisce;
- lock esclusivo per impedire update concorrenti;
- report ultimo update root-only;
- CLI update-download, update-verify, update-apply, update-run e update-status;
- builder deterministico scripts/build-update-package.py;
- CI che costruisce il pacchetto reale della repository e ne esegue il preflight.

Fuori scope Fase 17:
- auto-update periodico;
- polling automatico release GitHub;
- timer update;
- canali beta/stable automatici;
- update remoto tramite Linux Agent;
- NAT discovery/traversal;
- relay;
- multi-server control plane.

Criterio di chiusura: CI Python verde, pacchetto reale costruito e preflight verde, test download/verifica/install/health/rollback verdi, backup pre-update verificato, rollback automatico verificato e nessuna funzione Fase 18 anticipata.

Chiusura verificata:
- commit funzionale bf51cd6548389bf00caf1bdd513050409dc0d06a;
- fix builder diretto f1a426b43aad958a895d1fdb1f21125efd14b872;
- CI Python completata con successo sul fix, inclusi compileall, 127 test e bash -n;
- builder reale della repository completato con successo;
- preflight del pacchetto reale completato con successo;
- test download HTTPS + SHA-256 verde;
- test pacchetto manomesso/path inatteso/versione non più recente verdi;
- test installazione riuscita con backup configurazione + snapshot software verde;
- test health post-update fallito → rollback software + configurazione verde;
- test restart fallito → rollback verde;
- retention snapshot rollback limitata a 3 e verificata;
- workflow Android non modificato e ultimo run su main verde;
- nessun auto-update, NAT discovery/traversal, relay o multi-server introdotto.

## Fase 18 — NAT Discovery — COMPLETATA

Obiettivo: osservare endpoint pubblico e comportamento NAT/CGNAT del server senza modificare port mapping, firewall o WireGuard e senza anticipare il traversal P2P.

Scope:
- client STUN UDP Binding Request RFC 5389 in stdlib Python;
- parsing XOR-MAPPED-ADDRESS e MAPPED-ADDRESS;
- parsing RESPONSE-ORIGIN e OTHER-ADDRESS RFC 5780;
- CHANGE-REQUEST IP+port soltanto come test diagnostico quando OTHER-ADDRESS è disponibile;
- server STUN configurabili via CLI o STUN_SERVERS in bridge.env;
- default STUN su due destinazioni UDP;
- massimo 6 server STUN;
- timeout limitato 0.2..5.0 secondi;
- stessa socket UDP locale riusata per confrontare mapping verso destinazioni STUN distinte;
- IPv4 pubblico e mapped port diagnostica;
- IPv4 locale instradato;
- IPv6 globali locali;
- lettura WAN IPv4 router tramite upnpc -s soltanto;
- nessun upnpc -a/-d e nessuna modifica port mapping;
- classificazione NAT prudente NO_NAT, ENDPOINT_INDEPENDENT_MAPPING, SYMMETRIC_LIKE_MAPPING, UNKNOWN;
- filtering ENDPOINT_INDEPENDENT soltanto con evidenza RFC 5780, altrimenti UNKNOWN;
- rilevamento port preservation della sola socket diagnostica;
- CGNAT YES/LIKELY/POSSIBLE/NO_EVIDENCE/UNKNOWN con confidence e reason;
- riconoscimento RFC 6598 100.64.0.0/10;
- distinzione esplicita tra CGNAT e possibile double NAT quando l'evidenza non è definitiva;
- schema ge360-nat-discovery/v1;
- CLI nat-discover;
- dashboard autenticata /nat e /api/nat;
- cache dashboard soltanto in memoria 30 secondi;
- campi guardrail wireguard_port_inferred=false, phase19_traversal_attempted=false e port_mapping_changed=false;
- test dedicati parser STUN, transaction ID, NAT mapping, CGNAT, IPv6, UPnP read-only e guardrail Phase 19.

Fuori scope Fase 18:
- hole punching;
- rendezvous o scambio endpoint tra peer;
- modifica automatica PUBLIC_ENDPOINT;
- port forwarding UPnP;
- NAT-PMP/PCP mapping;
- WireGuard traversal;
- relay;
- multi-server control plane.

Criterio di chiusura: CI Python verde, parser STUN e classificazioni deterministiche testati, UPnP verificato read-only, dashboard/CLI compilano, nessuna funzione Fase 19 anticipata.

Chiusura verificata:
- commit funzionale ef02d884e39cc06780bec28ea64bfeb8d92dc6ca;
- CI Python completata con successo, inclusi compileall, 140 test e bash -n;
- parser XOR-MAPPED-ADDRESS, RESPONSE-ORIGIN, OTHER-ADDRESS e transaction ID verificati;
- classificazioni NO_NAT, ENDPOINT_INDEPENDENT_MAPPING, SYMMETRIC_LIKE_MAPPING e UNKNOWN verificate;
- CGNAT RFC 6598 YES/HIGH, LIKELY/MEDIUM e NO_EVIDENCE/HIGH verificati;
- test con singola destinazione conferma UNKNOWN invece di sovrastimare il NAT type;
- IPv6 globale filtrato correttamente;
- UPnP verificato soltanto con upnpc -s, senza -a/-d;
- guardrail verificati: wireguard_port_inferred=false, phase19_traversal_attempted=false, port_mapping_changed=false;
- dashboard /nat e /api/nat compilano con cache solo in memoria;
- pacchetto reale Update Engine continua a costruirsi e passare preflight;
- workflow Android non modificato e ultimo run su main verde;
- nessun hole punching, port forwarding, modifica PUBLIC_ENDPOINT, relay o multi-server introdotto.

## Fase 19 — NAT Traversal P2P — IN CORSO, IMPLEMENTAZIONE PRONTA PER CI

Obiettivo: tentare una connessione WireGuard diretta tramite candidate exchange STUN e aggiornamento endpoint runtime, senza introdurre relay o port forwarding automatico.

Scope:
- modulo server ge360_bridge/p2p.py;
- traversal configurabile tramite TRAVERSAL_ENABLED;
- autenticazione device_id + device_token con confronto constant-time;
- device attivo/non scaduto obbligatorio;
- candidato client IP globale + porta + local_port stabile;
- candidate server da PUBLIC_ENDPOINT configurato e IPv6 globale;
- nessuna inferenza della porta WireGuard dalla mapped port STUN diagnostica Fase 18;
- sessioni P2P TTL 90 secondi;
- rate limit 6 prepare/minuto/device;
- session ID random;
- mirror sessioni redatto root-only in /run/ge360-bridge;
- nessun token, PSK o public key peer nel mirror runtime;
- endpoint HTTPS /v3/traversal/prepare e /v3/traversal/status sulla porta pairing 8790;
- stesso certificate pinning pairing v2 lato Android;
- modifica endpoint peer soltanto runtime tramite wg set;
- persistent keepalive temporaneo 5 durante punch e 25 dopo successo;
- fino a 5 tentativi con traffico minimo WireGuard e verifica latest-handshakes;
- ripristino endpoint e keepalive runtime precedenti quando disponibili dopo fallimento;
- nessuna modifica devices.json o wg0.conf;
- audit P2P_PREPARED, P2P_SUCCEEDED e P2P_FAILED;
- CLI p2p-status;
- dashboard autenticata /p2p e /api/p2p;
- Android STUN candidate discovery con porta locale 51821..51830;
- Android WireGuardConfig con ListenPort opzionale persistito nello store cifrato;
- Android connectPreferP2P con fallback direct automatico se la preparazione non parte;
- Android traversalStatus e fallbackToDirect;
- AllowedIPs invariato 10.88.0.1/32;
- test server per auth, candidate, rate limit, handshake success/failure, restore endpoint, runtime mirror e no relay;
- test Android per STUN RFC5389, XOR-MAPPED-ADDRESS, ListenPort, persistence e fallback direct.

Limite esplicito:
- STUN non è signaling;
- un cold-start con entrambi i peer dietro CGNAT/NAT restrittivo e nessun control path HTTPS/IPv6/direct raggiungibile non può iniziare candidate exchange;
- questo caso deve fallire in modo visibile e non essere dichiarato P2P riuscito.

Fuori scope Fase 19:
- relay;
- TURN;
- server rendezvous esterno;
- port forwarding automatico UPnP/NAT-PMP/PCP;
- modifica automatica PUBLIC_ENDPOINT;
- endpoint peer persistenti;
- multi-server control plane.

Criterio di chiusura: CI Python e Android verdi, test handshake/fallback/guardrail verdi, Update Engine reale continua a costruire e passare preflight, nessun relay o funzione Fase 20 anticipata.

## Fase 20 — Relay opzionale

Fallback self-hosted, opzionale e visibile solo quando direct/P2P falliscono.

## Fase 21 — Multi-server GE360

Control plane GE360 con più server e risorse presentate alle app senza dipendere dalla macchina fisica.
