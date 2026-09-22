# Update Engine — Fase 17

GE360 Bridge v0.19 introduce un Update Engine controllato con backup pre-update, download HTTPS, verifica SHA-256, preflight, installazione atomica, health check e rollback automatico.

## Principio

L'Update Engine non esegue install.sh scaricati e non esegue script arbitrari contenuti nel pacchetto.

Un pacchetto GE360 contiene:

    manifest.json
    payload/...

Il manifest usa:

    ge360-bridge-update/v1

e dichiara versione, file, dimensioni, mode e SHA-256.

I target di installazione non sono scelti dal manifest: vengono calcolati localmente da una whitelist del motore.

## File gestibili

Sono ammessi soltanto:

- moduli Python sotto ge360_bridge/*.py;
- wrapper ge360-bridge;
- scripts/apply-firewall.sh;
- scripts/boot-verify.sh;
- unit systemd ge360-bridge*.service;
- timer systemd ge360-bridge*.timer.

Non è consentito scrivere configurazione in /etc/ge360-bridge tramite un pacchetto update.

La configurazione resta gestita dal Backup Engine Fase 16.

## Download

Il download è consentito soltanto tramite HTTPS.

È obbligatorio fornire SHA-256 atteso:

    sudo ge360-bridge update-download       https://server.example/ge360-update-v0.20.0.tar.gz       --sha256 <64-caratteri-hex>

Redirect verso protocolli diversi da HTTPS vengono rifiutati.

Dimensione massima pacchetto:

    32 MiB

Sono inoltre limitati numero di file, dimensione per membro e dimensione decompressa totale.

## Verifica e preflight

Verifica senza installazione:

    sudo ge360-bridge update-verify /var/lib/ge360-bridge/updates/download-....tar.gz

Il preflight controlla:

- schema manifest;
- versione pacchetto;
- pacchetto più recente della versione installata;
- whitelist dei percorsi;
- assenza di symlink e path traversal;
- size e SHA-256 di ogni payload;
- corrispondenza manifest/payload;
- versione in ge360_bridge/__init__.py;
- compileall di tutto ge360_bridge;
- bash -n per wrapper/script shell;
- struttura minima delle unit systemd.

Il preflight non importa e non esegue codice Python del pacchetto.

## Backup pre-update

Prima di installare, l'Update Engine richiede con successo un backup configurazione Fase 16:

    reason=pre-update

Il backup contiene registry, ACL, identità e configurazione server necessari al disaster recovery.

Se il backup configurazione non può essere creato, l'update viene abortito prima di modificare il software.

## Snapshot software rollback

Prima dell'installazione viene creato anche uno snapshot dei file software che saranno sostituiti:

    /var/lib/ge360-bridge/updates/rollback-*.tar.gz

Permessi:

    directory 0700
    snapshot 0600

Vengono conservati fino a 3 snapshot software rollback.

Lo snapshot ricorda anche quali target non esistevano prima dell'update; in caso di rollback tali file nuovi vengono rimossi.

## Installazione

I file vengono installati con:

- file temporaneo nella stessa directory target;
- write;
- fsync;
- chmod canonico;
- rename atomico.

Mode canonici:

    Python/systemd: 0644
    wrapper/script: 0755

Dopo l'installazione:

    systemctl daemon-reload
    restart wg-quick@wg0
    restart ge360-bridge-firewall
    restart ge360-bridge
    restart ge360-bridge-dashboard
    restart ge360-bridge-enrollment

## Health check

Dopo l'installazione vengono controllati fino a 10 volte:

- wg-quick@wg0.service;
- ge360-bridge-firewall.service;
- ge360-bridge.service;
- ge360-bridge-dashboard.service;
- ge360-bridge-enrollment.service;
- http://127.0.0.1:8789/healthz;
- https://127.0.0.1:8790/healthz.

Il certificato pairing locale è self-signed, quindi il check HTTPS locale usa TLS senza verifica CA soltanto per questo endpoint loopback.

Un update è riuscito solo se tutti i controlli diventano verdi.

## Rollback automatico

Se installazione, restart o health check falliscono:

1. vengono ripristinati i file software precedenti;
2. vengono rimossi eventuali file nuovi introdotti dal pacchetto;
3. viene ripristinato il backup configurazione pre-update;
4. systemd viene ricaricato;
5. i servizi vengono riavviati;
6. viene eseguito un nuovo health check.

Se il rollback torna sano:

    rolled_back=true

Se anche il rollback non torna sano, l'Update Engine genera un errore esplicito:

    Update fallito e rollback NON riuscito

Non viene mai nascosto un rollback incompleto.

## Comando completo

Download + verifica + backup + installazione + health + rollback:

    sudo ge360-bridge update-run       https://server.example/ge360-update-v0.20.0.tar.gz       --sha256 <SHA256>

## Pacchetto locale

Applicare un pacchetto già scaricato:

    sudo ge360-bridge update-apply /percorso/ge360-update.tar.gz

## Stato

    sudo ge360-bridge update-status

Mostra:

- versione corrente;
- ultimo update;
- risultato;
- rollback;
- snapshot software disponibili.

Il report viene salvato root-only in:

    /var/lib/ge360-bridge/updates/last-update.json

## Creazione pacchetto

Dal checkout della repository:

    python scripts/build-update-package.py       --source .       --output /tmp/ge360-update-v0.19.0.tar.gz

Il comando restituisce SHA-256 da pubblicare insieme all'artefatto.

La CI Fase 17 costruisce realmente questo pacchetto dalla repository e lo sottopone al medesimo preflight usato sul server.

## Nessun auto-update

La Fase 17 non introduce:

- polling automatico GitHub;
- installazione automatica di nuove versioni;
- timer update;
- update remoto via Linux Agent;
- canali beta/stable automatici.

L'operatore deve fornire esplicitamente URL e SHA-256 o un pacchetto locale.

## Fuori scope

Restano fuori dalla Fase 17:

- NAT Discovery;
- NAT Traversal P2P;
- relay;
- control plane multi-server.

Queste funzioni appartengono alle fasi successive della roadmap.
