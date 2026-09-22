# Backup configurazione — Fase 16

GE360 Bridge v0.18 introduce backup configurazione versionati, verificabili e ripristinabili.

## Obiettivo

Conservare una serie corta di snapshot completi della configurazione necessaria a ricostruire il Bridge dopo un guasto, senza includere database operativi o private key client.

Retention predefinita:

    10 backup

Frequenza automatica:

    1 backup al giorno

Il più vecchio viene eliminato automaticamente quando si supera la retention.

## Percorso

Directory:

    /etc/ge360-bridge/backups

Permessi directory:

    0700

Permessi archivio:

    0600

Formato:

    ge360-config-YYYYMMDDTHHMMSSZ-<reason>.tar.gz

Ogni archivio contiene un manifest JSON con versione Bridge, data, motivo, elenco file, dimensioni e checksum SHA-256.

## Contenuto

Sono inclusi esclusivamente i file configurazione in whitelist:

    /etc/ge360-bridge/devices.json
    /etc/ge360-bridge/resources.json
    /etc/ge360-bridge/services.json
    /etc/ge360-bridge/groups.json
    /etc/ge360-bridge/bridge.env
    /etc/ge360-bridge/server.key
    /etc/ge360-bridge/server.pub
    /etc/ge360-bridge/dashboard.token
    /etc/ge360-bridge/enrollment.key
    /etc/ge360-bridge/pairing-tls.key
    /etc/ge360-bridge/pairing-tls.crt
    /etc/wireguard/wg0.conf

Sono esclusi:

    audit.db
    metrics.db
    enrollments.json
    pairings/
    self_heal_state.json
    self_heal.lock

Audit, metriche, inviti pairing e contatori runtime non fanno parte della configurazione autoritativa.

## Private key client

Il Pairing v2 genera la private key WireGuard sul client e non la invia al Bridge.

Il motore backup effettua inoltre una scansione strutturale di devices.json e blocca il backup se trova campi compatibili con una private key client, ad esempio:

    private_key
    client_private_key
    wireguard_private_key

Il backup contiene invece segreti del server necessari al disaster recovery, come server.key e pairing-tls.key.

Per questo ogni archivio è sensibile e deve restare root-only. Se viene copiato fuori dal server, deve essere protetto con un trasporto/storage cifrato.

## Backup manuale

    sudo ge360-bridge backup-create

Retention personalizzata:

    sudo ge360-bridge backup-create --keep 10

## Backup automatico

Unit:

    ge360-bridge-backup.service
    ge360-bridge-backup.timer

Timer:

    ogni giorno alle 03:20
    Persistent=true
    jitter massimo 5 minuti

Comando eseguito:

    ge360-bridge backup-create --scheduled --keep 10

La modalità scheduled non crea più di un backup daily per data UTC, anche se il service viene richiamato più volte.

Durante installazione/aggiornamento viene creato anche il backup daily del giorno se non esiste già.

## Elenco

    sudo ge360-bridge backup-list

L'elenco verifica gli archivi e indica se un backup è valido o corrotto.

## Verifica

    sudo ge360-bridge backup-verify ge360-config-20260922T032000Z-daily.tar.gz

La verifica controlla:

- formato tar.gz;
- membri file regolari;
- whitelist dei percorsi;
- assenza di path traversal;
- schema manifest;
- dimensione file;
- checksum SHA-256;
- registry device/resource/group;
- mirror resources.json/services.json;
- bridge.env;
- configurazione WireGuard;
- garanzia contains_client_private_keys=false.

Nessun file viene ripristinato durante backup-verify.

## Restore sicuro

Senza --apply il comando verifica l'archivio e mostra soltanto il piano:

    sudo ge360-bridge backup-restore <backup>

Applicazione reale:

    sudo ge360-bridge backup-restore <backup> --apply

Prima del restore viene tentato automaticamente un safety backup pre-restore dello stato corrente.

Se lo stato corrente è già danneggiato e non può essere backuppato, l'archivio sorgente già verificato può comunque essere ripristinato; il risultato riporta safety_backup_error.

Dopo il restore la CLI:

- rigenera la configurazione WireGuard canonica dai device ripristinati;
- riavvia wg0;
- ricarica Bridge e firewall;
- riavvia dashboard;
- riavvia enrollment HTTPS.

## Atomicità

Ogni file viene prima scritto in un file temporaneo nella directory di destinazione, fsyncato, impostato 0600 e poi sostituito tramite rename atomico.

L'archivio viene verificato completamente prima di modificare qualunque file attivo.

## Limiti di sicurezza

Un archivio che contiene file extra, symlink, path traversal, checksum errati o JSON incoerente viene rifiutato.

La Fase 16 non scarica aggiornamenti e non implementa rollback software automatico. Queste funzioni appartengono alla Fase 17 — Update Engine.
