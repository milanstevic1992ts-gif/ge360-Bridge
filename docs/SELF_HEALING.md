# Self-healing — Fase 15

GE360 Bridge v0.17 introduce restart controllato dei backend locali gestiti da systemd.

Il self-healing è disattivato per default e deve essere abilitato esplicitamente per ogni Resource.

## Configurazione Resource

Nuovi campi compatibili:

    {
      "systemd_unit": "ge360-rilievi.service",
      "self_heal_enabled": true
    }

Le Resource esistenti vengono normalizzate con:

    systemd_unit=""
    self_heal_enabled=false

quindi un aggiornamento non abilita restart automatici su backend già configurati.

## Stati che possono innescare restart

Il restart è ammesso soltanto quando l'Health Engine restituisce:

- OFFLINE
- TIMEOUT

Non provocano restart:

- ONLINE
- DEGRADED
- UNAUTHORIZED
- BAD_RESPONSE

Questo evita di usare il restart come risposta generica a errori applicativi o di autorizzazione.

## Unit systemd

Sono accettate soltanto unit con nome semplice che termina in .service.

Le unit infrastrutturali GE360 Bridge, wg-quick e ge360-agent sono protette e non possono essere configurate come target del self-healing.

Prima del restart il motore verifica che systemd riporti:

    LoadState=loaded

Se l'unit non esiste o non è caricata, nessun tentativo di restart viene consumato.

## Limite anti-loop

Regola rigida per singola Resource:

    massimo 3 restart / 10 minuti

Il tentativo viene registrato prima di invocare systemctl restart.

Anche un restart systemd fallito conta nel limite.

Lo stato runtime viene mantenuto in:

    /etc/ge360-bridge/self_heal_state.json

con permessi 0600.

Quando il quarto tentativo cade ancora nella stessa finestra di 10 minuti, il motore restituisce RATE_LIMITED e non esegue systemctl restart.

## Verifica dopo restart

Dopo un restart riuscito il Bridge esegue fino a 10 health-check, distanziati di un secondo.

La Resource viene considerata recuperata soltanto quando torna:

    ONLINE

In caso contrario il risultato è STILL_UNHEALTHY e il tentativo resta conteggiato.

## Timer systemd

Il controllo automatico usa:

    ge360-bridge-self-heal.service
    ge360-bridge-self-heal.timer

Il timer parte circa 90 secondi dopo il boot e poi esegue un controllo ogni 60 secondi.

## CLI

Configurare una Resource:

    sudo ge360-bridge resource-update rilievi       --systemd-unit ge360-rilievi.service       --self-heal true

Verifica senza restart:

    sudo ge360-bridge self-heal-run --dry-run

Verifica una singola Resource:

    sudo ge360-bridge self-heal-run rilievi --dry-run

Esecuzione manuale:

    sudo ge360-bridge self-heal-run

Stato rate limit:

    ge360-bridge self-heal-status

Disabilitazione:

    sudo ge360-bridge resource-update rilievi --self-heal false

## Dashboard

La pagina di ogni Resource consente di configurare:

- systemd unit;
- self-healing attivo/disattivo.

La dashboard ricorda il limite 3 restart / 10 minuti.

## Audit

Sono registrati eventi tecnici senza payload applicativi:

- SELF_HEAL_RESTART
- SELF_HEAL_BLOCKED
- SELF_HEAL_RECOVERED

## Sicurezza

Il self-healing opera solo su Resource locali già registrate e su unit systemd esplicitamente configurate.

Non esegue comandi arbitrari forniti dall'utente: il nome unit passa attraverso validazione rigida e systemctl viene invocato con argv separati.

## Fuori scope Fase 15

Non vengono implementati:

- backup configurazione;
- update engine;
- restart o gestione di host remoti tramite Agent Linux;
- NAT discovery;
- P2P;
- relay;
- control plane multi-server.

Il self-healing non modifica la limitazione CGNAT del progetto.
