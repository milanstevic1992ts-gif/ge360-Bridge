# Backend Auto Discovery — Fase 13

GE360 Bridge v0.15 introduce un discovery controllato dei backend locali.

## Contratto backend

Ogni backend GE360 che vuole essere rilevato espone:

    GET /.well-known/ge360
    Content-Type: application/json

Schema v1:

    {
      "schema": 1,
      "name": "GE360 Rilievi",
      "type": "rilievi",
      "version": "4.2",
      "health": "/healthz",
      "icon": "ruler",
      "description": "Backend rilievi GE360"
    }

Campi obbligatori: name, type, version, health.
schema, icon e description sono opzionali. schema, quando presente, deve essere 1.

type diventa il nome tecnico della Resource e deve rispettare le regole già usate dal Resource Registry.
health deve essere un percorso locale assoluto come /healthz: URL remoti, network-path, fragment e target LAN non sono accettati.

## Confine di rete

Il discovery automatico legge soltanto listener TCP IPv4 associati esattamente a 127.0.0.1 dal file /proc/net/tcp.
Non effettua scansioni della LAN, non prova subnet private e non modifica la configurazione di rete.

Per localhost o ::1 si possono indicare esplicitamente le porte dalla CLI. Anche in quel caso validate_target_host mantiene il target confinato al loopback.

Le porte di sistema Bridge 8788, 8789 e 8790 sono escluse dal discovery automatico.

## Proposta, non import automatico

Un manifest valido produce una proposta. Nessuna Resource viene creata durante la scansione.

Stati proposta:

- new: importabile;
- registered: Resource già presente sullo stesso target;
- name_conflict: stesso type già usato da un'altra Resource;
- target_registered: target già registrato con un altro nome;
- bridge_port_required: serve scegliere una bridge port libera.

L'import rilegge e rivalida il manifest prima di chiamare register_resource. Non esiste un secondo registry e resources.json resta autoritativo con services.json come mirror compatibile.

## CLI

Discovery sui listener loopback locali:

    ge360-bridge resource-discover

Discovery controllato su porte specifiche:

    ge360-bridge resource-discover --port 9888 --port 5366

Import dopo verifica del manifest:

    sudo ge360-bridge resource-import 9888

Se la target port non può essere riusata come bridge port:

    sudo ge360-bridge resource-import 9888 --bridge-port 9890

Opzioni disponibili: --host, --scheme e --timeout. Host non-loopback vengono rifiutati.

## Dashboard

La dashboard autenticata espone:

    /discovery
    /api/discovery

La pagina mostra i backend con manifest valido e consente un import esplicito. La scansione non importa automaticamente nulla.

## Sicurezza e limiti

- massimo 64 porte per esecuzione;
- massimo 8 probe concorrenti;
- timeout discovery 0.1..5 secondi;
- manifest massimo 16 KiB;
- Content-Type obbligatorio application/json;
- schema e campi validati rigidamente;
- nessuna sovrascrittura di Resource esistenti;
- nessuna scansione LAN;
- nessuna funzione Agent Linux, self-healing, NAT discovery o relay.

Il discovery non modifica la limitazione CGNAT del progetto: riguarda soltanto il riconoscimento dei backend locali dietro il Bridge.
