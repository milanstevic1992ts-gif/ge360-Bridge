# Resource Launcher — Fase 10

La Fase 10 aggiunge una home device-facing per aprire le Resource GE360 autorizzate.

## URL

Dentro il tunnel WireGuard:

```text
http://10.88.0.1:8788/hub
```

JSON equivalente:

```text
http://10.88.0.1:8788/v1/resources
```

## Sicurezza

Il Launcher usa l'IP VPN del peer per identificare il device.

Prima di rispondere verifica:

1. device registrato;
2. device attivo/non scaduto;
3. ACL dirette e gruppi;
4. Resource abilitata.

Una Resource non autorizzata **non viene inclusa** nel payload HTML/JSON.

## Card Resource

Ogni card contiene:

- icona;
- nome;
- descrizione;
- stato Health Engine;
- URL Bridge.

Per `http` e `https` viene mostrato **Apri**.

Per `tcp` viene mostrato solo l'endpoint perché un browser non può aprire genericamente una connessione TCP applicativa.

## Pairing

La risposta enrollment v2 include:

```json
{
  "launcher_url": "http://10.88.0.1:8788/hub"
}
```

## Compatibilità

`/v1/status` continua a esporre `resources` e `services`, e aggiunge `launcher_url`.

## Fuori scope

Il Launcher non configura automaticamente Android/VPN. SDK e connessione automatica appartengono alle Fasi 11 e 12.
