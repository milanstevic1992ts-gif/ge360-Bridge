# Resource Registry — Fase 4

Il Resource Registry sostituisce il concetto generico di "service" come modello autoritativo del Bridge.

File autoritativo:

```text
/etc/ge360-bridge/resources.json
```

Per compatibilità, `services.json` viene mantenuto come mirror sincronizzato durante la Fase 4.

## Schema Resource

Ogni Resource contiene:

```json
{
  "name": "rilievi",
  "icon": "ruler",
  "description": "GE360 Rilievi",
  "protocol": "http",
  "bridge_port": 9888,
  "target_host": "127.0.0.1",
  "target_port": 9888,
  "health_url": "/healthz",
  "timeout_seconds": 2.0,
  "allowed_devices": [],
  "denied_devices": [],
  "enabled": true
}
```

Il campo legacy `listen_port` viene mantenuto come alias della `bridge_port` per compatibilità.

## Migrazione

All'aggiornamento da v0.5, ogni vecchio record di `services.json` diventa automaticamente una Resource.

I campi già esistenti vengono preservati:

- nome;
- bridge/listen port;
- target host/port;
- allow/deny per device;
- enabled;
- riferimenti nei gruppi.

I nuovi metadati usano valori conservativi:

- `protocol=tcp`;
- `icon=server`;
- descrizione vuota;
- health URL vuota;
- timeout 2 secondi.

## CLI

Nuova Resource:

```bash
sudo ge360-bridge resource-add rilievi \
  --port 9888 \
  --target-host 127.0.0.1 \
  --target-port 9888 \
  --protocol http \
  --icon ruler \
  --description "GE360 Rilievi" \
  --health-url /healthz \
  --timeout 2
```

Modifica:

```bash
sudo ge360-bridge resource-update rilievi \
  --protocol http \
  --health-url /healthz \
  --timeout 3
```

Elenco:

```bash
ge360-bridge resource-list
```

Rimozione:

```bash
sudo ge360-bridge resource-remove rilievi
```

I comandi `service-add`, `service-remove`, `service-grant`, `service-revoke` e `service-inherit` restano disponibili come compatibilità.

## Protocollo

Valori ammessi:

- `tcp`;
- `http`;
- `https`.

In Fase 4 il protocollo è metadato della Resource. Il proxy continua a trasportare TCP come nelle fasi precedenti.

## Health URL e timeout

La Fase 4 registra e valida questi campi, ma **non esegue ancora un Health Engine HTTP/TLS**.

Sono ammessi:

- percorso relativo, ad esempio `/healthz`;
- URL `http://` o `https://` soltanto verso loopback e sulla stessa target port.

L'esecuzione dei controlli TCP/HTTP, la latenza e gli stati ONLINE/DEGRADED/OFFLINE appartengono alla Fase 5.

## ACL

Le ACL della Fase 2 restano invariate:

```text
deny diretto
> allow diretto
> gruppo
> nessun accesso
```

I gruppi continuano a essere retrocompatibili con `allowed_services`, ma espongono anche `allowed_resources`.
