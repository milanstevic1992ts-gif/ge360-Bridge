# Health Engine — Fase 5

Il Health Engine controlla lo stato attuale delle Resource del GE360 Universal Bridge.

Non salva storico, non riavvia servizi e non esegue diagnostica di rete avanzata: queste funzioni appartengono alle fasi successive.

## Stati

Il motore restituisce esclusivamente gli stati previsti dalla roadmap:

- `ONLINE`: il controllo configurato è riuscito;
- `DEGRADED`: il transport risponde, ma il controllo applicativo è incompleto o non strutturato;
- `OFFLINE`: target TCP/HTTP non raggiungibile;
- `TIMEOUT`: timeout TCP o HTTP;
- `UNAUTHORIZED`: endpoint health HTTP risponde 401 o 403;
- `BAD_RESPONSE`: status HTTP non valido, JSON dichiarato ma malformato, errore TLS o risposta eccessiva.

## Controllo TCP

Ogni Resource viene prima verificata su:

```text
target_host:target_port
```

Viene misurata la latenza di connessione.

Per una Resource `protocol=tcp`, il successo TCP è sufficiente per `ONLINE`.

## HTTP / HTTPS

Per `protocol=http` o `protocol=https`:

- se `health_url` non è configurata, TCP funzionante produce `DEGRADED`;
- se `health_url` è configurata, viene eseguito `GET`;
- 2xx prosegue alla validazione del body;
- 401/403 produce `UNAUTHORIZED`;
- altri status non-2xx producono `BAD_RESPONSE`.

Il body health è limitato a 64 KiB.

## JSON

Se il server dichiara JSON tramite `Content-Type`, oppure la risposta ha forma JSON, il motore verifica che il body sia JSON valido.

- JSON valido + HTTP 2xx → `ONLINE`;
- JSON malformato → `BAD_RESPONSE`;
- body vuoto o risposta 2xx non JSON → `DEGRADED`.

Il motore **non interpreta semanticamente** campi applicativi come `ok`, `status` o altri valori: in Fase 5 valida struttura e trasporto senza inventare regole specifiche dei singoli backend.

## TLS

Per endpoint HTTPS viene usata la verifica TLS standard del sistema.

Il risultato espone, quando disponibile:

- versione TLS;
- cipher;
- esito verifica certificato.

Un certificato non verificabile produce `BAD_RESPONSE`.

## Timeout

Ogni Resource usa il proprio:

```json
"timeout_seconds": 2.0
```

Valori ammessi dal Resource Registry: 0.1–30 secondi.

## Cache

I risultati vengono mantenuti in memoria per pochi secondi per evitare richieste duplicate causate dal refresh contemporaneo di dashboard/API.

La cache:

- non è persistente;
- non è uno storico;
- non produce metriche temporali.

## CLI

Tutte le Resource:

```bash
ge360-bridge health-check
```

Una Resource:

```bash
ge360-bridge health-check rilievi
```

Forzare un nuovo controllo:

```bash
ge360-bridge health-check rilievi --no-cache
```

## API

La dashboard autenticata espone:

```text
GET /api/health
```

Il normale endpoint Bridge `/v1/status` include inoltre il blocco health delle sole Resource accessibili al device che effettua la richiesta.

## Fase successiva

Ping, DNS, traceroute, test PDF e strumenti diagnostici espliciti **non fanno parte del Health Engine**. Appartengono alla Fase 6.
