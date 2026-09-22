# Connection Doctor — Fase 7

Il Connection Doctor trasforma i segnali già prodotti da WireGuard, ACL, Health Engine e Diagnostica Fase 6 in una classificazione deterministica.

Non esegue nuovi tipi di test di rete e non conserva storico.

## Categorie

Le categorie previste dalla roadmap sono:

- `VPN_DOWN`
- `BRIDGE_DOWN`
- `DEVICE_NOT_AUTHORIZED`
- `SERVICE_NOT_ALLOWED`
- `BACKEND_DOWN`
- `HTTP_ERROR`
- `PDF_URL_INVALID`
- `TIMEOUT`
- `PORT_CONFLICT`
- `ENDPOINT_INVALID`

Quando nessun problema viene rilevato il risultato è `OK`.

## Fonti usate

Il Doctor utilizza soltanto dati verificabili:

- presenza interfaccia `wg0`;
- stato systemd `ge360-bridge.service`;
- listener della bridge port;
- `PUBLIC_ENDPOINT`;
- Device Registry;
- ACL effettive Resource;
- handshake WireGuard del device;
- risultato Health Engine;
- risultato Diagnostica Fase 6.

## Precedenza

Una diagnosi può avere più finding contemporaneamente. La categoria primaria segue questa precedenza:

```text
BRIDGE_DOWN
PORT_CONFLICT
ENDPOINT_INVALID
DEVICE_NOT_AUTHORIZED
SERVICE_NOT_ALLOWED
VPN_DOWN
TIMEOUT
BACKEND_DOWN
PDF_URL_INVALID
HTTP_ERROR
```

I finding secondari restano visibili nel JSON.

## CLI

Diagnosi base:

```bash
ge360-bridge doctor rilievi
```

Con device:

```bash
ge360-bridge doctor rilievi --device telefono-milan
```

Con PDF:

```bash
ge360-bridge doctor rilievi \
  --device telefono-milan \
  --api-path /healthz \
  --pdf-path /api/report/123.pdf
```

## Dashboard

Il form Diagnostica della Resource accetta anche il device opzionale.

Dopo l'esecuzione mostra:

- categoria primaria;
- finding secondari;
- motivazione;
- evidenze;
- test Fase 6 completi.

## Nessuna speculazione

Il Doctor non deduce cause che non risultano dai segnali.

Per esempio:

- un PDF con `Content-Type: application/pdf` ma senza firma `%PDF-` produce `PDF_URL_INVALID`;
- target TCP non raggiungibile produce `BACKEND_DOWN`;
- HTTP 500 con TCP funzionante produce `HTTP_ERROR`;
- handshake vecchio oltre la soglia produce `VPN_DOWN`.

## Fuori scope

Audit log, metriche storiche e grafici appartengono alle Fasi 8 e 9.
