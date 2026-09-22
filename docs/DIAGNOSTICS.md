# Diagnostica avanzata — Fase 6

La Fase 6 aggiunge test manuali e istantanei per capire dove si interrompe una comunicazione GE360.

Non classifica automaticamente la causa e non conserva storico. La classificazione automatica appartiene alla Fase 7.

## Test disponibili

Per una Resource il Bridge può eseguire:

- ping del Bridge `10.88.0.1`;
- ping del backend/target;
- test TCP del target;
- test API HTTP/HTTPS;
- test PDF;
- risoluzione DNS;
- traceroute del target.

## Comando completo

```bash
ge360-bridge diagnose-resource rilievi
```

Con API specifica:

```bash
ge360-bridge diagnose-resource rilievi --api-path /healthz
```

Con PDF:

```bash
ge360-bridge diagnose-resource rilievi \
  --api-path /healthz \
  --pdf-path /api/report/123.pdf
```

Senza traceroute:

```bash
ge360-bridge diagnose-resource rilievi --no-traceroute
```

## Sicurezza URL

I test API/PDF non accettano destinazioni arbitrarie.

Sono ammessi:

- percorsi relativi della Resource, ad esempio `/healthz`;
- URL completi soltanto se host e porta coincidono esattamente con il target registrato della Resource.

Questo mantiene il guardrail loopback già presente nel Resource Registry.

## Test PDF

Il test PDF controlla separatamente:

- raggiungibilità;
- status HTTP;
- `Content-Type`;
- `Content-Length`;
- firma reale del file `%PDF-`.

Un server che risponde `Content-Type: application/pdf` ma restituisce HTML fallisce il test.

Il Bridge legge soltanto l'inizio del file necessario alla verifica e non salva il PDF.

## Test API

Il test API riporta:

- status code;
- Content-Type;
- latenza;
- validità JSON;
- piccola preview della risposta;
- eventuale errore TLS/HTTP.

La preview non viene persistita.

## DNS

La risoluzione DNS usa il resolver del sistema Linux e restituisce gli indirizzi IPv4/IPv6 trovati.

## Ping e traceroute

L'installer aggiunge:

- `iputils-ping`;
- `traceroute`.

I risultati sono istantanei e non vengono registrati in un database.

## Dashboard

Nella pagina di ogni Resource compare il pannello **Diagnostica avanzata · Fase 6**.

È possibile inserire:

- percorso API;
- percorso PDF;
- inclusione/esclusione traceroute.

Il risultato mostra ogni test separatamente e il JSON completo.

## Limite intenzionale

La Fase 6 non produce etichette diagnostiche automatiche come:

- `VPN_DOWN`;
- `BACKEND_DOWN`;
- `PDF_URL_INVALID`;
- `PORT_CONFLICT`.

Queste appartengono alla Fase 7 — Connection Doctor.
