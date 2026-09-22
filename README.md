# GE360 Universal Bridge

Versione corrente: **v0.8 — Fase 6 completata: Diagnostica avanzata**. La Fase 7 è la prossima e non è ancora stata avviata.

La fonte di verità resta `docs/ROADMAP.md`.

## Diagnostica Fase 6

Per ogni Resource puoi verificare separatamente:

```text
Ping Bridge
Ping backend
TCP target
API
PDF
DNS
Traceroute
```

Esempio Rilievi:

```bash
ge360-bridge diagnose-resource rilievi \
  --api-path /healthz \
  --pdf-path /api/report/123.pdf
```

Il test PDF verifica anche la firma reale `%PDF-`, quindi distingue un PDF valido da una pagina HTML restituita per errore.

## Aggiornamento

```bash
cd ~/ge360-Bridge
git pull
sudo ./install.sh
```

La Fase 6 richiede anche `iputils-ping` e `traceroute`, installati automaticamente.

## Dashboard

Apri:

```text
http://127.0.0.1:8789
```

Poi entra nella Resource, per esempio `rilievi`, e usa **Diagnostica avanzata · Fase 6**.

## Guardrail

API e PDF possono puntare soltanto alla Resource selezionata. Il Bridge non usa la diagnostica per interrogare host arbitrari.

## Importante

La Fase 6 mostra i test separati ma non decide ancora automaticamente “qual è il problema”. Le categorie e la diagnosi automatica appartengono alla **Fase 7 — Connection Doctor**.

Vedi `docs/DIAGNOSTICS.md`.
