# Integrazione frontend GE360

Ogni frontend deve avere una pagina `Connessione Bridge` con almeno:

- tunnel WireGuard: attivo/non attivo;
- URL health: `http://10.88.0.1:8788/v1/status`;
- latenza health;
- nome dispositivo e VPN IP restituiti dal Bridge;
- servizi autorizzati;
- test separato del backend applicativo;
- ultimo errore con distinzione tra `VPN_DOWN`, `BRIDGE_UNREACHABLE`, `SERVICE_NOT_ALLOWED`, `BACKEND_UNREACHABLE`.

Il test Bridge e il test backend devono essere separati: un tunnel sano non implica che FastAPI sia in ascolto, e un backend locale sano non implica che il telefono abbia stabilito WireGuard.
