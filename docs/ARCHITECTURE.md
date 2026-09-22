# Architettura GE360 Universal Bridge

GE360 Bridge è un gateway privato riutilizzabile per più frontend e più backend.

## Flusso

Android / laptop -> WireGuard UDP 51820 -> `wg0` (`10.88.0.1/24`) -> proxy TCP Bridge -> backend locale (`127.0.0.1:<porta>`).

Il backend non deve essere pubblicato su Internet. Il Bridge ascolta le porte applicative solo sull'IP WireGuard `10.88.0.1`.

## Server Only

`AllowedIPs` del client contiene solo `10.88.0.1/32`. Il Bridge non deve diventare una VPN per navigare su Internet e non deve dare accesso alla LAN. La chain nftables `forward_guard` scarta il forwarding proveniente da `wg0`.

## Servizi multipli

Ogni servizio registra:
- nome stabile;
- porta privata sul Bridge;
- target locale;
- dispositivi autorizzati.

Esempio: `rilievi` espone `10.88.0.1:9888` e inoltra a `127.0.0.1:9888` solo per i dispositivi autorizzati.

## Limite fisico: CGNAT

Una connessione completamente diretta richiede almeno uno tra IPv6 globale raggiungibile o IPv4 pubblica con port forwarding/UPnP. Se l'operatore usa CGNAT e non assegna IPv6 globale, non esiste un percorso Internet entrante verso il server domestico senza un nodo/relay esterno. Il Bridge deve segnalarlo chiaramente invece di fingere che la connessione sia configurata.
