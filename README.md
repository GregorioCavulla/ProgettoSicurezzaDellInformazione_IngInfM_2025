
# Progetto Sicurezza Dell'Informazione – Ing. Informatica M (2025) / Passwordless Authentication System

Questo progetto è stato sviluppato come parte del corso di **Sicurezza Informatica** presso il corso di laurea in Ingegneria Informatica M anno accademico 2024/2025.
## Obiettivo

Dimostrare un sistema di autenticazione passwordless sicuro tra un client e un server, utilizzando token generati casualmente e chiavi pubbliche/privati. Il sistema include la registrazione di nuovi utenti utilizzando un supporto usb e l'autenticazione tramite challenge-response.

## Struttura del progetto

Progetto/\
│\
├── client/\
│   ├── client.py               # Client CLI per connessione al server\
│   ├── client\_gui.py          # Interfaccia grafica del client, in fase di testing\
│   └── rng\_token.txt          # Token RNG usato per autenticazione\
│\
├── server/\
│   ├── server.py               # Server TCP/HTTP per autenticazione\
│   ├── usb\_making\_tool.py    # Strumento per generare token USB\
│   ├── rng.json                # Configurazione/token RNG del server\
│   └── users.json              # Elenco degli utenti e credenziali\
│\
├── usb\_device/\
│   └── rng\_token.txt          # Copia/token associato al dispositivo USB\

## Requisiti

- Python 3.8+
- Librerie necessarie:
  - `cryptography` 
  - `flask`
  - `json`
  - `base64`
  - `os`
  - `secrets`
  - `requests`

## Istruzioni per l'uso

1. **Avvio del Server**
    ```bash
   cd server
   python server.py
    ````

2. **Creazione/Setup token USB**

   ```bash
   cd server
   python usb_making_tool.py
   ```

   Questo script genera il file `rng_token.txt` prendendo il token dal `RNG_DB` (`rng.json`) del server e, insieme alla chiave pubblica del server, lo salva su un dispositivo USB (simulato dalla directory `usb_device`).

3. **Avvio del Client (CLI)**

   ```bash
   cd client
   python client.py
   ```

## Flusso del server

1. Il server si avvia e inizializza le chiavi pubblica e privata, carica i database `rng.json` e `users.json`. Se non è presente il rng lo genera.
2. Il server attende la connessione di un client.
3. Ricevuta una richiesta di registrazione, il server verifica la validità del token inviato dal client, confrontandolo con il database `rng.json`, una volta fatto il confronto il server elimina il token già utilizzato e ne genera uno nuovo.
4. Se il token è valido, il server risponde con un messaggio di successo e registra l'utente nel database `users.json` associandogli la sua chiave pubblica. Se il token non è valido, il server risponde con un messaggio di errore.
5. Ricevuta una richiesta di challenge per l'autenticazione, il server genera un nonce e lo invia al client, quindi attende la risposta del client.
6. Alla ricezione della risposta, il server verifica la firma del nonce con la chiave pubblica del client. Se la firma è valida, il server risponde con un messaggio di successo, altrimenti risponde con un messaggio di errore.

Ogni volta che si vuole permettere a un client di registrarsi, il server deve generare un nuovo supporto usb con il nuovo token attraverso lo script `usb_making_tool.py`.

## Flusso del client

1. Il client si avvia, genera le proprie chiavi pubblica e privata e carica i file dal dispositivo USB (simulato dalla directory `usb_device`), in particolare il file `rng_token.txt`  e la chiave pubblica del server.
2. Il client quindi chiede all'utente di inserire il proprio username e chiede se vuole registrarsi o autenticarsi.
3. Se l'utente sceglie di registrarsi, il client invia al server il messaggio $S_{client}(E_{pub\_server}(rng\_token||pub\_client))$ e attende la risposta del server con il risultato della registrazione.
4. Se l'utente, precedentemente registrato, sceglie di autenticarsi, il client invia una richiesta di challenge al server e attende un nonce. Quindi firma il nonce con la propria chiave privata e invia la risposta al server.
5. Il client attende la risposta del server e visualizza il risultato dell'autenticazione.

## Note

* I file `.json` e `.txt` sono fondamentali per la gestione dei token e delle credenziali.
* Il supporto USB è simulato via filesystem, ma può essere adattato per dispositivi reali.



