# Confronto: `pass` vs `goldwarden`

> **Aggiornamento (settembre 2026).** I gap identificati in questo documento
> sono stati poi colmati, con l'eccezione deliberata di FIDO2. Vedi la
> [§7 "Stato dopo l'implementazione"](#7-stato-dopo-limplementazione) in fondo
> per cosa è cambiato e come. Le sezioni 1-6 restano l'analisi originale.


> Analisi comparativa tra questo progetto (`pass`, gestore password locale
> basato su file KDBX4) e [goldwarden](https://github.com/quexten/goldwarden)
> di quexten (client desktop compatibile Bitwarden/Vaultwarden).
>
> Nota: goldwarden non è stato clonato/ispezionato riga per riga in questa
> analisi; le informazioni sono ricavate dal README e dalla wiki/deepwiki
> pubblici del progetto. Verificare i dettagli più fini direttamente sul
> repository prima di prendere decisioni tecniche vincolanti.

## 1. Filosofia di fondo: modello radicalmente diverso

Il confronto più importante non è "feature per feature", ma di **modello
architetturale**:

| | `pass` | `goldwarden` |
|---|---|---|
| Modello | Vault **locale**, file singolo (`.kdbx`), nessun server richiesto | **Client** per un server Bitwarden/Vaultwarden esistente (self-hosted o cloud) |
| Sync | File-based (Nextcloud/qualsiasi sync di file) + merge applicativo | Via API Bitwarden verso il server (sync nativo multi-device) |
| Dipendenza da infrastruttura | Nessuna: funziona offline, per sempre, senza account | Richiede un'istanza Bitwarden/Vaultwarden raggiungibile (anche self-hosted) |
| Formato dati | KDBX4 standard, apribile da KeePassXC | Formato vault Bitwarden proprietario (tramite API) |

In sostanza: `pass` è un **gestore di password autonomo e interoperabile**
(formato aperto KDBX4), mentre `goldwarden` è un **client alternativo per
l'ecosistema Bitwarden**, pensato per aggiungere funzionalità desktop
avanzate a un server che deve comunque esistere altrove. Non sono
sostituibili 1:1: scegliere l'uno o l'altro dipende da se si vuole un vault
locale indipendente o un client avanzato per un ecosistema Bitwarden già in uso.

## 2. Stack tecnico

| | `pass` | `goldwarden` |
|---|---|---|
| Linguaggio principale | Rust (workspace multi-crate) | Go (daemon core) + Python/GTK (GUI) |
| Componenti | `passlib` (core), `passcli`, `passlib_ffi` (FFI/C), `pass-native-host`, `pass-gnome`, `pass-apple` | Daemon Go + GUI Python-GTK, comunicazione via IPC |
| Librerie crittografiche chiave | `keepass` crate (KDBX4), Argon2id, ChaCha20, `zeroize` | `tink-crypto`, `memguard` (memory hardening), `go-libfido2`, `go-touchid` |
| Maturità dichiarata | In sviluppo attivo; client macOS/iOS esplicitamente **non verificato** (nessun ambiente Apple disponibile in fase di build) | **Sviluppo sospeso indefinitamente** dall'autore; molte funzionalità sono state "upstreamate" nei client Bitwarden ufficiali |

Punto degno di nota: `goldwarden` è dichiarato dal proprio autore come
progetto con sviluppo fermo, perché diverse feature che lo motivavano
(SSH item, SSH-agent, memory security, biometric unlock su Linux) sono
state assorbite dai client ufficiali Bitwarden. Questo è un segnale
rilevante se si valuta `goldwarden` come dipendenza a lungo termine.

## 3. Sicurezza — cosa protegge ciascuno

| Meccanismo | `pass` | `goldwarden` |
|---|---|---|
| Cifratura a riposo | AES-256 (KDBX4, outer) + HMAC-SHA256 (block auth) + ChaCha20 (campi protetti in memoria) | Cifratura del vault gestita lato protocollo Bitwarden; vault mantenuto cifrato in memoria e decifrato solo brevemente all'uso |
| KDF | Argon2id (memory-hard) | Eredita il KDF configurato lato account Bitwarden (tipicamente PBKDF2/Argon2id, a seconda del server) |
| Hardening memoria | `zeroize` per wiping automatico | `memguard` per protezione memoria a livello kernel + contromisure anti memory-dump — più aggressivo di `pass` su questo fronte |
| Autenticazione biometrica | Non presente | Sì — implementa il protocollo biometrico delle estensioni browser Bitwarden, incluso su Linux (dove Bitwarden ufficiale storicamente non la offriva) |
| FIDO2/WebAuthn | Non presente | Sì, supportato |
| Audit di sicurezza | Nessuno — dichiarato esplicitamente nel README (`⚠️ Disclaimer`) | Non dichiarato esplicitamente nelle fonti consultate |

Sintesi: `goldwarden` investe di più in **hardening runtime** (memguard,
anti-dump, biometria, FIDO2) perché deve proteggere segreti che restano
in memoria durante l'uso continuativo come agente di sistema. `pass`
investe di più nella **robustezza del formato a riposo** (KDBX4 standard,
verificato bidirezionalmente contro KeePassXC reale) ma non ha ancora
hardening di memoria avanzato oltre `zeroize`, né biometria/FIDO2.

## 4. Funzionalità — gap analysis

### Cosa ha `goldwarden` che `pass` non ha

- **SSH Agent integrato**: chiavi SSH custodite nel vault, usabili per
  login SSH e per firma commit Git (`git commit -S`) senza chiavi su disco.
- **Autotype di sistema**: digitazione automatica delle credenziali in
  qualsiasi applicazione (Linux X11/Wayland via portale `remotedesktop`,
  macOS, Windows) — funzionalità che `pass` non offre affatto (nel
  roadmap di `pass` c'è solo "clipboard con auto-clear", non autotype).
- **Iniezione variabili d'ambiente da CLI**: possibilità di iniettare
  segreti del vault come env var nel processo di un comando (utile per
  CI locali/script con API key), assente in `pass`.
- **Biometria per l'estensione browser**: sblocco biometrico
  dell'estensione Bitwarden su Linux.
- **FIDO2/WebAuthn** come fattore di sblocco/login.
- **Sync nativo multi-device via server**: sincronizzazione in tempo
  reale attraverso il server Bitwarden/Vaultwarden, senza dover gestire
  file e merge manualmente.

### Cosa ha `pass` che `goldwarden` non ha (o non enfatizza)

- **Nessuna infrastruttura richiesta**: vault locale, zero server, zero
  account — funziona anche completamente offline per sempre.
- **Formato KDBX4 standard e verificato**: interoperabilità reale e
  bidirezionale con KeePassXC (verificata con `keepassxc-cli` reale, non
  solo teorica), quindi portabile anche fuori dall'ecosistema Bitwarden.
- **Merge multi-device senza server proprietario**: `pass merge` /
  `pass watch` sfruttano `keepass::Database::merge` su un file
  sincronizzato da un qualsiasi strumento di file-sync (Nextcloud, ecc.),
  senza dipendere da un backend Bitwarden/Vaultwarden.
- **Client nativi multi-piattaforma "ricchi" oltre CLI**: GNOME/GTK4
  nativo (Rust diretto, no FFI), estensione Chromium con native
  messaging host, app SwiftUI condivisa macOS/iOS (quest'ultima non
  verificata). `goldwarden` è invece Linux-first, con build Mac/Windows
  esplicitamente "somewhat feature-stripped" e non testate.
- **TOTP/MFA integrato nel formato KDBX**: generazione codici TOTP
  (RFC 6238) salvati con la stessa convenzione `otp` di KeePassXC,
  quindi leggibili/scrivibili in modo intercambiabile da entrambi i tool.
- **Sviluppo attivo**, contro lo sviluppo sospeso indefinitamente
  dichiarato dall'autore di `goldwarden`.

### Funzionalità presenti in entrambi (con enfasi diversa)

- **Estensione browser**: entrambi la offrono, ma con approcci diversi —
  `pass` parla con un native messaging host locale che opera sullo stesso
  vault file; `goldwarden` implementa il protocollo nativo
  dell'estensione Bitwarden (incluso lo sblocco biometrico via quel
  protocollo).
- **CLI**: entrambi hanno una CLI completa; quella di `goldwarden`
  aggiunge l'iniezione env-var, quella di `pass` è più orientata a
  CRUD/interactive mode sul vault locale.

## 5. Cosa manca a `pass` rispetto a `goldwarden` (gap prioritari)

Se l'obiettivo fosse "colmare il gap" con `goldwarden`, i gap più
significativi in ordine di impatto/probabile costo di implementazione
sono:

1. **SSH Agent** — feature ad alto valore percepito (sostituisce
   `ssh-agent`/`gpg-agent` con il vault come sorgente di chiavi). Impatto
   alto, complessità media-alta (protocollo `ssh-agent` + FFI verso `passlib`).
2. **Autotype di sistema** — già annotato nel roadmap di `pass` solo come
   "clipboard con auto-clear"; l'autotype vero e proprio è più invasivo
   (richiede portali di sistema o hook a basso livello) e non è
   attualmente pianificato.
3. **Hardening di memoria avanzato** (equivalente `memguard`) — oggi
   `pass` si affida solo a `zeroize`; manca protezione anti-dump/mlock
   esplicita.
4. **Biometria / FIDO2 come fattore di sblocco** — assente in `pass`,
   presente in `goldwarden` sia per il client sia per l'estensione browser.
5. **Iniezione env-var da CLI** — feature piccola e a basso costo,
   utile per workflow da terminale/script.

Questi sono gap reali, ma vanno letti nel contesto: `goldwarden` li ha
costruiti *sopra* un client Bitwarden, mentre `pass` dovrebbe aggiungerli
a un vault locale KDBX4 — l'architettura sottostante resta diversa e
alcune di queste feature (specialmente SSH agent e autotype) sono
indipendenti dal fatto che il backend sia un server remoto o un file locale.

## 6. Conclusione

`pass` e `goldwarden` risolvono problemi diversi più che competere
direttamente:

- **`pass`** è la scelta giusta per chi vuole un vault **locale, aperto,
  verificabile e interoperabile** (KDBX4/KeePassXC), senza dipendere da
  un server, con sync opzionale "manuale" via file-sync.
- **`goldwarden`** è la scelta giusta per chi è già nell'ecosistema
  **Bitwarden/Vaultwarden** e vuole un client desktop Linux-first con
  funzionalità di sistema avanzate (SSH agent, autotype, biometria,
  FIDO2) che i client ufficiali storicamente non offrivano — con
  l'avvertenza che lo sviluppo è oggi fermo e molte di quelle feature
  sono confluite nei client ufficiali.

Il gap più "interessante" da colmare in `pass`, guardando a cosa lo
renderebbe competitivo anche per utenti power-user senza però tradire
la sua natura di vault locale, è **SSH Agent** seguito da un
**hardening di memoria più aggressivo** — entrambi indipendenti dal
modello client/server e quindi coerenti con l'architettura attuale.

---

Fonti consultate per `goldwarden` (README e wiki pubblici, non ispezione
diretta del codice):
- https://github.com/quexten/goldwarden
- https://github.com/quexten/goldwarden/blob/main/Readme.md
- https://deepwiki.com/quexten/goldwarden
- https://github.com/quexten/goldwarden/wiki/Browser-Biometric-Approval

---

## 7. Stato dopo l'implementazione

Le funzionalità di `goldwarden` mancanti a `pass` sono state implementate,
tranne FIDO2 (esclusa esplicitamente). Non è stato fatto un port: ognuna è
stata rimappata sull'architettura di `pass` — vault locale KDBX4, nessun
server — e in due casi il risultato è **più interoperabile** dell'originale.

### 7.1 Gap chiusi

| Gap (§4) | Come è stato chiuso | Verificato |
|---|---|---|
| **SSH Agent** | `pass-agent` implementa il protocollo OpenSSH agent su socket Unix, servendo chiavi dal vault. Le chiavi sono memorizzate nel formato **KeeAgent che usa KeePassXC** (allegato + campo `KeeAgent.settings`), non in un formato proprietario | Sì — test end-to-end contro `ssh-add -l`/`-L` reali, più verifica della firma contro la chiave pubblica |
| **Autotype di sistema** | `pass type`, pilotando lo strumento del desktop (`wtype`/`ydotool`/`xdotool`/AppleScript) | Parziale — logica di selezione backend e sequenze coperte da test; la digitazione reale richiede una sessione grafica |
| **Hardening memoria** (`memguard`) | `passlib::secmem`: `mlock` + `MADV_DONTDUMP` (via `memsec`) + `zeroize`, più `Shielded` che tiene i segreti **cifrati in RAM** e li decifra solo all'uso | Sì — test unitari, incluso che il ciphertext non contenga il plaintext |
| **Iniezione env-var** | `pass run --secret VAR=entry[:field] -- cmd`, con propagazione dell'exit code | Sì — test unitari sul parsing + smoke test end-to-end |
| **Biometria / PIN locale** | `pass quick-unlock`: password master sigillata con chiave Argon2id derivata dal PIN; `--verify-command` (es. `fprintd-verify`) come **secondo fattore prima** del PIN | PIN sì (test + smoke test). Il percorso biometrico non è verificabile qui: nessun lettore di impronte |

Extra non richiesti ma necessari a rendere il resto utilizzabile: agent con
auto-lock, generatore di password, prompt scriptabili (stdin non-tty).

### 7.2 Dove `pass` ora è avanti

- **Chiavi SSH interoperabili.** goldwarden le tiene negli SSH item di
  Bitwarden, leggibili solo da client Bitwarden. In `pass` sono nel formato
  KeeAgent: una chiave creata da `pass` compare nella tab "SSH Agent" di
  KeePassXC e viceversa.
- **Condivisione senza server** (`pass share`): goldwarden non ce l'ha
  affatto — la delega alle organizzazioni Bitwarden, quindi al server.
- **Agent read-only**: `ssh-add` non può aggiungere né cancellare chiavi,
  perché una chiave arrivata così vivrebbe fuori dal vault.
- **Sviluppo attivo**, contro lo sviluppo sospeso di goldwarden.

### 7.3 Cosa resta indietro, onestamente

- **FIDO2/WebAuthn**: escluso su richiesta. Resta l'unico gap funzionale.
- **Autotype su Wayland**: goldwarden usa il portale `remotedesktop`, che
  funziona su GNOME/KDE senza strumenti esterni. `pass` richiede `wtype` o
  `ydotool` installati. Scelta deliberata: linkare una libreria di input
  avrebbe aggiunto una dipendenza C (`libxdo`) all'intera CLI, rendendo
  impossibile *compilare il password manager* su una macchina che non ce
  l'ha, in cambio di una funzione che molti non usano mai.
- **RSA `rsa-sha2-256`**: l'agent firma RSA solo con SHA-512. Ed25519 (il
  default di `ssh-keygen` e di `pass ssh generate`) non è interessato.
- **Windows**: l'agent è solo Unix (socket Unix). Il protocollo e la sessione
  sono portabili; manca il trasporto su named pipe.
- **Biometria vera**: nessuna integrazione TouchID/Windows Hello. Su Linux il
  secondo fattore è un comando esterno, non un binding a hardware sicuro.

### 7.4 Un bug reale trovato lungo la strada

Memorizzare le chiavi SSH come allegati KDBX ha fatto emergere che
`keepass` 0.13 **non fonde gli allegati** (c'è un `TODO: attachments` nel suo
`merge_entry`). Per un vault di sole password è cosmetico; con le chiavi SSH
dentro, una entry portata da un merge arrivava con riferimenti a id di
allegati inesistenti e il primo accesso andava in panico.

Corretto in `Vault::merge_attachments`, con test di regressione — incluso il
caso non ovvio in cui `add_attachment` restituiva proprio l'id stantio che
stava sostituendo e cancellava l'allegato appena inserito.

### 7.5 Conclusione aggiornata

Il confronto di §6 resta valido nella sostanza — sono due modelli diversi —
ma la parte "goldwarden ha funzioni desktop che a `pass` mancano" non è più
vera, FIDO2 a parte. Quello che distingue i due progetti oggi è solo il
modello: **client di un server Bitwarden** contro **vault locale
interoperabile**.
