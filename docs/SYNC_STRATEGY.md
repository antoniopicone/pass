# Strategia di sincronizzazione e condivisione senza server

> Documento di design per `pass`. Descrive **cosa è già implementato**, **cosa
> è proposto** e — soprattutto — *perché*, dato che l'assenza di un server non
> è una limitazione da aggirare ma il vincolo che definisce il progetto.
>
> Per **come si muovono** i dati, in diagrammi: [SYNC_FLOWS.md](SYNC_FLOWS.md).

## 1. Il vincolo, e perché è una scelta

Bitwarden/Vaultwarden risolvono la sincronizzazione con un'autorità centrale: il
server conosce l'ordine degli eventi, arbitra i conflitti, distribuisce le
chiavi di collezione, revoca gli accessi. Tutto il resto discende da lì.

`pass` non ha quel server, e non deve averlo: il vault è un file KDBX4 e la sua
proprietà più preziosa è che **funziona senza infrastruttura, per sempre,
offline**. Un file che oggi apri con `pass` e KeePassXC lo aprirai fra dieci
anni anche se nessuno dei due progetti esiste più.

La conseguenza da accettare esplicitamente è che **senza autorità centrale non
esiste un ordinamento globale degli eventi**. Ogni strategia qui sotto è un modo
di convivere con questo fatto, non di nasconderlo.

## 2. I quattro livelli

La sincronizzazione non è un problema unico: sono quattro problemi diversi, che
si risolvono con meccanismi diversi e vanno tenuti separati.

| Livello | Problema | Stato |
|---|---|---|
| **L0 — Trasporto** | Far arrivare i byte da un dispositivo all'altro | ✅ Implementato (file-sync **e** peer-to-peer diretto) |
| **L1 — Riconciliazione** | Fondere due copie modificate in parallelo | ✅ Implementato (merge KDBX + fix allegati) |
| **L2 — Identità del dispositivo** | Sapere *quale* dispositivo ha scritto cosa | ✅ Implementato (roster nel vault, op firmati) |
| **L3 — Condivisione tra persone** | Dare una credenziale a qualcun altro | ✅ Implementato (share bundle) |

Il punto centrale del design: **L0 è intercambiabile**. Il trasporto è l'unica
parte che dipende dall'infrastruttura, ed è deliberatamente la parte più
sottile. Syncthing, Nextcloud, una chiavetta USB, `scp`, la LAN: cambia il
trasporto, il resto non si accorge di niente.

## 3. L0 — Trasporto

### 3.1 Oggi: file-sync generico (implementato)

```bash
# Il client Nextcloud/Syncthing sincronizza il file; pass lo fonde
pass watch ~/Nextcloud/vault.kdbx --publish ~/Nextcloud/vault.kdbx
```

`pass watch` osserva il file con gli eventi nativi del filesystem
(inotify/FSEvents/ReadDirectoryChangesW), fa il debounce della raffica di
eventi che un singolo salvataggio atomico produce, e rifonde a ogni cambiamento.

**Perché va bene**: nessun codice di rete da scrivere, da mantenere e da
mettere in sicurezza. Il file cifrato attraversa un servizio che non può
leggerlo — Nextcloud vede un blob KDBX4, e l'unica cosa che apprende è quando
lo modifichi.

**Dove si rompe**: il client di sync può creare file di conflitto
(`vault (conflicted copy).kdbx`). Non è un problema di correttezza — sono
comunque vault KDBX validi — ma oggi vanno fusi a mano.

> **Proposta L0.a — riconoscere i file di conflitto.**
> `pass watch` dovrebbe riconoscere i pattern di conflitto dei principali
> client (`*conflicted copy*`, `*.sync-conflict-*` di Syncthing,
> `*(conflict)*`), fonderli automaticamente e poi rimuoverli. È il caso più
> frequente in cui oggi l'utente deve intervenire, ed è interamente
> risolvibile con il merge che già esiste.

### 3.2 Sincronizzazione peer-to-peer diretta (L0.b) — implementata

Il trasporto via file-sync ha un difetto strutturale: **passa da un terzo**.
Anche se cifrato, il vault finisce su un server altrui, e la sincronizzazione
richiede che quel servizio funzioni.

`pass agent run --sync` elimina il terzo: i dispositivi che si raggiungono
parlano direttamente. Il codice sta in [`passlib::sync`](../passlib/src/sync/)
(la regola di merge) e in [`pass-agent/src/sync/`](../pass-agent/src/sync/)
(tutto ciò che tocca il mondo esterno).

**Cosa è cambiato rispetto alla proposta originale.** La proposta era: mDNS
per la scoperta, Noise `XX` per il canale, e "ogni lato manda il proprio KDBX
e fa `merge_entries`". Tre modifiche, ognuna per un motivo preciso.

1. **Niente mDNS.** Il multicast non attraversa un router e Tailscale non lo
   propaga affatto: il caso interessante — portatile al bar, fisso a casa — è
   esattamente quello che mDNS non copre. La scoperta usa tre sorgenti, in
   ordine crescente di indipendenza: un indirizzo di bootstrap configurato a
   mano, la tailnet (`tailscale status --json`), e — quella che conta — il
   **peer exchange bidirezionale**: dopo un solo contatto con un peer
   qualsiasi, un dispositivo conosce tutta la mesh e continua a conoscerla
   anche se domani Tailscale sparisce. Il verso singolo non basterebbe: se A
   non contatta mai B, A non impara mai che B esiste, e la scoperta
   dipenderebbe dall'ordine di avvio.

2. **Niente Noise, niente TLS: la sicurezza sta nell'op, non nella
   connessione.** Ogni op è *sigillato* con una chiave che esiste solo dentro
   il vault (XChaCha20-Poly1305) e *firmato* (Ed25519) da un dispositivo
   presente nel roster di quel vault. Il trasporto è HTTP/1.1 in chiaro su una
   porta legata all'indirizzo tailnet. Non è una svista: è ciò che permette a
   una macchina sempre accesa — un server di casa, il portatile di un'altra
   persona sulla stessa tailnet — di fare da **nodo di sovrapposizione** senza
   essere un punto di fiducia. Non può leggere ciò che inoltra, non può
   scrivere nella replica di nessuno, non può influenzare il merge. Un canale
   cifrato punto-a-punto proteggerebbe *meno*, perché renderebbe il relay un
   partecipante fidato.

3. **Niente scambio di KDBX interi: un op-log CRDT.** Mandare il file intero
   era la scelta giusta finché il trasporto era un file su Nextcloud. Fra due
   agent no: significherebbe rimandare qualche centinaio di kilobyte a ogni
   round di riconciliazione (ogni 30 secondi, per ogni peer), e soprattutto
   costringerebbe ogni peer ad avere la chiave del vault per fare qualcosa di
   utile. Con l'op-log si scambia solo il delta — "ho visto fino a 7, mandami
   il resto" — e il delta è opaco.

**La regola di merge.** HLC (Hybrid Logical Clock) + last-writer-wins per
entry, con i delete come tombstone che partecipano allo stesso LWW. L'HLC
ordina per `(millis, counter, device)`: il device in coda è il tie-break
deterministico, senza il quale due dispositivi che scrivono nello stesso
millisecondo sceglierebbero vincitori diversi e non convergerebbero mai. È
monotono anche se l'orologio di sistema torna indietro, e assorbe l'orologio
dei peer, così una macchina con l'ora avanti non vince per sempre.

Rispetto al merge KDBX di §4 questa è una regola *diversa*, e va detto
chiaramente: la risoluzione è al millisecondo invece che al secondo, e
l'ordinamento è causale invece che puramente temporale. Ma **il perdente
finisce comunque nella cronologia KDBX**, perché la scrittura passa da
`Vault::update_entry` come qualunque altra modifica. La rete di sicurezza è la
stessa.

**Il pairing è esplicito, e non è pigrizia.** Un dispositivo può scrivere nel
tuo vault solo dopo che l'hai messo nel roster con `pass sync trust`. Fidarsi
di chi si presenta significherebbe che qualunque macchina in grado di
raggiungere la porta può cambiare le tue password: "è arrivato, quindi è mio"
non è una decisione che un password manager può prendere per conto tuo.

**Il bug che l'`epoch` esiste per evitare.** `seq` è monotono per dispositivo
e i peer ignorano gli op con un `seq` già visto. Ripristina un dispositivo da
un backup e il suo contatore torna indietro: da quel momento ogni op che
scrive porta un `seq` che i peer considerano vecchio, e lo scartano — in
silenzio, per sempre, e il sintomo ("le password nuove non arrivano più al
portatile") si manifesta settimane dopo senza niente nei log. L'identità sul
filo è quindi `<fingerprint>@<epoch>`: l'agent si accorge del rewind
confrontando l'op-log con il massimo `seq` già pubblicato, e apre una nuova
epoch, che per gli altri è semplicemente una replica nuova. Costa una riga in
più in ogni version vector e niente altro.

**Cosa non fa.** Non replica le chiavi SSH né l'identità di condivisione:
quelle vivono nei gruppi del vault, viaggiano col file, e una chiave privata
SSH non è una cosa da mettere sul filo per una comodità. E non sostituisce
§3.1: due dispositivi che non sono mai accesi insieme non si raggiungono, e
lì serve ancora il file-sync (o un peer sempre acceso che faccia da relay).

### 3.3 Proposta: trasporto asincrono cifrato (L0.c)

Per i dispositivi che non si incontrano mai sulla LAN e per cui non si vuole un
servizio di file-sync, il formato armored di `passlib::share` è già un
trasporto: un blocco di testo che si incolla ovunque. La stessa costruzione può
sigillare **l'intero vault** per un altro proprio dispositivo, non solo singole
voci.

```bash
pass sync export --to laptop > vault.pass   # sigillato per quel dispositivo
pass sync import vault.pass                 # apre e fonde
```

Costa poco (riusa `share.rs`) e copre il caso "mandami il vault via Signal /
mettilo su una chiavetta" senza che il trasporto debba essere fidato.

## 4. L1 — Riconciliazione

### 4.1 Cosa garantisce già

Il merge è `keepass::Database::merge`, cioè **lo stesso algoritmo che usa
KeePassXC**. Riconcilia due copie usando il timestamp di ultima modifica di ogni
oggetto; le cancellazioni si propagano tramite il gruppo Recycle Bin (soft
delete), non con uno schema di tombstone proprietario.

Questo è deliberato e vale la pena dirlo esplicitamente: **non è stato inventato
un algoritmo di merge**. Un merge sbagliato in un password manager perde
credenziali in silenzio, ed è il tipo di bug che si scopre mesi dopo. Usare
quello che milioni di database KDBX già usano è una scelta di rischio, non di
pigrizia.

### 4.2 Un difetto reale, trovato e corretto

`keepass` 0.13 **non fonde gli allegati** — c'è un `TODO: attachments` letterale
nel suo `merge_entry`. Per un vault di sole password è cosmetico. Da quando
`pass` memorizza le **chiavi SSH come allegati** (nel formato KeePassXC/KeeAgent,
vedi `passlib::sshkey`) non lo è più: una entry portata dall'altro lato arriva
con riferimenti a id di allegati che esistevano solo *nell'altro* database, e
il primo tentativo di leggerla va in panico.

`Vault::merge_attachments` (in `passlib/src/vault.rs`) ripara questo: dopo il
merge riattacca i binari dal lato sorgente per ogni entry che il merge ha
risolto in favore della sorgente. Coperto da test di regressione, incluso il
caso — non ovvio — in cui `add_attachment` restituiva proprio l'id stantio che
stava sostituendo e cancellava l'allegato appena inserito.

### 4.3 Due regole di merge, e quando vale quale

Da §3.2 in poi ci sono **due** riconciliatori, e non sono lo stesso:

| trasporto | riconciliatore | risoluzione | ordinamento |
|---|---|---|---|
| file-sync (§3.1), `pass merge` | `keepass::Database::merge` | 1 secondo | timestamp |
| peer-to-peer (§3.2) | HLC + LWW su op-log | 1 millisecondo | causale |

Non si sovrappongono e non si azzuffano: il primo entra in gioco quando
arriva un *file*, il secondo quando arriva un *op*. Un dispositivo può usarli
entrambi (`pass watch` su Nextcloud **e** `pass agent run --sync`) senza che
si contraddicano, perché entrambi scrivono nel vault passando dagli stessi
`Vault::update_entry`/`delete_entry`, e la scrittura dell'uno diventa per
l'altro semplicemente una modifica locale da pubblicare al giro dopo.

Il paragrafo seguente riguarda il primo.

Il merge per timestamp ha una risoluzione di **un secondo** (è il formato KDBX,
non l'implementazione) e la regola è *last-writer-wins per campo*. Due
dispositivi che modificano la stessa entry entro lo stesso secondo producono un
esito arbitrario ma deterministico.

Nella pratica non è un problema — le persone non modificano la stessa password
su due dispositivi nello stesso secondo — ma **la cronologia KDBX4 salva la
versione perdente**, quindi il dato non è distrutto: `pass get` mostra la
cronologia delle password, e KeePassXC pure.

> **Proposta L1.a — riepilogo del merge non silenzioso.**
> Oggi `pass watch` stampa quante entry sono state create/aggiornate. Dovrebbe
> distinguere il caso "aggiornata perché l'altro lato era più recente" da
> "aggiornata sovrascrivendo una tua modifica più vecchia dello stesso secondo",
> e in quel secondo caso dire quale entry guardare in cronologia. È l'unico
> punto in cui il modello last-writer-wins può sorprendere qualcuno.

## 5. L2 — Identità del dispositivo (implementata)

Ogni dispositivo che replica il vault ha una chiave di firma Ed25519 e una
entry nel gruppo `Pass` del vault: etichetta, fingerprint, chiave pubblica,
epoch. L'insieme di quelle entry **è** il roster, cioè l'elenco dei
dispositivi autorizzati a scrivere nella replica. Si fonde come qualunque
altra entry, resta leggibile in KeePassXC, e non introduce nessuno stato
fuori dal vault.

```bash
pass sync devices    # chi può scrivere in questo vault
pass sync id         # la chiave di questo dispositivo, da leggere sull'altro
pass sync trust laptop 'pass-device-pk1:…'
pass sync forget vecchio-telefono
```

**Perché la chiave privata di dispositivo sta nel vault.** A prima vista è
sbagliato. Non lo è: chi ha il file e la password master ha già tutte le
password, quindi una chiave per-dispositivo nascosta a costui non
proteggerebbe niente. Quello da cui il roster protegge davvero è il caso che
esiste: una macchina sulla stessa tailnet che *non* ha il vault, che
raggiunge la porta di sync e viene rifiutata perché non sa firmare come
nessun dispositivo elencato.

**Cosa questo non è**: non è controllo d'accesso, e `pass sync forget` non è
una revoca. Impedisce a un dispositivo di scrivere da lì in avanti; non gli
toglie niente di ciò che ha già letto. Senza server la revoca reale si chiama
*cambiare le password*, e va detto all'utente invece di lasciar credere il
contrario — `pass sync forget` lo stampa esso stesso.

## 6. L3 — Condivisione tra persone (implementato)

`pass share` sigilla una o più entry per la chiave pubblica del destinatario e
produce un blocco di testo armored:

```bash
pass share init                                   # crea la tua identità
pass share add marta pass-share-pk1:AbC...        # ricorda la sua chiave
pass share export netflix --to marta > netflix.pass
pass share import netflix.pass                    # dall'altra parte
```

**Costruzione** (`passlib::share`): due scambi Diffie-Hellman X25519 mescolati
in un'unica chiave —

- `effimero × destinatario`, chiave nuova a ogni bundle, così compromettere in
  futuro la chiave d'identità del mittente non decifra i bundle già inviati;
- `mittente × destinatario`, che **autentica il mittente**: senza questo,
  chiunque conosca la chiave pubblica del destinatario potrebbe inviargli una
  credenziale spacciandosi per un'altra persona, che per un password manager è
  un attacco di phishing perfetto.

L'header del bundle è autenticato come AAD, quindi nessun campo pubblico può
essere scambiato senza far fallire il tag.

**I limiti, dichiarati**:

- **Non c'è revoca, e non può esserci.** Una volta che qualcuno ha visto una
  password, riprendersela significa *cambiarla*, non cancellare un file. Questo
  vale anche per Bitwarden: la differenza è che lì l'interfaccia lascia credere
  il contrario.
- **Non è una collezione condivisa viva.** Un bundle è una copia puntuale. Se la
  password cambia, va rimandato. Una collezione che resta sincronizzata fra
  persone diverse richiede un punto di incontro — cioè un server, o almeno un
  file condiviso a cui entrambi accedono, che è di nuovo L0.

## 7. La password master condivisa fra dispositivi

Il punto più scomodo, che nessuna delle strategie sopra elimina: **tutti i
dispositivi che sincronizzano lo stesso vault condividono la stessa password
master**, perché è la chiave del file.

Le conseguenze:

- cambiare la password master è un'operazione che va coordinata su tutti i
  dispositivi (un dispositivo con la vecchia password non aprirà più il file
  aggiornato, e le sue modifiche non potranno essere fuse);
- un dispositivo compromesso compromette il vault, non una sua fetta.

**Mitigazioni realistiche, in ordine di rapporto valore/costo:**

1. **Quick unlock per dispositivo** (✅ implementato, `pass quick-unlock`): la
   password master resta la chiave del file, ma sul singolo dispositivo si
   digita un PIN, sigillato con Argon2id. Il PIN è locale al dispositivo: due
   dispositivi possono avere PIN diversi, e disabilitarne uno non tocca gli
   altri. Non è una chiave separata, ma è la parte pratica del problema.
2. **Auto-lock aggressivo** (✅ implementato): l'agent tiene in memoria solo la
   password master cifrata in RAM e le chiavi SSH, e le cancella dopo il
   timeout di inattività.
3. **File chiave KDBX4 (proposta L2.a)**: KDBX4 supporta nativamente
   password + keyfile. Tenere il keyfile *fuori* dal canale di sincronizzazione
   (trasferito una volta a mano) fa sì che il vault sincronizzato su Nextcloud
   sia inutile a chi ottenga solo quello. È supportato dal formato, da
   KeePassXC, e oggi `pass` non lo espone: è probabilmente il singolo
   miglioramento di sicurezza col miglior rapporto costo/beneficio rimasto.

## 8. Confronto onesto con il modello Bitwarden/goldwarden

| | `pass` (serverless) | Bitwarden/Vaultwarden |
|---|---|---|
| Sincronizzazione | Eventuale, dipende dal trasporto | Quasi immediata, via server |
| Conflitti | Merge locale per timestamp, cronologia come rete di sicurezza | Arbitrati dal server |
| Condivisione | Bundle sigillati punto-a-punto, copie puntuali | Collezioni vive, con permessi |
| Revoca | Non esiste: si ruotano le password | Revoca dell'accesso (ma la copia già vista resta vista) |
| Dipendenze | Nessuna | Un'istanza raggiungibile |
| Superficie d'attacco remota | Nessuna | API del server, autenticazione, gestione sessioni |
| Costo di gestione | Zero | Aggiornamenti, backup, TLS, monitoraggio |

Il modello serverless è **strettamente peggiore** su immediatezza e
condivisione viva, e **strettamente migliore** su dipendenze, superficie
d'attacco e longevità. Non è un pareggio da vendere come tale: sono due scelte
per due esigenze diverse, e `pass` sceglie deliberatamente la seconda.

## 9. Roadmap proposta, in ordine di priorità

| # | Intervento | Costo | Valore |
|---|---|---|---|
| 1 | **Keyfile KDBX4** (§7.3) | Basso | Alto — separa il segreto dal canale di sync |
| 2 | **Auto-merge dei file di conflitto** (§3.1) | Basso | Alto — elimina l'unico intervento manuale ricorrente |
| 3 | **Riepilogo merge non silenzioso** (§4.3) | Basso | Medio — rende visibile l'unico caso sorprendente |
| ~~4~~ | ~~**Identità dispositivo** (§5)~~ | — | ✅ Fatto |
| ~~5~~ | ~~**Sync peer-to-peer diretta** (§3.2)~~ | — | ✅ Fatto |
| 6 | **Trasporto asincrono sigillato** (§3.3) | Basso | Medio — riusa `share.rs` |

L'ordine non è per attrattiva: i primi tre restano interventi piccoli su
problemi che gli utenti incontrano davvero oggi, e restano da fare.

### Cosa manca alla sync peer-to-peer

Onestamente, in ordine di quanto morde:

1. **Compaction dell'op-log.** Il log cresce e non viene mai potato: oggi
   ogni modifica resta lì per sempre. Potarlo richiede la *stabilità causale*
   (sapere che ogni peer ha visto un op prima di scartarlo), che a sua volta
   richiede l'eviction esplicita dei dispositivi persi. Per un vault
   personale sono kilobyte all'anno, quindi non è urgente — ma è la cosa che
   non scala.
2. **Persistenza su SQLite** invece di un file JSON riletto per intero
   all'avvio, per la stessa ragione.
3. **Scoperta sulla LAN senza Tailscale.** Oggi due macchine sulla stessa
   rete domestica senza Tailscale devono conoscersi tramite `--sync-peer`.
   mDNS *qui* avrebbe senso, come quarta sorgente accanto alle altre tre.
4. **Blocco del file del vault.** L'agent verifica il tempo di modifica prima
   di riscrivere il vault e si tira indietro se qualcun altro l'ha toccato,
   ma fra il controllo e il rename resta una finestra di millisecondi. Un
   lock file la chiuderebbe del tutto.
5. **Pairing con short authentication string.** Oggi si copia una chiave
   pubblica; sei parole della wordlist di `passlib::generator` confrontate a
   voce sarebbero più facili da verificare davvero.
