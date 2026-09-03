# I flussi della sincronizzazione peer-to-peer

> Complemento a [SYNC_STRATEGY.md](SYNC_STRATEGY.md), che spiega **perché** le
> cose stanno così. Qui c'è **come si muovono**, in diagrammi. Il codice sta
> in [`passlib::sync`](../passlib/src/sync/) per la regola di merge e in
> [`pass-agent/src/sync/`](../pass-agent/src/sync/) per tutto ciò che tocca il
> mondo esterno.

---

## 1. Gli strati, e in che verso scorrono

Il vault resta un file KDBX4 che KeePassXC apre: l'op-log è un *changelog
davanti* al vault, non il formato di archiviazione. Cancellalo e non perdi
niente se non la capacità di rispondere in fretta a "cos'è cambiato da quando
il tuo version vector diceva 7".

```mermaid
flowchart TB
    subgraph device["Un dispositivo"]
        direction TB
        V[("vault.kdbx<br/>la verità su disco")]
        B["bridge<br/>ingest / materialise"]
        R[("op-log + stato LWW<br/>la replica")]
        MK["marks<br/>dove vault e op-log<br/>si sono trovati d'accordo"]
        N["node<br/>5 endpoint + anti-entropia"]

        V -->|"ingest: contenuto cambiato<br/>rispetto al mark"| B
        B -->|"op firmato e sigillato"| R
        R -->|"il vincitore del merge"| B
        B -->|"materialise: scrive nel vault"| V
        MK -.-> B
        R <--> N
    end

    N <--> P(["altri dispositivi<br/>HTTP/1.1, JSON"])

    style V fill:#e8f0fe,stroke:#4a6fa5
    style R fill:#e8f0fe,stroke:#4a6fa5
    style MK fill:#fff4e5,stroke:#b8860b
```

I `marks` non sono decorazione: sono l'unica cosa che impedisce alle due
direzioni di rincorrersi. Vedi §4.

---

## 2. Un round di anti-entropia

Simmetrico e senza stato condiviso. Gira identico su ogni piattaforma,
compresi i client che non possono essere *chiamati* — un iPhone in background
non tiene un listener aperto, quindi guida lui i propri round.

```mermaid
sequenceDiagram
    autonumber
    participant A as Nodo A
    participant B as Nodo B

    Note over A: prima di parlare, pubblica<br/>le modifiche locali (vault pass)

    A->>B: GET /v1/node
    B-->>A: proto, device_id, hostname, services, key_check
    Note over A: controlla versione di protocollo,<br/>che non sia sé stesso,<br/>e che la chiave di sync coincida

    A->>B: POST /v1/ops/since {vv di A}
    B-->>A: gli op che ad A mancano
    Note over A: verifica firma e roster,<br/>applica, fonde con LWW

    A->>B: GET /v1/vv
    B-->>A: vv di B
    Note over A: chiesto DOPO il pull,<br/>così ciò che ha appena imparato<br/>riparte nello stesso round
    A->>B: POST /v1/ops {ciò che manca a B}
    B-->>A: applied, refused, vv

    A->>B: POST /v1/peers {i peer che A conosce}
    B-->>A: l'unione delle due liste

    Note over A: scrive nel vault ciò che è arrivato<br/>(vault pass), poi persiste
```

**Il verso doppio del peer exchange non è ridondanza.** Se A non contatta mai
B, A non impara mai che B esiste, e un terzo nodo che parte da A resta cieco
su B: la scoperta dipenderebbe dall'ordine di avvio.

**La correttezza sta nel round periodico, non nelle notifiche.** Un push che
si perde, un peer spento, una rete che torna dopo venti minuti: il round dopo
riconcilia comunque, perché è un confronto completo di version vector e non un
aggiornamento incrementale che qualcuno deve ricevere.

---

## 3. Il passaggio sul vault

Aprire il vault è Argon2id a 64 MiB — centinaia di millisecondi *per
costruzione*. Quindi non si apre se non c'è motivo: a regime un round non
costa nessun lavoro sul vault.

```mermaid
flowchart TD
    S(["inizio del vault pass"]) --> ST["stat del vault<br/><b>prima</b> di aprirlo"]
    ST --> Q1{"il tempo di modifica<br/>è diverso da quello visto?"}
    Q1 -->|sì| ING["serve ingest"]
    Q1 -->|no| Q2
    ING --> Q2{"sono arrivati op<br/>dai peer?"}
    Q2 -->|sì| MAT["serve materialise"]
    Q2 -->|no| Q3
    MAT --> OPEN
    Q3{"serve qualcosa?"} -->|no| END(["esci senza aprire il vault"])
    Q3 -->|sì| OPEN["apri il vault<br/>senza toccare il timer di auto-lock"]

    OPEN --> RO["aggiorna il roster dal vault"]
    RO --> I{"ingest?"}
    I -->|sì| I1["per ogni entry: hash del contenuto<br/>diverso dal mark → conia un op"]
    I -->|no| M
    I1 --> M{"materialise?"}
    M -->|no| OK
    M -->|sì| M1["stage dei mark<br/>scrivi i vincitori nel vault"]
    M1 --> CH{"qualcosa è cambiato?"}
    CH -->|no| COMMIT
    CH -->|sì| RACE{"il file è cambiato<br/>mentre lavoravamo?"}
    RACE -->|sì| BACK["lascia stare e ritenta<br/>al round dopo:<br/>i mark restano com'erano"]
    RACE -->|no| SAVE["salva il vault"]
    SAVE --> COMMIT["conferma i mark"]
    COMMIT --> OK(["fatto"])

    style BACK fill:#fde8e8,stroke:#b04
    style ST fill:#fff4e5,stroke:#b8860b
```

Due dettagli che sembrano paranoia e sono cicatrici:

- **Lo `stat` va fatto prima di aprire il vault, non dopo.** Farlo dopo perde
  scritture: un `pass add` che atterra *durante* il passaggio lascia un tempo
  di modifica che il passaggio registra come "già visto", pur avendo letto una
  versione precedente. Da lì in poi quella entry non viene pubblicata mai —
  non in ritardo, mai — finché qualcos'altro non tocca il file.
- **Il passaggio non tocca il timer di inattività.** L'auto-lock è una
  proprietà di sicurezza: una funzione di sfondo non deve poterla sospendere.

---

## 4. Perché le due direzioni non si rincorrono

Entrambe scattano sulla stessa osservazione — "vault e op-log non sono
d'accordo su questa entry". Senza un arbitro, due dispositivi si rimbalzano
una entry all'infinito: A scrive nel proprio vault la modifica di B, il che
cambia il tempo di modifica KDBX, il che sembra una modifica locale fresca,
che A ripubblica a B, e via.

Non è un'ipotesi: è esattamente ciò che si ottiene confrontando i timestamp,
perché scrivere una modifica remota **è** una scrittura locale per il KDBX.

```mermaid
flowchart LR
    subgraph senza["Senza mark — il ping-pong"]
        direction TB
        A1["B modifica"] --> A2["A scrive nel vault"]
        A2 --> A3["mtime del vault cambia"]
        A3 --> A4["sembra una modifica<br/>locale di A"]
        A4 --> A5["A ripubblica a B"]
        A5 --> A6["B scrive nel vault"]
        A6 --> A3
    end

    subgraph con["Con i mark"]
        direction TB
        B1["mark = hash del contenuto<br/>+ HLC vincente"] --> B2{"ingest:<br/>contenuto ≠ mark?"}
        B2 -->|no| B3["non conia niente"]
        B1 --> B4{"materialise:<br/>HLC vincente ≠ mark?"}
        B4 -->|no| B5["non scrive niente"]
    end

    style senza fill:#fde8e8,stroke:#b04
    style con fill:#e8f6ea,stroke:#2a7
```

Il mark è **l'hash del contenuto**, non un timestamp: dopo aver scritto la
modifica di un peer il contenuto coincide con il mark, quindi l'ingest non
conia nulla. I mark sono bookkeeping locale e non vengono mai replicati —
dicono cosa ha riconciliato *questo* dispositivo, che è una domanda diversa da
su cosa sono d'accordo le repliche.

---

## 5. Come si risolve un conflitto

Due dispositivi modificano la stessa entry mentre sono scollegati. Vince
l'HLC più alto, e l'ordinamento è `(millis, counter, device)`: il device in
coda è il tie-break deterministico, senza il quale due dispositivi che
scrivono nello stesso millisecondo sceglierebbero vincitori diversi e non
convergerebbero mai.

```mermaid
sequenceDiagram
    autonumber
    participant A as Nodo A
    participant B as Nodo B

    Note over A,B: stessa entry, nessun contatto

    A->>A: op seq 4, hlc 1000.0.A, from-a
    B->>B: op seq 7, hlc 1002.0.B, from-b

    Note over A,B: tornano in contatto

    A->>B: POST /v1/ops [op di A]
    Note over B: 1002.0.B batte 1000.0.A, B resta su from-b
    B->>A: POST /v1/ops [op di B]
    Note over A: 1002.0.B batte 1000.0.A, A passa a from-b

    Note over A,B: stesso vincitore, stesso fingerprint
    Note over A: la password perdente resta<br/>nella cronologia KDBX
```

**Il perdente non è distrutto.** La scrittura passa da `Vault::update_entry`
come qualunque altra modifica, quindi la versione sovrascritta finisce nella
cronologia KDBX4 — visibile da `pass get` e da KeePassXC.

**Il fingerprint è lo strumento diagnostico.** È un hash della *decisione* di
merge — quale HLC ha vinto, cancellato o no — non del payload. Due repliche
convergenti stampano lo stesso valore: se `pass sync status` ne mostra due
diversi, il problema è il merge, non la rete.

---

## 6. Cosa succede a un op in arrivo

```mermaid
flowchart TD
    OP(["op ricevuto"]) --> SVC{"è del servizio giusto?"}
    SVC -->|no| R1(["WrongService"])
    SVC -->|sì| ROS{"il fingerprint del device<br/>è nel roster del vault?"}
    ROS -->|no| R2(["UntrustedDevice<br/>→ detto all'utente <b>una volta</b>:<br/>«esegui pass sync trust ...»"])
    ROS -->|sì| SIG{"la firma Ed25519 torna?"}
    SIG -->|no| R3(["BadSignature"])
    SIG -->|sì| CLK{"l'HLC dichiara<br/>il device dell'op?"}
    CLK -->|no| R4(["BadSignature<br/>un peer fidato ma scorretto<br/>non può prendere in prestito<br/>l'orologio di un altro"])
    CLK -->|sì| SEQ{"seq"}
    SEQ -->|"seq già visto"| R5(["Duplicate — normale<br/>a ogni round sano"])
    SEQ -->|"seq troppo avanti"| R6(["CausalGap — manca un op prima,<br/>lo riempie il round dopo"])
    SEQ -->|"seq atteso"| APP["assorbe l'HLC remoto,<br/>confronto LWW,<br/>appende all'op-log"]
    APP --> OK(["applicato"])

    style R2 fill:#fff4e5,stroke:#b8860b
    style R3 fill:#fde8e8,stroke:#b04
    style R4 fill:#fde8e8,stroke:#b04
    style OK fill:#e8f6ea,stroke:#2a7
```

Duplicati e buchi causali sono **silenziosi**: sono lo stato normale di un
round sano. Un op da un dispositivo non accoppiato **non** lo è — quello è un
utente che sta cercando di accoppiare, e va detto, o l'accoppiamento sembra
rotto. Ma va detto una volta sola, o il messaggio che conta annega nel rumore.

---

## 7. Scoperta: tre sorgenti, una che conta

```mermaid
flowchart TB
    subgraph fonti["Da dove arrivano i candidati"]
        direction LR
        BS["bootstrap<br/>--sync-peer host:porta"]
        TS["tailnet<br/>tailscale status --json"]
        PX["peer exchange<br/>la cache PEX"]
    end

    fonti --> T["lista dei target del round"]

    subgraph mesh["Perché il PEX è quello che conta"]
        direction LR
        C["C conosce solo A"] -->|"POST /v1/peers"| A2["A"]
        A2 -->|"l'unione: A + B"| C2["C ora conosce anche B"]
    end

    style PX fill:#e8f6ea,stroke:#2a7
    style mesh fill:#f6f6f6,stroke:#999
```

mDNS non è nell'elenco di proposito: il multicast non attraversa un router e
una tailnet non lo trasporta affatto, quindi il caso interessante — portatile
al bar, fisso a casa — è esattamente quello che mDNS non copre.

Dopo **un solo contatto** con un peer qualsiasi, un dispositivo conosce tutta
la mesh, e continua a conoscerla anche se domani Tailscale sparisce. È anche
il modo in cui un client che non vede `tailscaled` — un'app da App Store non
può parlare col suo socket — conosce la rete chiedendo a chiunque.

**Una porta per dispositivo, non per servizio.** Una porta convenzionale per
servizio costa N×M tentativi di connessione a ogni giro (6 device × 8 servizi
= 48 probe, quasi tutti in timeout) e collide: la 2283 identifica "qualcosa
che parla come Immich", non *il tuo* Immich. Qui `GET /v1/node` risponde con
tutti i servizi che quel dispositivo replica: N probe invece di N×M, e
aggiungere un servizio non tocca la scoperta.

---

## 8. Accoppiamento, e cosa vede chi

Due segreti fanno due lavori diversi. Confonderli è il modo classico di
costruire qualcosa che *sembra* cifrato e non autentica nessuno.

```mermaid
flowchart TB
    subgraph vault["Dentro il vault"]
        DK["chiave del dispositivo<br/>Ed25519 — <i>chi</i> ha scritto"]
        SK["chiave di sync<br/>32 byte — <i>cosa</i> dice"]
        RO["roster<br/>i device ammessi a scrivere"]
    end

    DK -->|firma| OP["op sul filo"]
    SK -->|sigilla il payload| OP
    RO -->|"verifica in arrivo"| OP

    OP --> W{"chi lo riceve"}
    W --> W1["peer accoppiato<br/>con il vault"]
    W --> W2["macchina sulla tailnet<br/>senza il vault"]

    W1 --> R1(["legge tutto,<br/>scrive nella propria replica"])
    W2 --> R2(["<b>non</b> legge il payload<br/><b>non</b> scrive: non sa firmare<br/>come nessun device del roster<br/><br/><b>vede</b> quali id sono cambiati,<br/>su che device e quando"])

    style R2 fill:#fff4e5,stroke:#b8860b
```

**L'accoppiamento è esplicito di proposito.** Fidarsi di chi si presenta
significherebbe che qualunque macchina in grado di raggiungere la porta può
cambiare le tue password: "è arrivato, quindi è mio" non è una decisione che
un password manager può prendere per conto tuo.

**Il trasporto è HTTP in chiaro, e non è una svista.** Riservatezza e
autenticità sono proprietà dell'*op*, non della connessione: è questo che
permette a una macchina sempre accesa e non fidata di fare da relay per
dispositivi che non sono mai svegli insieme. Un canale cifrato punto-a-punto
proteggerebbe *meno*, perché renderebbe il relay un partecipante fidato.

**Ciò che resta scoperto sono i metadati**, ed è scritto in
[SECURITY.md §6](../SECURITY.md) invece che nascosto: le richieste non sono
autenticate, quindi chiunque raggiunga la porta può scaricare l'op-log e
vedere quali UUID sono cambiati, su che dispositivo e quando. È il motivo per
cui la porta si lega all'indirizzo tailnet — o al loopback se la tailnet non
c'è — e mai a tutte le interfacce.

---

## 9. Il bug che l'`epoch` esiste per evitare

`seq` è monotono per dispositivo e i peer scartano gli op con un `seq` già
visto. Ripristina un dispositivo da un backup e il contatore torna indietro.

```mermaid
sequenceDiagram
    autonumber
    participant D as Dispositivo
    participant P as Peer

    D->>P: op seq 1, 2, 3
    Note over P: ha visto fino a 3

    Note over D: ripristino da un backup<br/>che si ferma a seq 1

    D->>P: op seq 2 ("password nuova")
    Note over P: 2 non supera 3, quindi già visto e scartato
    Note over D,P: in silenzio. Per sempre.<br/>Il sintomo arriva settimane dopo:<br/>«le password nuove non arrivano più»

    Note over D: l'agent confronta l'op-log<br/>con il massimo seq già pubblicato<br/>e apre una nuova epoch

    D->>P: op seq 1, device = fingerprint@nuova-epoch
    Note over P: replica mai vista → accettata
```

L'identità sul filo è quindi `<fingerprint>@<epoch>`. La **fiducia segue la
chiave, non l'epoch**, quindi un dispositivo ripristinato resta accoppiato
senza rifare niente. Costa una riga in più in ogni version vector e nient'altro.

---

## 10. Il ciclo di vita del nodo

```mermaid
stateDiagram-v2
    [*] --> Caricato: l'agent parte
    Caricato --> Disarmato: op-log e roster<br/>letti da disco

    Disarmato --> Armato: pass unlock<br/>crea chiave di sync e identità,<br/>ripara l'epoch se serve

    Armato --> Armato: round di anti-entropia
    Armato --> Bloccato: auto-lock per inattività<br/>o pass lock
    Bloccato --> Armato: pass unlock

    note right of Disarmato
        Non sa ancora chi è: non firma
        e non sigilla niente. Ma l'agent
        parte lo stesso — una sync mal
        configurata non deve impedire
        di servire ssh.
    end note

    note right of Bloccato
        Continua a verificare, accettare
        e ritrasmettere op per la mesh:
        la verifica delle firme usa solo
        chiavi pubbliche. Non può scrivere
        nel vault, e lo dice
        («in attesa di sblocco»).
    end note
```

Un dispositivo bloccato che continua a fare da relay è la ragione per cui una
macchina sempre accesa è utile in questa rete anche mentre nessuno la sta
usando.

---

## Provarlo

Due nodi sulla stessa macchina, senza avere due computer:

```bash
cargo build --release
./sync-two-nodes.sh        # prepara, accoppia, verifica, lascia gli agent accesi
./sync-two-nodes.sh stop   # ferma tutto e pulisce
```

Lo script è commentato con le tre trappole che rendono una prova locale
fuorviante: `PASS_STATE_DIR` separato per nodo, il vault del secondo nodo che
dev'essere una copia del primo presa **dopo** il primo `pass unlock`, e i
socket sotto `/tmp` per via del limite di ~108 caratteri sul path di un socket
Unix.
