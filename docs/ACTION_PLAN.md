# Piano Architetturale e Suddivisione dei Lavori: Web Sanitiser

Il progetto sarà strutturato mantenendo una netta separazione tra una libreria riutilizzabile (`crate library`) che racchiude l'engine di sanificazione e un'applicazione a riga di comando (`crate binary`) che ne rappresenta il front-end.

## 1. Architettura del Sistema

Il software sarà suddiviso in quattro layer principali, progettati per garantire modularità, sicurezza della memoria e alte prestazioni.

### A. Input / IO Layer
* **Gestione Input**: Astrae la lettura da file locali, intere alberature di directory o fetch di URL remoti.
* **Sicurezza e Budgeting**: Implementa limiti stringenti sui timeout e sulle dimensioni massime per prevenire attacchi DoS come Slowloris, compression bombs o immagini giganti. Previene esplicitamente vulnerabilità di tipo SSRF e path-traversal durante la risoluzione delle risorse.

### B. Parsing & Sanitisation Layer
* **Parsing Zero-Copy**: Elabora i byte in input in modo sicuro tramite parser HTML esistenti (es. `lol_html`, `html5ever`), sfruttando semantiche zero-copy, prestito di dati (borrowing), copy-on-write e tokenizzatori in streaming per evitare allocazioni ridondanti.
* **Engine delle Regole**: Applica una sequenza di controlli guidati da una policy configurabile:
    * *Strutturali*: Rimozione di handler di eventi inline, tag `<script>` non in allow-list, URI `javascript:` o `data:`, iframe/object puntanti a origini non sicure e meta-refresh.
    * *Ispezione URL*: Estrazione e verifica dei link contro block-list (malware, tracker) e controllo di pattern omografi IDN o confusioni di normalizzazione Unicode. I link sospetti vengono riscritti, rimossi o sostituiti.
    * *Risorse Embedded*: Validazione del tipo di contenuto tramite sniffing del contenuto per evitare MIME confusion e ispezione dei file scaricati (es. codice attivo nei PDF) con limiti su profondità, byte e richieste.

### C. Concurrency & Scheduling Engine
* **Pipeline Concorrente**: Un pool di thread worker consuma gli input da una coda condivisa, mentre i risultati e i report confluiscono attraverso canali.
* **Stato Condiviso**: Gestione sicura di cache per URL risolti, statistiche e lookup di block-list tramite l'uso di primitive atomiche e lock (`Arc`, `Mutex`/`RwLock`).

### D. CLI & Policy Layer
* **Interfaccia Utente**: Gestisce la modalità batch, il livello di verbosità e restituisce codici di uscita non zero in caso di blocco totale del contenuto.
* **Configurazione**: Parsifica i file di configurazione dichiarativi che definiscono le policy di sanificazione.

---

## 2. Suddivisione dei Lavori (WBS Equa)

Le responsabilità vengono divise equamente lungo i due assi principali del progetto: la concorrenza/infrastruttura di I/O e il parsing sicuro/logica di sicurezza.

### 👤 Programmatore A: Infrastruttura, Concorrenza e I/O
Si occupa della gestione dei thread, della stabilità del sistema sotto carico e del recupero delle risorse.

* **Task A1: Struttura del Progetto e CLI**
    * Configurazione del workspace Cargo e separazione netta tra binary e library crate.
    * Sviluppo dell'interfaccia CLI (gestione batch, verbosità, caricamento policy e codici di uscita).
* **Task A2: Layer di Input e Network I/O**
    * Sviluppo dell'astrazione per file locali, scansione ricorsiva di directory e client HTTP.
    * Implementazione dei controlli di sicurezza di basso livello: mitigazione SSRF, prevenzione path-traversal e vincoli rigorosi su dimensioni/timeout (anti-DoS).
* **Task A3: Engine di Concorrenza**
    * Progettazione del pool di thread worker, della coda condivisa e dei canali di comunicazione per i report.
    * Sincronizzazione dello stato globale tramite `Arc`, `Mutex` o `RwLock` per cache e block-list.
* **Task A4: Benchmarking non funzionale**
    * Scrittura degli script automatizzati per misurare throughput, latenza, scalabilità sui core e impronta di memoria.

### 👤 Programmatore B: Parsing, Regele di Sicurezza e Sanificazione
Si occupa dell'ispezione dei contenuti all'interno della sandbox della memoria sicura di Rust.

* **Task B1: Layer di Parsing Zero-Copy**
    * Integrazione di un parser HTML sicuro (es. `lol_html`), assicurando l'uso di zero-copy e tokenizzatori in streaming.
    * Gestione dei vincoli di lifetime e dei buffer per permettere lo scambio sicuro di dati tra thread.
* **Task B2: Sviluppo delle Regole di Sanificazione HTML e URL**
    * Scrittura dei moduli per rimuovere o riscrivere costrutti HTML pericolosi (XSS, handler inline, script non in allow-list, iframe).
    * Estrazione e ispezione degli URL, implementazione dei controlli sulle block-list e mitigazione degli attacchi basati su omofoni IDN e normalizzazione Unicode.
* **Task B3: Analisi dei Contenuti e Risorse Avanzate**
    * Implementazione del content-sniffing contro la MIME confusion.
    * Analisi delle risorse sub-embedded e controllo dei file complessi (es. javascript nei PDF).
* **Task B4: Generazione Report e Corpus di Test**
    * Creazione della struttura dati ed emissione del report JSON (regola, posizione, frammento originale, rimpiazzo).
    * Raccolta di un corpus di test con campioni benigni e malevoli sintetici (XSS, link in block-list, malformati) per valutare la correttezza (rilevamento e falsi positivi).

---

## 3. Matrice delle Responsabilità e Tabella di Marcia

| Fase | Attività del Programmatore A | Attività del Programmatore B | Punto di Integrazione/Milestone |
| :--- | :--- | :--- | :--- |
| **1** | Setup del workspace CLI, lettura file/directory e scheletro delle Policy. | Scelta della libreria di parsing, setup iniziale dei tipi di dati dei Report e delle Policy. | **Milestone 1**: Applicazione CLI di base che legge un input e lo passa al parser. |
| **2** | Client HTTP sicuro con logiche anti-SSRF, limiti di budget e timeout. | Regole di pulizia dell'HTML (XSS, script, tag vietati) e content-sniffing. | **Milestone 2**: Il software è in grado di ripulire una singola pagina HTML locale o remota. |
| **3** | Sviluppo del Thread Pool concorrente, canali per i report e cache sincronizzate (`Arc`/`Mutex`). | Ispezione URL avanzata (block-list, Unicode) ed estrazione di codice dai PDF. | **Milestone 3**: **Integrazione Critica**: Risoluzione del passaggio di dati prestati (`lifetimes` vs `Arc<[u8]>`) tra pool e parser. |
| **4** | Suite di benchmark automatizzati e generazione grafici (Throughput/Scalabilità). | Creazione del corpus di test (benigni/payload) e verifica di correttezza e falsi positivi. | **Milestone 4**: Il sistema è stabile, sicuro (no panic) e i dati prestazionali sono pronti. |
| **5** | Relazione: sezioni Architettura, Concorrenza e Performance. | Relazione: sezioni Parsing, Memory Safety, Regole e Correttezza. | **Milestone 5**: Consegna del repository Git finale completo e della relazione di 15-25 pagine. |

---

## 4. Gestione dei Rischi e Aree di Collaborazione Stretta

Sebbene il lavoro sia distribuito in modo indipendente, i due programmatori dovranno obbligatoriamente collaborare attivamente su un punto cruciale del design in Rust: **il trasferimento degli stati del parser attraverso i thread**. 

Poiché il Programmatore B scriverà un parser basato su zero-copy (che prende in prestito i dati tramite reference e `lifetimes`), e il Programmatore A gestirà lo spostamento di questi dati all'interno di un thread pool (che richiede che i tipi implementino i trait `Send` e `Sync`), i due programmatori dovranno incontrarsi all'inizio della **Fase 3** per definire se utilizzare buffer di memoria prima allocati (come `Arc<[u8]>`) o come strutturare i dati in modo da gestire in modo sicuro l'ownership tra i thread.
