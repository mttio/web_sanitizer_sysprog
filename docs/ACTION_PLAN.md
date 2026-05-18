# Piano Architetturale e Suddivisione dei Lavori: Web Sanitiser

[span_0](start_span)[span_1](start_span)Il progetto sarà strutturato mantenendo una netta separazione tra una libreria riutilizzabile (`crate library`) che racchiude l'engine di sanificazione e un'applicazione a riga di comando (`crate binary`) che ne rappresenta il front-end[span_0](end_span)[span_1](end_span).

## 1. Architettura del Sistema

[span_2](start_span)[span_3](start_span)Il software sarà suddiviso in quattro layer principali, progettati per garantire modularità, sicurezza della memoria e alte prestazioni[span_2](end_span)[span_3](end_span).

### A. Input / IO Layer
* **[span_4](start_span)[span_5](start_span)Gestione Input**: Astrae la lettura da file locali, intere alberature di directory o fetch di URL remoti[span_4](end_span)[span_5](end_span).
* **[span_6](start_span)[span_7](start_span)Sicurezza e Budgeting**: Implementa limiti stringenti sui timeout e sulle dimensioni massime per prevenire attacchi DoS come Slowloris, compression bombs o immagini giganti[span_6](end_span)[span_7](end_span). [span_8](start_span)Previene esplicitamente vulnerabilità di tipo SSRF e path-traversal durante la risoluzione delle risorse[span_8](end_span).

### B. Parsing & Sanitisation Layer
* **[span_9](start_span)[span_10](start_span)Parsing Zero-Copy**: Elabora i byte in input in modo sicuro tramite parser HTML esistenti (es. `lol_html`, `html5ever`), sfruttando semantiche zero-copy, prestito di dati (borrowing), copy-on-write e tokenizzatori in streaming per evitare allocazioni ridondanti[span_9](end_span)[span_10](end_span).
* **[span_11](start_span)[span_12](start_span)Engine delle Regole**: Applica una sequenza di controlli guidati da una policy configurabile[span_11](end_span)[span_12](end_span):
    * *[span_13](start_span)Strutturali*: Rimozione di handler di eventi inline, tag `<script>` non in allow-list, URI `javascript:` o `data:`, iframe/object puntanti a origini non sicure e meta-refresh[span_13](end_span).
    * *[span_14](start_span)[span_15](start_span)Ispezione URL*: Estrazione e verifica dei link contro block-list (malware, tracker) e controllo di pattern omografi IDN o confusioni di normalizzazione Unicode[span_14](end_span)[span_15](end_span). [span_16](start_span)I link sospetti vengono riscritti, rimossi o sostituiti[span_16](end_span).
    * *[span_17](start_span)Risorse Embedded*: Validazione del tipo di contenuto tramite sniffing del contenuto per evitare MIME confusion[span_17](end_span) [span_18](start_span)[span_19](start_span)e ispezione dei file scaricati (es. codice attivo nei PDF) con limiti su profondità, byte e richieste[span_18](end_span)[span_19](end_span).

### C. Concurrency & Scheduling Engine
* **[span_20](start_span)Pipeline Concorrente**: Un pool di thread worker consuma gli input da una coda condivisa, mentre i risultati e i report confluiscono attraverso canali[span_20](end_span).
* **[span_21](start_span)Stato Condiviso**: Gestione sicura di cache per URL risolti, statistiche e lookup di block-list tramite l'uso di primitive atomiche e lock (`Arc`, `Mutex`/`RwLock`)[span_21](end_span).

### D. CLI & Policy Layer
* **[span_22](start_span)[span_23](start_span)Interfaccia Utente**: Gestisce la modalità batch, il livello di verbosità e restituisce codici di uscita non zero in caso di blocco totale del contenuto[span_22](end_span)[span_23](end_span).
* **[span_24](start_span)[span_25](start_span)Configurazione**: Parsifica i file di configurazione dichiarativi che definiscono le policy di sanificazione[span_24](end_span)[span_25](end_span).

---

## 2. Suddivisione dei Lavori (WBS Equa)

[span_26](start_span)[span_27](start_span)Le responsabilità vengono divise equamente lungo i due assi principali del progetto: la concorrenza/infrastruttura di I/O e il parsing sicuro/logica di sicurezza[span_26](end_span)[span_27](end_span).

### 👤 Programmatore A: Infrastruttura, Concorrenza e I/O
[span_28](start_span)[span_29](start_span)Si occupa della gestione dei thread, della stabilità del sistema sotto carico e del recupero delle risorse[span_28](end_span)[span_29](end_span).

* **Task A1: Struttura del Progetto e CLI**
    * [span_30](start_span)Configurazione del workspace Cargo e separazione netta tra binary e library crate[span_30](end_span).
    * [span_31](start_span)Sviluppo dell'interfaccia CLI (gestione batch, verbosità, caricamento policy e codici di uscita)[span_31](end_span).
* **Task A2: Layer di Input e Network I/O**
    * [span_32](start_span)[span_33](start_span)Sviluppo dell'astrazione per file locali, scansione ricorsiva di directory e client HTTP[span_32](end_span)[span_33](end_span).
    * [span_34](start_span)[span_35](start_span)Implementazione dei controlli di sicurezza di basso livello: mitigazione SSRF, prevenzione path-traversal e vincoli rigorosi su dimensioni/timeout (anti-DoS)[span_34](end_span)[span_35](end_span).
* **Task A3: Engine di Concorrenza**
    * [span_36](start_span)Progettazione del pool di thread worker, della coda condivisa e dei canali di comunicazione per i report[span_36](end_span).
    * [span_37](start_span)Sincronizzazione dello stato globale tramite `Arc`, `Mutex` o `RwLock` per cache e block-list[span_37](end_span).
* **Task A4: Benchmarking non funzionale**
    * [span_38](start_span)[span_39](start_span)[span_40](start_span)[span_41](start_span)Scrittura degli script automatizzati per misurare throughput, latenza, scalabilità sui core e impronta di memoria[span_38](end_span)[span_39](end_span)[span_40](end_span)[span_41](end_span).

### 👤 Programmatore B: Parsing, Regele di Sicurezza e Sanificazione
[span_42](start_span)[span_43](start_span)Si occupa dell'ispezione dei contenuti all'interno della sandbox della memoria sicura di Rust[span_42](end_span)[span_43](end_span).

* **Task B1: Layer di Parsing Zero-Copy**
    * [span_44](start_span)[span_45](start_span)Integrazione di un parser HTML sicuro (es. `lol_html`), assicurando l'uso di zero-copy e tokenizzatori in streaming[span_44](end_span)[span_45](end_span).
    * [span_46](start_span)Gestione dei vincoli di lifetime e dei buffer per permettere lo scambio sicuro di dati tra thread[span_46](end_span).
* **Task B2: Sviluppo delle Regole di Sanificazione HTML e URL**
    * [span_47](start_span)[span_48](start_span)Scrittura dei moduli per rimuovere o riscrivere costrutti HTML pericolosi (XSS, handler inline, script non in allow-list, iframe)[span_47](end_span)[span_48](end_span).
    * [span_49](start_span)[span_50](start_span)Estrazione e ispezione degli URL, implementazione dei controlli sulle block-list e mitigazione degli attacchi basati su omofoni IDN e normalizzazione Unicode[span_49](end_span)[span_50](end_span).
* **Task B3: Analisi dei Contenuti e Risorse Avanzate**
    * [span_51](start_span)Implementazione del content-sniffing contro la MIME confusion[span_51](end_span).
    * [span_52](start_span)[span_53](start_span)Analisi delle risorse sub-embedded e controllo dei file complessi (es. javascript nei PDF)[span_52](end_span)[span_53](end_span).
* **Task B4: Generazione Report e Corpus di Test**
    * [span_54](start_span)[span_55](start_span)Creazione della struttura dati ed emissione del report JSON (regola, posizione, frammento originale, rimpiazzo)[span_54](end_span)[span_55](end_span).
    * [span_56](start_span)Raccolta di un corpus di test con campioni benigni e malevoli sintetici (XSS, link in block-list, malformati) per valutare la correttezza (rilevamento e falsi positivi)[span_56](end_span).

---

## 3. Matrice delle Responsabilità e Tabella di Marcia

| Fase | Attività del Programmatore A | Attività del Programmatore B | Punto di Integrazione/Milestone |
| :--- | :--- | :--- | :--- |
| **1** | [span_57](start_span)[span_58](start_span)[span_59](start_span)Setup del workspace CLI, lettura file/directory e scheletro delle Policy[span_57](end_span)[span_58](end_span)[span_59](end_span). | [span_60](start_span)[span_61](start_span)Scelta della libreria di parsing, setup iniziale dei tipi di dati dei Report e delle Policy[span_60](end_span)[span_61](end_span). | **[span_62](start_span)[span_63](start_span)Milestone 1**: Applicazione CLI di base che legge un input e lo passa al parser[span_62](end_span)[span_63](end_span). |
| **2** | [span_64](start_span)[span_65](start_span)Client HTTP sicuro con logiche anti-SSRF, limiti di budget e timeout[span_64](end_span)[span_65](end_span). | [span_66](start_span)[span_67](start_span)Regole di pulizia dell'HTML (XSS, script, tag vietati) e content-sniffing[span_66](end_span)[span_67](end_span). | **[span_68](start_span)[span_69](start_span)Milestone 2**: Il software è in grado di ripulire una singola pagina HTML locale o remota[span_68](end_span)[span_69](end_span). |
| **3** | [span_70](start_span)Sviluppo del Thread Pool concorrente, canali per i report e cache sincronizzate (`Arc`/`Mutex`)[span_70](end_span). | [span_71](start_span)[span_72](start_span)Ispezione URL avanzata (block-list, Unicode) ed estrazione di codice dai PDF[span_71](end_span)[span_72](end_span). | **[span_73](start_span)Milestone 3**: **Integrazione Critica**: Risoluzione del passaggio di dati prestati (`lifetimes` vs `Arc<[u8]>`) tra pool e parser[span_73](end_span). |
| **4** | [span_74](start_span)[span_75](start_span)Suite di benchmark automatizzati e generazione grafici (Throughput/Scalabilità)[span_74](end_span)[span_75](end_span). | [span_76](start_span)Creazione del corpus di test (benigni/payload) e verifica di correttezza e falsi positivi[span_76](end_span). | **[span_77](start_span)[span_78](start_span)Milestone 4**: Il sistema è stabile, sicuro (no panic) e i dati prestazionali sono pronti[span_77](end_span)[span_78](end_span). |
| **5** | [span_79](start_span)Relazione: sezioni Architettura, Concorrenza e Performance[span_79](end_span). | [span_80](start_span)Relazione: sezioni Parsing, Memory Safety, Regole e Correttezza[span_80](end_span). | **[span_81](start_span)Milestone 5**: Consegna del repository Git finale completo e della relazione di 15-25 pagine[span_81](end_span). |

---

## 4. Gestione dei Rischi e Aree di Collaborazione Stretta

[span_82](start_span)Sebbene il lavoro sia distribuito in modo indipendente, i due programmatori dovranno obbligatoriamente collaborare attivamente su un punto cruciale del design in Rust: **il trasferimento degli stati del parser attraverso i thread**[span_82](end_span). 

[span_83](start_span)Poiché il Programmatore B scriverà un parser basato su zero-copy (che prende in prestito i dati tramite reference e `lifetimes`[span_83](end_span)[span_84](start_span)), e il Programmatore A gestirà lo spostamento di questi dati all'interno di un thread pool (che richiede che i tipi implementino i trait `Send` e `Sync`[span_84](end_span)[span_85](start_span)), i due programmatori dovranno incontrarsi all'inizio della **Fase 3** per definire se utilizzare buffer di memoria prima allocati (come `Arc<[u8]>`) o come strutturare i dati in modo da gestire in modo sicuro l'ownership tra i thread[span_85](end_span).
