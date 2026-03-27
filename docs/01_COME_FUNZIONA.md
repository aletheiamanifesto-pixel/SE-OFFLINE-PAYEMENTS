# 🏦 Come Funziona il Pagamento Offline su Secure Element

## Introduzione: Perché serve un chip "blindato"?

Immagina di avere una **cassaforte che nessuno può aprire**, nemmeno il proprietario
del telefono. Questa cassaforte è il **Secure Element (SE)**: un microprocessore
tamper-resistant integrato nel dispositivo NFC. A differenza di un'app normale che
vive nella memoria del telefono (dove un hacker potrebbe modificarla), il Secure
Element è un **mondo a sé stante** con le proprie chiavi crittografiche, il proprio
sistema operativo (Java Card) e le proprie regole.

### Analogia: La Cassaforte che Nessuno Può Aprire

Pensa a una cassaforte fisica fatta così:
- Ha un **contatore meccanico** che segna quante volte è stata aperta (non si può riavvolgere)
- Ogni volta che apri la cassaforte, la cassaforte **firma un foglio** con un sigillo unico
- Se qualcuno prova a forzarla, la cassaforte **si autodistrugge** (cancella le chiavi)
- Non puoi "clonare" la cassaforte perché le chiavi private non escono MAI

Questo è esattamente ciò che fa il Secure Element nel nostro sistema di pagamento.

---

## Il Flusso di Pagamento: Una Storia

### I Personaggi
- **Alice** 📱 — vuole pagare 25€ per un caffè e un cornetto
- **Bob** 📱 — è il barista che riceve il pagamento
- **Chip di Alice** 🔐 — Secure Element con saldo 100€, contatore a 42
- **Chip di Bob** 🔐 — Secure Element con saldo 50€, contatore a 18

### Atto 1: L'Avvicinamento (NFC Tap)

Alice avvicina il suo telefono al POS di Bob. I due chip NFC si "vedono"
a circa 4 cm di distanza. È come due persone che si stringono la mano:
il contatto fisico è necessario.

```
   📱 Alice                    📱 Bob
   ┌─────────┐    ≈4cm NFC    ┌─────────┐
   │  App     │◄══════════════►│  App     │
   │  ┌─────┐ │               │ ┌─────┐  │
   │  │ SE  │ │               │ │ SE  │  │
   │  │100€ │ │               │ │ 50€ │  │
   │  │Cnt42│ │               │ │Cnt18│  │
   │  └─────┘ │               │ └─────┘  │
   └─────────┘                └─────────┘
```

### Atto 2: Autenticazione Reciproca (Chi sei davvero?)

Prima di scambiarsi soldi, i due chip devono **dimostrare la propria identità**.
È come quando due diplomatici si incontrano: prima mostrano le credenziali.

1. Il chip di Bob genera un **numero casuale** (nonce) e lo invia ad Alice
2. Il chip di Alice firma il nonce con la sua **chiave privata ECDSA**
3. Bob verifica la firma con il **certificato** di Alice
4. Il processo si ripete al contrario: Alice verifica Bob

Se uno dei due chip è falso o compromesso, la verifica fallisce e il
pagamento **non avviene**. Nessun soldo viene toccato.

### Atto 3: Verifica del Saldo

Il chip di Alice controlla internamente:
- Ho abbastanza soldi? (100€ ≥ 25€ ✅)
- L'importo è sotto il limite massimo per transazione? (25€ ≤ 500€ ✅)
- Il mio stato è valido? (wallet inizializzato ✅)

```
   Chip Alice verifica:
   ┌──────────────────────────┐
   │ Saldo attuale:    100,00€│
   │ Importo richiesto: 25,00€│
   │ ─────────────────────────│
   │ 100,00 ≥ 25,00?   ✅ SÌ │
   │ 25,00 ≤ 500,00?   ✅ SÌ │
   │ Wallet valido?     ✅ SÌ │
   │ → TRANSAZIONE AUTORIZZATA│
   └──────────────────────────┘
```

### Atto 4: Il Trasferimento Atomico

Questa è la parte più critica. Il trasferimento deve essere **atomico**:
o avviene completamente, o non avviene affatto. È come un notaio che
tiene in mano l'assegno e le chiavi di casa: li scambia nello stesso
istante, oppure restituisce tutto ai proprietari originali.

```
   TRANSAZIONE ATOMICA
   ═══════════════════

   BEGIN TRANSACTION ──────────────────►
   │
   │  Alice: 100€ → 75€  (debito 25€)
   │  Alice: Cnt 42 → 43
   │  Bob:   50€ → 75€   (credito 25€)
   │  Bob:   Cnt 18 → 19
   │
   │  Tutto OK? ─── SÌ ──► COMMIT ✅
   │              │
   │              NO ──────► ABORT ↩️
   │                         (tutto torna come prima)
```

Il **JCSystem** di Java Card garantisce che:
- Se il telefono si spegne a metà → ABORT automatico
- Se la connessione NFC cade → ABORT automatico
- Se un chip rileva un errore → ABORT esplicito

### Atto 5: La Ricevuta Firmata

Dopo il COMMIT, entrambi i chip generano una **ricevuta firmata digitalmente**:

```
   RICEVUTA DIGITALE
   ┌─────────────────────────────────┐
   │ Da:        Alice (ID: 0xA1B2)   │
   │ A:         Bob   (ID: 0xC3D4)   │
   │ Importo:   25,00€               │
   │ Contatore: 43                   │
   │ Timestamp: 2025-01-15T10:30:00  │
   │ Hash:      SHA-256(...)         │
   │ Firma:     ECDSA(chiave_alice)  │
   └─────────────────────────────────┘
```

Questa ricevuta è la **prova crittografica** che il pagamento è avvenuto.

---

## Cosa Succede se la Connessione NFC Cade? (Rollback Atomico)

Questa è la domanda che tutti fanno. La risposta è semplice e rassicurante:
**non si perde nemmeno un centesimo**.

### Scenari di Interruzione

| Momento dell'interruzione | Cosa succede |
|--------------------------|--------------|
| Durante l'autenticazione | Nessun danno, si riparte da zero |
| Durante la verifica saldo | Nessun danno, nulla è stato modificato |
| Durante il debito di Alice | **ABORT**: il saldo torna a 100€ |
| Durante il credito di Bob  | **ABORT**: entrambi tornano allo stato originale |
| Dopo il COMMIT | Pagamento completato, nessun problema |

Il segreto è il meccanismo di **transazione atomica** del Java Card:

```
   JCSystem.beginTransaction()     ← Apre il "recinto di sicurezza"
       |
       |   Modifica saldo Alice    ← Ancora provvisorio!
       |   Incrementa contatore    ← Ancora provvisorio!
       |   Modifica saldo Bob      ← Ancora provvisorio!
       |
       |   Errore? → JCSystem.abortTransaction()  ← TUTTO annullato
       |   OK?     → JCSystem.commitTransaction()  ← TUTTO confermato
```

---

## Come si Previene il "Double Spending"?

### Analogia: La Banconota con Numero di Serie e Contachilometri

Immagina una banconota da 50€ che ha:
1. Un **numero di serie unico** (come ogni transazione ha un ID unico)
2. Un **contachilometri incorporato** che segna quante volte è stata spesa
3. Ogni volta che la spendi, il contachilometri **avanza di uno** e **non può mai tornare indietro**

Se qualcuno prova a "copiare" la banconota e spenderla due volte:
- La copia avrebbe lo **stesso numero del contachilometri**
- Ma il sistema si aspetta il **numero successivo**
- → La copia viene **rifiutata**!

### Come funziona nel nostro sistema

Il **contatore monotònico** è un numero memorizzato nel Secure Element che:
- Parte da 0 quando il wallet viene creato
- Aumenta di 1 ad **ogni transazione**
- **Non può MAI diminuire** (è implementato in hardware)
- Viene incluso in ogni ricevuta firmata

```
   Transazione #42: Alice → Bob, 25€, Contatore=42  ✅ Accettata
   Transazione #42: Alice → Eve, 25€, Contatore=42  ❌ RIFIUTATA!
                                                       (contatore già usato)
   Transazione #43: Alice → Eve, 25€, Contatore=43  ✅ Accettata
```

---

## Riconciliazione con la Blockchain AEGIS

Quando il dispositivo torna online, le ricevute firmate vengono inviate al
**bridge di riconciliazione** che le registra sulla blockchain AEGIS.

```
   OFFLINE                           ONLINE
   ════════                          ══════

   📱 Pagamento 1  ──┐
   📱 Pagamento 2  ──┼──► Bridge ──► Blockchain AEGIS
   📱 Pagamento 3  ──┘    di          ┌──────────────┐
                        Riconcil.     │ Ledger AEGIS │
                                      │ TX #42: 25€  │
                                      │ TX #43: 10€  │
                                      │ TX #44: 5€   │
                                      └──────────────┘
```

### Fasi della Riconciliazione

1. **Upload**: il dispositivo invia tutte le ricevute firmate al bridge
2. **Validazione**: il bridge verifica le firme ECDSA e i contatori
3. **Ordinamento**: le transazioni vengono ordinate per contatore monotònico
4. **Registrazione**: ogni transazione viene scritta sulla blockchain AEGIS
5. **Conferma**: il bridge conferma al dispositivo che tutto è stato registrato

### Conflitti? Impossibili!

Grazie al contatore monotònico, l'ordine delle transazioni è **determinístico**.
Non ci possono essere conflitti o ambiguità: la transazione #42 viene SEMPRE
prima della #43, e così via. È come un libro con pagine numerate: non puoi
inserire una pagina tra la 42 e la 43.

---

## Riepilogo Visivo Completo

```
   ┌─────────────────────────────────────────────────────┐
   │              FLUSSO PAGAMENTO COMPLETO               │
   ├─────────────────────────────────────────────────────┤
   │                                                      │
   │  1. NFC TAP        📱 ←──4cm──→ 📱                  │
   │  2. AUTH            🔑 ←──firma──→ 🔑                │
   │  3. VERIFICA        💰 saldo ≥ importo?              │
   │  4. BEGIN TX        🔒 apri transazione              │
   │  5. DEBITO          💳 Alice -25€                    │
   │  6. CREDITO         💳 Bob +25€                      │
   │  7. COMMIT          ✅ conferma tutto                │
   │  8. RICEVUTA        📜 firma digitale                │
   │  9. RICONCILIAZIONE 🌐 → blockchain (quando online) │
   │                                                      │
   └─────────────────────────────────────────────────────┘
```

---

## Glossario Rapido

| Termine | Significato |
|---------|-------------|
| **Secure Element** | Chip tamper-resistant con proprio OS |
| **Java Card** | Sistema operativo per smart card |
| **APDU** | Protocollo di comunicazione con il chip |
| **ECDSA** | Algoritmo di firma digitale a curve ellittiche |
| **Contatore Monotònico** | Numero che può solo crescere, mai diminuire |
| **Transazione Atomica** | Operazione "tutto o niente" |
| **NFC** | Near Field Communication (~4cm) |
| **Riconciliazione** | Sincronizzazione offline → blockchain |

---

*Documento parte del progetto SE-OFFLINE-PAYMENTS — AEGIS Protocol*
