# 🛡️ Modello di Sicurezza — Pagamenti Offline su Secure Element

## Introduzione

La sicurezza di un sistema di pagamento offline è **più critica** di quella
di un sistema online. Perché? Perché offline non c'è nessun server a cui
chiedere "questa transazione è valida?". Tutto deve essere garantito
**localmente**, dal chip stesso.

In questo documento spieghiamo ogni meccanismo di protezione con analogie
comprensibili e dettagli tecnici.

---

## 1. Contatore Monotònico Hardware

### Analogia: Il Contachilometri che Non Si Può Riavvolgere

Immagina il contachilometri di un'auto: segna 150.000 km e può solo
**andare avanti**. Non puoi riportarlo a 0 km per rivendere l'auto come
nuova. Se qualcuno ci prova, il meccanismo si blocca o si rompe.

Il **contatore monotònico** nel Secure Element funziona allo stesso modo:

```
   Contatore monotònico nel Secure Element
   ┌─────────────────────────────┐
   │  Valore attuale: 42         │
   │                             │
   │  increment() → 43  ✅       │
   │  increment() → 44  ✅       │
   │  reset(0)    → ❌ VIETATO   │
   │  decrement() → ❌ VIETATO   │
   │  setValue(41) → ❌ VIETATO   │
   └─────────────────────────────┘
```

### Perché è essenziale?

Ogni transazione include il valore corrente del contatore. Se un attaccante
prova a **ripetere** (replay) una transazione vecchia, il contatore nella
transazione sarà **inferiore** a quello attuale → la transazione viene
**rifiutata**.

```
   Transazione legittima: contatore=42, importo=25€  ✅
   Replay attack:         contatore=42, importo=25€  ❌ (contatore ora è 43!)
   Prossima legittima:    contatore=43, importo=10€  ✅
```

### Implementazione

Il contatore è memorizzato in un array persistente Java Card (`CLEAR_ON_RESET`
NON è usato — i dati sopravvivono al riavvio). L'unico metodo pubblico che
modifica il valore è `increment()`, che aggiunge 1 in modo atomico.

---

## 2. Firme ECDSA (Elliptic Curve Digital Signature Algorithm)

### Analogia: La Firma Notarile Digitale

Quando un notaio firma un documento, sta dicendo: "Io, con la mia autorità,
certifico che questo documento è autentico". Nessuno può falsificare la
firma del notaio perché solo lui ha il suo timbro e la sua chiave.

La firma **ECDSA** funziona allo stesso modo:

```
   FIRMA ECDSA
   ┌─────────────────────────────────────────┐
   │                                          │
   │  Chiave Privata (nel chip, MAI esce)     │
   │          │                               │
   │          ▼                               │
   │  Dati ──► ECDSA.sign() ──► Firma        │
   │                                          │
   │  Chiunque con la Chiave Pubblica         │
   │  può VERIFICARE la firma                 │
   │  ma NON può CREARE nuove firme           │
   │                                          │
   └─────────────────────────────────────────┘
```

### Curva utilizzata: secp256r1 (P-256)

- Lunghezza chiave: **256 bit**
- Livello di sicurezza: equivalente a RSA-3072
- Standard: NIST, ampiamente usato in pagamenti e TLS
- Supportato nativamente da Java Card 3.0.4+

### Cosa firma il chip?

Per ogni transazione, il chip firma un **hash SHA-256** che include:
- ID del wallet mittente
- ID del wallet destinatario
- Importo in centesimi
- Valore del contatore monotònico
- Timestamp

Questo crea una **prova crittografica irrefutabile** che:
1. La transazione è stata autorizzata da QUEL chip specifico
2. I dati non sono stati alterati dopo la firma
3. La transazione ha un ordine preciso (contatore)

---

## 3. Transazioni Atomiche (JCSystem)

### Analogia: Il Notaio con Due Buste

Immagina un notaio che deve trasferire una proprietà:
1. Mette l'assegno dell'acquirente in una busta
2. Mette il certificato di proprietà in un'altra busta
3. **Scambia le due buste contemporaneamente**
4. Se qualcosa va storto (un documento è falso), **restituisce tutto**

Il `JCSystem` di Java Card fa esattamente questo:

```
   JCSystem.beginTransaction()
   ┌─────────────────────────────────────┐
   │  Tutte le modifiche sono            │
   │  "provvisorie" fino al commit       │
   │                                     │
   │  saldo_alice -= 2500               │
   │  contatore_alice += 1              │
   │  saldo_bob += 2500                │
   │  contatore_bob += 1               │
   │                                     │
   │  Se ERRORE → abortTransaction()     │
   │  → TUTTO torna come prima          │
   │                                     │
   │  Se OK → commitTransaction()        │
   │  → TUTTO viene confermato           │
   └─────────────────────────────────────┘
```

### Garanzie

- **Atomicità**: tutto o niente, mai uno stato intermedio
- **Consistenza**: i saldi totali nel sistema rimangono costanti
- **Durabilità**: dopo il commit, i dati persistono anche senza corrente
- **Resistenza a power-loss**: se il chip perde alimentazione durante
  una transazione, al riavvio il rollback è automatico

---

## 4. Meccanismo Anti Double-Spending

### Il Problema

Nel mondo digitale, copiare dati è facile. Se Alice ha 100€ digitali,
cosa le impedisce di "copiare" quei 100€ e pagarli sia a Bob che a Eve?

### La Soluzione: Triple Protezione

```
   PROTEZIONE ANTI DOUBLE-SPENDING
   ════════════════════════════════

   Livello 1: CONTATORE MONOTÒNICO
   ├── Ogni TX ha un numero univoco crescente
   └── TX con contatore già usato → RIFIUTATA

   Livello 2: SALDO NEL SECURE ELEMENT
   ├── Il saldo è nel chip tamper-resistant
   ├── Non può essere modificato dall'esterno
   └── Dopo un debito, il saldo è REALMENTE diminuito

   Livello 3: FIRMA CRITTOGRAFICA
   ├── Ogni TX è firmata dal chip
   ├── La firma include il contatore
   └── Impossibile creare firme false
```

### Scenario di Attacco (e perché fallisce)

```
   ATTACCANTE prova a spendere 100€ due volte:

   1. Paga Bob:    contatore=42, firma=ECDSA(42,100€,Bob)   ✅ OK
      Saldo: 100€ → 0€, Contatore: 42 → 43

   2. Prova a pagare Eve: contatore=42 (lo stesso!)
      ❌ FALLISCE: contatore nel chip è già 43!

   3. Prova a riportare il contatore a 42:
      ❌ IMPOSSIBILE: il contatore è monotònico!

   4. Prova a modificare il saldo del chip:
      ❌ IMPOSSIBILE: il Secure Element è tamper-resistant!

   5. Prova a clonare il chip:
      ❌ IMPOSSIBILE: la chiave privata non esce MAI!
```

---

## 5. Modello di Minaccia (Threat Model)

### Cosa PUÒ fare un attaccante

| Azione | Possibile? | Conseguenza |
|--------|-----------|-------------|
| Intercettare comunicazione NFC | ✅ Sì | Vede dati cifrati, inutile |
| Ripetere una TX (replay) | ✅ Sì | Rifiutata (contatore diverso) |
| Modificare l'app sul telefono | ✅ Sì | Il chip rifiuta comandi invalidi |
| Provare a debito senza saldo | ✅ Sì | Errore 6A83: saldo insufficiente |
| Inviare comandi APDU falsi | ✅ Sì | Auth fallisce, nessun danno |

### Cosa NON PUÒ fare un attaccante

| Azione | Perché impossibile |
|--------|-------------------|
| Estrarre la chiave privata | Hardware tamper-resistant |
| Clonare il Secure Element | Chiavi legate al silicio |
| Modificare il saldo | Solo il firmware del chip può farlo |
| Riavvolgere il contatore | Contatore monotònico hardware |
| Falsificare una firma | Serve la chiave privata (nel chip) |
| Creare denaro dal nulla | Saldo inizializzato solo da autorità |

### Attacchi fisici al chip

I Secure Element di classe **EAL5+** (come JCOP4) resistono a:
- **Analisi al microscopio** — circuiti schermati con mesh attive
- **Fault injection** — sensori che rilevano glitch di voltaggio
- **Side-channel attack** — contromisure integrate (randomizzazione)
- **Probing fisico** — distruzione delle chiavi se rileva intrusione

---

## 6. Resistenza al Tampering del Secure Element

Il Secure Element non è un semplice chip di memoria. È un
**microprocessore certificato** con protezioni fisiche multiple:

```
   STRATI DI PROTEZIONE DEL SECURE ELEMENT
   ┌─────────────────────────────────────────┐
   │  Layer 1: Mesh metallica attiva          │
   │  Layer 2: Sensori di luce e voltaggio    │
   │  Layer 3: Scrambling dei bus interni     │
   │  Layer 4: Memoria criptata               │
   │  Layer 5: Contromisure side-channel      │
   │  Layer 6: Self-destruct se manomesso     │
   └─────────────────────────────────────────┘
```

### Certificazioni

- **Common Criteria EAL5+**: standard per carte di pagamento
- **EMVCo**: certificazione per carte bancarie
- **FIPS 140-2 Level 3**: standard governativo USA

---

## Riepilogo delle Protezioni

```
   ┌─────────────────────────────────────────────────┐
   │          DIFESE STRATIFICATE                     │
   ├─────────────────────────────────────────────────┤
   │                                                  │
   │  🔢 Contatore Monotònico → Anti-replay           │
   │  ✍️  Firma ECDSA → Autenticità e integrità       │
   │  🔒 Transazione Atomica → Consistenza            │
   │  💰 Saldo nel SE → Anti-falsificazione           │
   │  🔑 Chiave nel chip → Anti-clonazione            │
   │  🛡️ Hardware EAL5+ → Anti-manomissione           │
   │                                                  │
   └─────────────────────────────────────────────────┘
```

---

*Documento parte del progetto SE-OFFLINE-PAYMENTS — AEGIS Protocol*
