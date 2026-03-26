# 🔒 Modello di Sicurezza

> Spiegazione del modello di sicurezza del sistema di pagamento offline,
> dai principi base agli attacchi possibili e alle contromisure.

---

## Indice

1. [I tre pilastri della sicurezza](#i-tre-pilastri-della-sicurezza)
2. [Livelli di protezione](#livelli-di-protezione)
3. [La crittografia ECDSA in parole semplici](#la-crittografia-ecdsa-in-parole-semplici)
4. [Il contatore monotonico anti-frode](#il-contatore-monotonico-anti-frode)
5. [Attacchi possibili e contromisure](#attacchi-possibili-e-contromisure)
6. [Modello di minaccia (Threat Model)](#modello-di-minaccia-threat-model)
7. [Limiti del sistema](#limiti-del-sistema)

---

## I tre pilastri della sicurezza

Il sistema si basa su tre proprietà fondamentali:

### 1. Autenticità — "Sei davvero Alice?"

```
PROBLEMA: Come sa Bob che il pagamento viene davvero da Alice
          e non da qualcuno che finge di essere Alice?

SOLUZIONE: Firma digitale ECDSA
  Alice ha una chiave PRIVATA (segreta, nel chip)
  Alice ha una chiave PUBBLICA (nota a tutti)

  Alice firma il pagamento con la chiave privata.
  Bob verifica con la chiave pubblica di Alice.
  Solo chi ha la chiave privata può produrre una firma valida.
```

### 2. Integrità — "Il messaggio non è stato modificato?"

```
PROBLEMA: Qualcuno intercetta il pagamento e cambia "25€" in "2500€"?

SOLUZIONE: La firma ECDSA copre l'intero contenuto del messaggio.
  Se anche un solo byte cambia, la firma diventa invalida.
  Bob si accorge immediatamente del tentativo di manomissione.
```

### 3. Non-ripudio — "Alice non può negare di aver pagato?"

```
PROBLEMA: Alice paga Bob, poi dice "io non ho mai pagato"?

SOLUZIONE: La firma digitale è prova matematica dell'azione.
  Solo Alice (con la sua chiave privata) poteva produrre quella firma.
  La firma è registrata nel log delle transazioni.
```

---

## Livelli di protezione

```
┌─────────────────────────────────────────────────────────────────┐
│  LIVELLO 3: Blockchain (quando online)                          │
│  → Verifica globale, immutabilità, finalità                    │
├─────────────────────────────────────────────────────────────────┤
│  LIVELLO 2: Firma ECDSA P-256                                   │
│  → Autenticità transazione, integrità dati                     │
├─────────────────────────────────────────────────────────────────┤
│  LIVELLO 1: Contatore monotonico                                │
│  → Anti-replay, anti-doppio utilizzo                           │
├─────────────────────────────────────────────────────────────────┤
│  LIVELLO 0: Secure Element (hardware)                           │
│  → Isolamento fisico, chiavi non estraibili                    │
└─────────────────────────────────────────────────────────────────┘
     ↑ Il livello più basso è il più fondamentale
```

### Livello 0: Hardware Security

Il Secure Element è un chip fisico certificato:

| Certificazione | Significato |
|---------------|-------------|
| **CC EAL5+** | Common Criteria — livello bancario |
| **EMVCo** | Standard per carte di pagamento |
| **FIPS 140-2** | Standard crittografico governativo USA |

Il chip resiste a:
- Analisi di potenza (Power Analysis)
- Attacchi a canale laterale (Side-channel)
- Iniezione di guasti (Fault injection)
- Depackaging fisico

### Livello 1: Contatore monotonico

```
REGOLA: Il contatore può solo aumentare, mai diminuire

Transazione 1: Alice Cnt=42 → 43  ✓
Transazione 2: Alice Cnt=43 → 44  ✓
Transazione REPLAY: Alice Cnt=44 → 43  ✗ RIFIUTATA
```

### Livello 2: ECDSA P-256

- Curva ellittica P-256 (secp256r1)
- Chiave privata: 256 bit (generata nel chip, non esce mai)
- Firma: 64-72 byte (formato DER)
- Sicurezza equivalente a RSA 3072 bit

### Livello 3: Blockchain AEGIS

Quando online, ogni transazione viene:
1. Inviata al bridge di riconciliazione
2. Verificata dalla rete AEGIS
3. Registrata in modo immutabile

---

## La crittografia ECDSA in parole semplici

### Analogia: il sigillo di cera

```
🕯️ ANALOGIA SIGILLO DI CERA

Ogni persona ha un anello unico (chiave privata).
Ogni anello produce un'impronta unica nella cera (firma).

Alice sigilla la lettera con il suo anello.
Bob ha il calco dell'anello di Alice (chiave pubblica).
Bob confronta il sigillo con il calco.
Se corrispondono → il messaggio viene davvero da Alice.

Trucco crittografico: non si può ricavare l'anello dal calco.
```

### Come funziona davvero

```
FIRMA (Alice):
  1. Hash del messaggio: H = SHA-256(dati_transazione)
  2. Numero casuale k (generato nel chip, usa un seme sicuro)
  3. Calcolo punto curva: R = k * G  (G = punto base della curva)
  4. Firma: (r, s) dove:
     r = R.x mod n
     s = k⁻¹ * (H + r * chiave_privata) mod n

VERIFICA (Bob):
  1. Hash del messaggio: H = SHA-256(dati_transazione)
  2. w = s⁻¹ mod n
  3. u1 = H * w mod n
  4. u2 = r * w mod n
  5. Punto: X = u1*G + u2*chiave_pubblica_alice
  6. Verifica: X.x mod n == r ?  → OK se sì
```

La magia: Bob può verificare senza conoscere la chiave privata di Alice.

---

## Il contatore monotonico anti-frode

### Il problema senza contatore

```
ATTACCO REPLAY (senza contatore):
─────────────────────────────────
T=0: Alice paga Bob 50€
     Pacchetto P = {50€, firma_alice}   ← Eve intercetta P

T=1: Bob riceve P → saldo Bob += 50€ ✓

T=2: Eve invia di nuovo P a Bob
     Pacchetto P = {50€, firma_alice}   ← stesso pacchetto!
     Bob controlla: firma valida? SÌ
     Bob accredita: saldo Bob += 50€   ✗ FRODE!
```

### La soluzione con contatore

```
PROTEZIONE REPLAY (con contatore):
───────────────────────────────────
T=0: Alice Cnt=42, paga Bob 50€
     Pacchetto P = {50€, Cnt=42→43, firma_alice}  ← Eve intercetta P

T=1: Bob riceve P → saldo Bob += 50€, nota Cnt_alice=43

T=2: Eve invia di nuovo P a Bob
     Pacchetto P = {50€, Cnt=42→43, firma_alice}
     Bob controlla: Cnt ricevuto (43) > Cnt notato (43)? NO!
     Bob rifiuta → ATTACCO FALLITO ✓
```

### Implementazione

```java
// Nel chip: il contatore è in memoria non volatile (EEPROM)
// e può solo aumentare
public void incrementCounter() {
    counter++;  // Operazione atomica nel chip
    // Non esiste una funzione decrementCounter()
    // Il firmware del chip impedisce qualsiasi decremento
}
```

---

## Attacchi possibili e contromisure

### 🔴 Attacco 1: Clonazione del chip

```
SCENARIO: Eve ruba il telefono di Alice e prova a copiare il chip

CONTROMISURA:
  La chiave privata è generata DENTRO il chip con true random.
  Non esce MAI dal chip — nemmeno durante backup o aggiornamenti.
  Il chip ha protezioni fisiche contro la lettura della memoria.

RISULTATO: Impossibile da clonare (con chip certificato EAL5+)
```

### 🔴 Attacco 2: Doppio utilizzo (Double Spending)

```
SCENARIO: Alice paga Bob 100€ e poi "resetta" il chip per ripagare Carlo

CONTROMISURA:
  Il contatore monotonico non può essere decrementato.
  La blockchain registra l'ultimo contatore valido.
  Se Alice prova a usare un contatore già visto, la transazione è rifiutata.

RISULTATO: Impossibile in modalità online. Offline, limitato ai tetti di spesa.
```

### 🟡 Attacco 3: Man-in-the-Middle (NFC)

```
SCENARIO: Eve mette un dispositivo tra Alice e Bob e intercetta il pagamento

CONTROMISURA:
  Le firme ECDSA proteggono l'integrità (Eve non può modificare i dati).
  Eve può leggere ma non alterare le transazioni.
  NFC a 4cm limita fisicamente la possibilità di intercettazione.

RISCHIO RESIDUO: Eve può registrare le transazioni (privacy).
MITIGAZIONE FUTURA: Canale cifrato con ECDH session key.
```

### 🟡 Attacco 4: Chip compromesso (firmware malevolo)

```
SCENARIO: Il produttore del chip installa firmware malevolo

CONTROMISURA:
  Applet JavaCard firmata dal nostro certificato.
  Il chip verifica la firma prima di caricare l'applet.
  Audit del codice dell'applet open source.

RISCHIO RESIDUO: Dipendenza dalla supply chain hardware.
```

### 🟢 Attacco 5: Attacco offline prolungato

```
SCENARIO: Alice accumula transazioni offline per 30 giorni
          senza mai sincronizzarsi → accumula debiti impossibili

CONTROMISURA:
  Limite di spesa offline configurabile (es. 500€)
  Limite temporale (es. max 30 giorni senza sync)
  Alla sincronizzazione, la blockchain verifica tutto

RISULTATO: Perdita limitata ai tetti impostati
```

---

## Modello di minaccia (Threat Model)

```
SUPERFICIE DI ATTACCO:
┌─────────────────────────────────────────────────────┐
│                                                     │
│  ❌ OUT OF SCOPE (chip certificato difende da):      │
│     - Analisi hardware del chip                     │
│     - Estrazione chiave privata                     │
│     - Clonazione del SE                             │
│                                                     │
│  ⚠️  IN SCOPE (il nostro codice difende da):        │
│     - Attacchi replay                               │
│     - Dati falsificati via NFC                      │
│     - Double spending offline                       │
│     - Applet malevola nel chip                      │
│                                                     │
│  📋 FUORI MODELLO (da considerare in produzione):   │
│     - Attacchi DDoS al bridge                       │
│     - Compromissione della blockchain               │
│     - Attacchi social engineering                   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## Limiti del sistema

| Limite | Valore default | Motivo |
|--------|---------------|--------|
| Spesa offline massima | 500€ | Limitare l'esposizione in caso di frode |
| Durata offline massima | 30 giorni | Obbligare riconciliazione periodica |
| Transazioni per sessione | 100 | Prevenire accumulo eccessivo |
| Importo singola transazione | 250€ | Limite NFC standard EMV |
| Transazioni nel log chip | 10 | Memoria limitata del chip |

---

## Algoritmi e parametri crittografici

| Algoritmo | Uso | Parametri |
|-----------|-----|-----------|
| ECDSA | Firma transazioni | Curva P-256 (secp256r1) |
| SHA-256 | Hash messaggi | Output 32 byte |
| ECDH | Scambio chiavi session (futuro) | Curva P-256 |
| AES-128 | Cifratura canale (futuro) | Modalità GCM |
| TRNG | Generazione chiavi | Hardware RNG nel chip |

---

*Precedente: [02_FLUSSO_APDU.md](02_FLUSSO_APDU.md) — Prossimo: [04_HARDWARE_GUIDA.md](04_HARDWARE_GUIDA.md)*
