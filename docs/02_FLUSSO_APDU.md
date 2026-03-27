# 📨 Flusso APDU — Comunicazione con il Secure Element

## Cos'è un APDU?

### Analogia: La Lettera con Busta e Indirizzo

Un **APDU** (Application Protocol Data Unit) è come una **lettera formale**:

- La **busta** ha un formato standard (intestazione con CLA, INS, P1, P2)
- L'**indirizzo** dice a chi è destinata (quale comando eseguire)
- Il **contenuto** è il dato vero e proprio (payload)
- La **risposta** include sempre un **codice di stato** (come l'avviso di ricevimento)

```
   APDU COMANDO (dal telefono al chip)
   ┌──────┬──────┬──────┬──────┬──────┬────────────┬──────┐
   │ CLA  │ INS  │  P1  │  P2  │  Lc  │    Data    │  Le  │
   │ (chi)│(cosa)│(come)│(come)│(lung)│ (contenuto)│(risp)│
   └──────┴──────┴──────┴──────┴──────┴────────────┴──────┘

   CLA = Classe (chi parla: 0x00=standard, 0x80=proprietario)
   INS = Istruzione (cosa vuoi fare)
   P1  = Parametro 1 (dettaglio aggiuntivo)
   P2  = Parametro 2 (dettaglio aggiuntivo)
   Lc  = Lunghezza dei dati in ingresso
   Data = I dati veri e propri
   Le  = Lunghezza massima della risposta attesa

   APDU RISPOSTA (dal chip al telefono)
   ┌────────────┬──────┬──────┐
   │    Data    │ SW1  │ SW2  │
   │ (risposta) │(stato│esito)│
   └────────────┴──────┴──────┘

   SW1-SW2 = Status Word (es: 90 00 = tutto OK)
```

---

## Tabella Comandi APDU

Ecco tutti i comandi supportati dall'applet OfflineDigitalEuro:

| Comando | CLA | INS | P1 | P2 | Lc | Data | Le | Descrizione |
|---------|-----|-----|----|----|----|------|----|-------------|
| **SELECT** | 00 | A4 | 04 | 00 | var | AID dell'applet | 00 | Seleziona l'applet sul chip |
| **GET_BALANCE** | 80 | 10 | 00 | 00 | 00 | — | 04 | Legge il saldo corrente (in centesimi) |
| **DEBIT** | 80 | 20 | 00 | 00 | 04 | Importo (4 byte) | 00 | Addebita un importo dal wallet |
| **CREDIT** | 80 | 30 | 00 | 00 | 04 | Importo (4 byte) | 00 | Accredita un importo al wallet |
| **GET_COUNTER** | 80 | 40 | 00 | 00 | 00 | — | 04 | Legge il contatore monotònico |
| **SIGN** | 80 | 50 | 00 | 00 | var | Dati da firmare | 48 | Firma dati con ECDSA (max 72 byte) |
| **GET_CERTIFICATE** | 80 | 60 | 00 | 00 | 00 | — | var | Ottiene il certificato pubblico |
| **MUTUAL_AUTH** | 80 | 70 | 00 | 00 | var | Nonce + firma | var | Autenticazione reciproca |

### Nota sul CLA (Classe)

- `0x00` — Comandi **standard** ISO 7816 (come SELECT)
- `0x80` — Comandi **proprietari** della nostra applicazione

È come la differenza tra una lettera inviata con il servizio postale
nazionale (standard) e un corriere privato (proprietario).

---

## Tabella Status Word (Codici di Risposta)

| SW1 | SW2 | Codice | Significato | Analogia |
|-----|-----|--------|-------------|----------|
| 90 | 00 | **9000** | Successo | "Lettera consegnata, tutto OK" |
| 69 | 83 | **6983** | Wallet non inizializzato | "Cassaforte ancora sigillata" |
| 69 | 85 | **6985** | Condizioni non soddisfatte | "Non hai i requisiti" |
| 67 | 00 | **6700** | Lunghezza dati errata | "Busta con formato sbagliato" |
| 6D | 00 | **6D00** | Istruzione non supportata | "Comando sconosciuto" |
| 6A | 83 | **6A83** | Saldo insufficiente | "Non hai abbastanza soldi" |
| 6A | 84 | **6A84** | Limite transazione superato | "Importo troppo alto" |

---

## Fase 1: Autenticazione Reciproca (MUTUAL_AUTH)

Prima di qualsiasi operazione, i due chip devono **provare la propria identità**.
È come quando due spie si incontrano e devono scambiarsi una parola d'ordine.

```
   📱 Alice (Initiator)                 📱 Bob (Responder)
   ─────────────────                    ─────────────────
        │                                      │
        │  1. SELECT applet                    │
        │─────────────────────────────────────►│
        │                          SW: 9000 OK │
        │◄─────────────────────────────────────│
        │                                      │
        │  2. GET_CERTIFICATE                  │
        │─────────────────────────────────────►│
        │                    Cert_Bob + 9000   │
        │◄─────────────────────────────────────│
        │                                      │
        │  3. MUTUAL_AUTH (Nonce_A + Cert_A)   │
        │─────────────────────────────────────►│
        │     Bob verifica Cert_A, firma       │
        │     Nonce_A con chiave privata       │
        │          Firma_B(Nonce_A) + 9000     │
        │◄─────────────────────────────────────│
        │                                      │
        │  Alice verifica Firma_B              │
        │  con chiave pubblica di Bob          │
        │  ✅ Autenticazione completata!       │
        │                                      │
```

### Dettaglio APDU per la Fase 1

```
   → SELECT:         00 A4 04 00 07 [AID 7 byte] 00
   ← Risposta:       90 00

   → GET_CERTIFICATE: 80 60 00 00 00
   ← Risposta:       [certificato X.509] 90 00

   → MUTUAL_AUTH:    80 70 00 00 [Lc] [Nonce_A(16) + Cert_A(var)] 00
   ← Risposta:       [Firma_B(Nonce_A)] 90 00
```

---

## Fase 2: Verifica del Saldo (GET_BALANCE)

Dopo l'autenticazione, l'app di Alice verifica il saldo disponibile.

```
   📱 Alice                              🔐 Chip Alice
   ────────                              ─────────────
        │                                      │
        │  GET_BALANCE                         │
        │  80 10 00 00 00                      │
        │─────────────────────────────────────►│
        │                                      │
        │  Il chip legge il saldo dalla        │
        │  memoria persistente (EEPROM)        │
        │                                      │
        │         [00 00 27 10] 90 00          │
        │◄─────────────────────────────────────│
        │                                      │
        │  0x00002710 = 10000 centesimi        │
        │            = 100,00 €                │
        │                                      │
```

### Nota: Perché in Centesimi?

Java Card non supporta numeri decimali (`float` o `double`). Usiamo
i **centesimi** come unità base: 100,00€ = 10000 centesimi.
È come quando al mercato il prezzo è "2 euro e 50" ma nel registratore
di cassa è memorizzato come "250".

---

## Fase 3: Trasferimento Atomico (DEBIT + CREDIT)

Questa è la fase critica. Il trasferimento è **atomico**: o tutto va
a buon fine, o nulla cambia.

```
   📱 App Host                   🔐 Chip Alice        🔐 Chip Bob
   ──────────                    ─────────────        ────────────
        │                              │                     │
        │ DEBIT 25,00€ (2500 cent)     │                     │
        │ 80 20 00 00 04 [00 00 09 C4] │                     │
        │─────────────────────────────►│                     │
        │                              │                     │
        │  ┌─ beginTransaction() ─┐    │                     │
        │  │ saldo: 10000→7500    │    │                     │
        │  │ contatore: 42→43    │    │                     │
        │  └─ commitTransaction()─┘    │                     │
        │                              │                     │
        │              90 00 (OK)      │                     │
        │◄─────────────────────────────│                     │
        │                                                    │
        │ CREDIT 25,00€ (2500 cent)                          │
        │ 80 30 00 00 04 [00 00 09 C4]                       │
        │───────────────────────────────────────────────────►│
        │                                                    │
        │                    ┌─ beginTransaction() ─┐        │
        │                    │ saldo: 5000→7500     │        │
        │                    │ contatore: 18→19     │        │
        │                    └─ commitTransaction()─┘        │
        │                                                    │
        │                                    90 00 (OK)      │
        │◄───────────────────────────────────────────────────│
        │                                                    │
```

### Se qualcosa va storto durante il DEBIT:

```
   │  ┌─ beginTransaction() ─┐
   │  │ saldo: 10000→7500    │
   │  │     ⚡ ERRORE!        │  ← Connessione NFC persa!
   │  └─ abortTransaction() ─┘  ← Il chip annulla TUTTO
   │
   │  Saldo rimane: 10000 (100,00€)  ← Come se nulla fosse successo
   │  Contatore rimane: 42
```

---

## Fase 4: Conferma e Ricevuta Firmata (SIGN)

Dopo il trasferimento, entrambi i chip firmano una ricevuta.

```
   📱 App Host                   🔐 Chip Alice
   ──────────                    ─────────────
        │                              │
        │  GET_COUNTER                 │
        │  80 40 00 00 00              │
        │─────────────────────────────►│
        │         [00 00 00 2B] 90 00  │  ← contatore = 43
        │◄─────────────────────────────│
        │                              │
        │  SIGN (hash della TX)        │
        │  80 50 00 00 20 [hash 32B]   │
        │─────────────────────────────►│
        │                              │
        │  Il chip firma con ECDSA     │
        │  usando la chiave privata    │
        │  che NON esce MAI dal chip   │
        │                              │
        │    [firma ECDSA 64-72B] 9000 │
        │◄─────────────────────────────│
        │                              │
```

### Struttura della Ricevuta

```
   ┌─────────────────────────────────────────┐
   │           RICEVUTA TRANSAZIONE           │
   ├─────────────────────────────────────────┤
   │ Mittente:    wallet_id_alice             │
   │ Destinatario: wallet_id_bob              │
   │ Importo:     2500 (centesimi) = 25,00€   │
   │ Contatore:   43                          │
   │ Timestamp:   2025-01-15T10:30:00Z        │
   │ Valuta:      EUR (0x0978)                │
   ├─────────────────────────────────────────┤
   │ Hash SHA-256: a1b2c3d4...               │
   │ Firma ECDSA:  3045022100...             │
   └─────────────────────────────────────────┘
```

---

## Flusso Completo in un Diagramma

```
   ┌──────────────────────────────────────────────────────────┐
   │                   FLUSSO COMPLETO APDU                    │
   ├────────┬─────────────────────────────────────────────────┤
   │ FASE   │ COMANDI                                          │
   ├────────┼─────────────────────────────────────────────────┤
   │ 1.AUTH │ SELECT → GET_CERTIFICATE → MUTUAL_AUTH           │
   │        │ "Chi sei? Dimostralo!"                           │
   ├────────┼─────────────────────────────────────────────────┤
   │ 2.CHECK│ GET_BALANCE                                      │
   │        │ "Hai abbastanza soldi?"                           │
   ├────────┼─────────────────────────────────────────────────┤
   │ 3.TX   │ DEBIT (Alice) → CREDIT (Bob)                    │
   │        │ "Sposta i soldi, atomicamente"                   │
   ├────────┼─────────────────────────────────────────────────┤
   │ 4.PROVA│ GET_COUNTER → SIGN                               │
   │        │ "Dammi la prova firmata"                         │
   └────────┴─────────────────────────────────────────────────┘
```

---

## Esempio Pratico: Byte per Byte

### Pagamento di 25,00€ (2500 centesimi = 0x09C4)

```
   PASSO 1 — Seleziona applet:
   → 00 A4 04 00 07 D2 76 00 00 60 41 01 00
   ← 90 00

   PASSO 2 — Leggi saldo:
   → 80 10 00 00 00
   ← 00 00 27 10 90 00          (10000 cent = 100,00€)

   PASSO 3 — Debita 25,00€:
   → 80 20 00 00 04 00 00 09 C4
   ← 90 00                      (successo)

   PASSO 4 — Leggi contatore:
   → 80 40 00 00 00
   ← 00 00 00 2B 90 00          (contatore = 43)

   PASSO 5 — Firma ricevuta:
   → 80 50 00 00 20 [32 byte SHA-256 hash]
   ← [64-72 byte firma ECDSA] 90 00
```

---

## Gestione Errori

### Esempi di Risposte di Errore

```
   Caso: Saldo insufficiente
   → 80 20 00 00 04 00 01 86 A0   (debito 100000 cent = 1000€)
   ← 6A 83                         "Non hai abbastanza soldi!"

   Caso: Wallet non inizializzato
   → 80 10 00 00 00
   ← 69 83                         "Wallet non ancora attivato!"

   Caso: Comando sconosciuto
   → 80 FF 00 00 00
   ← 6D 00                         "Non capisco questo comando!"

   Caso: Dati con lunghezza errata
   → 80 20 00 00 02 00 09
   ← 67 00                         "I dati hanno il formato sbagliato!"
```

---

*Documento parte del progetto SE-OFFLINE-PAYMENTS — AEGIS Protocol*
