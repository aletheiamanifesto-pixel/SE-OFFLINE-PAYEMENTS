# 📊 Flusso APDU — Messaggi tra i Chip

> **APDU** = Application Protocol Data Unit
> È il "linguaggio" standard con cui parlano i chip NFC/smartcard.
> Come HTTP è il linguaggio del web, APDU è il linguaggio delle smartcard.

---

## Indice

1. [Cos'è un APDU](#cosè-un-apdu)
2. [Struttura di un comando APDU](#struttura-di-un-comando-apdu)
3. [I comandi del sistema](#i-comandi-del-sistema)
4. [Flusso completo di un pagamento](#flusso-completo-di-un-pagamento)
5. [Diagramma di sequenza dettagliato](#diagramma-di-sequenza-dettagliato)
6. [Codici di risposta](#codici-di-risposta)
7. [Esempi di payload in bytes](#esempi-di-payload-in-bytes)

---

## Cos'è un APDU

Un APDU è un "pacchetto" di dati. Ogni messaggio tra l'app host e il chip è un APDU.

```
ANALOGIA: APDU è come una lettera raccomandata
─────────────────────────────────────────────
📨 Busta (header):   Chi manda, a chi, tipo messaggio
📄 Contenuto (data): Il testo della lettera
📬 Risposta:         Il destinatario risponde OK o ERRORE
```

Esistono due tipi:
- **Command APDU** (C-APDU): dall'host → al chip (una richiesta)
- **Response APDU** (R-APDU): dal chip → all'host (una risposta)

---

## Struttura di un comando APDU

```
C-APDU (Command):
┌────┬────┬────┬────┬────────────────────┬────┐
│ CLA│ INS│ P1 │ P2 │       DATA         │ Le │
└────┴────┴────┴────┴────────────────────┴────┘
  1B   1B   1B   1B   0-255 bytes          1B

CLA = Classe (0x80 = comandi proprietari)
INS = Istruzione (quale comando?)
P1  = Parametro 1 (opzioni)
P2  = Parametro 2 (opzioni)
DATA = Dati del comando
Le  = Lunghezza risposta attesa

R-APDU (Response):
┌────────────────────┬────┬────┐
│       DATA         │ SW1│ SW2│
└────────────────────┴────┴────┘
  0-255 bytes          1B   1B

SW1+SW2 = Status Word (es. 0x9000 = OK)
```

---

## I comandi del sistema

| INS | Nome | Direzione | Descrizione |
|-----|------|-----------|-------------|
| `0x10` | `SELECT` | Host→Chip | Seleziona l'applet |
| `0x20` | `GET_BALANCE` | Host→Chip | Legge il saldo corrente |
| `0x30` | `GET_PUBLIC_KEY` | Host→Chip | Ottiene la chiave pubblica |
| `0x40` | `INITIATE_PAYMENT` | Bob→Alice | Bob chiede pagamento ad Alice |
| `0x50` | `PROCESS_PAYMENT` | Alice→Bob | Alice invia la transazione firmata |
| `0x60` | `CONFIRM_PAYMENT` | Bob→Alice | Bob conferma la ricezione |
| `0x70` | `GET_COUNTER` | Host→Chip | Legge il contatore monotonico |
| `0x80` | `GET_TRANSACTION_LOG` | Host→Chip | Ottiene lo storico transazioni |
| `0xA0` | `LOAD_FUNDS` | Blockchain→Chip | Carica fondi (richiede firma CA) |

---

## Flusso completo di un pagamento

```
APP BOB              CHIP BOB           NFC            CHIP ALICE          APP ALICE
    │                    │               │                  │                   │
    │──SELECT──────────→│               │                  │                   │
    │←─9000─────────────│               │                  │                   │
    │                    │               │                  │                   │
    │──GET_PUBLIC_KEY──→│               │                  │                   │
    │←─[pubkey_bob]──────│               │                  │                   │
    │                    │               │                  │                   │
    ┌─────────── Bob avvicina il telefono ad Alice ─────────────────────────────┐
    │                    │               │                  │                   │
    │──INITIATE_PAYMENT─→│               │                  │                   │
    │  {25€, pubkey_bob} │               │                  │                   │
    │                    │──[APDU]───────→──────────────────→                   │
    │                    │  INS=0x40     │  INS=0x40        │──INITIATE────────→│
    │                    │  DATA={25€,   │  DATA={25€,      │                   │
    │                    │   pubkey_bob} │   pubkey_bob}    │                   │
    │                    │               │                  │                   │
    │                    │               │                  │  [verifica saldo] │
    │                    │               │                  │  [firma ECDSA]    │
    │                    │               │                  │                   │
    │                    │               │                  │←─PAYMENT_DATA─────│
    │                    │               │                  │  {firma, cnt, ...}│
    │                    │               │                  │                   │
    │                    │←─[APDU]───────←──────────────────│                   │
    │                    │  INS=0x50     │  INS=0x50        │                   │
    │                    │  DATA={firma} │  DATA={firma}    │                   │
    │                    │               │                  │                   │
    │                    │  [verifica]   │                  │                   │
    │                    │  [aggiorna]   │                  │                   │
    │                    │               │                  │                   │
    │←─CONFERMA──────────│               │                  │                   │
    │  {nuovo_saldo_bob} │               │                  │                   │
    │                    │──[CONFIRM]────→──────────────────→                   │
    │                    │               │                  │──CONFIRM─────────→│
    │                    │               │                  │                   │
    │                    │               │                  │  [aggiorna saldo] │
    │                    │               │                  │                   │
    ✓                    ✓               ✓                  ✓                   ✓
```

---

## Diagramma di sequenza dettagliato

### Fase 1: Selezione applet (SELECT)

```
C-APDU:
┌──────┬──────┬──────┬──────┬────────────────────────────────┐
│  00  │  A4  │  04  │  00  │ AID: A0 00 00 08 48 41 45 47 01│
└──────┴──────┴──────┴──────┴────────────────────────────────┘
 CLA   INS=   P1=    P2=    AID dell'applet AEGIS
       SELECT BY_NAME

R-APDU:
┌──────────────────────────────────────────────────┬──────┬──────┐
│  "AEGIS-EURO-v1.0"                               │  90  │  00  │
└──────────────────────────────────────────────────┴──────┴──────┘
 Nome applet                                         SW=OK
```

### Fase 2: Richiesta saldo (GET_BALANCE)

```
C-APDU:
┌──────┬──────┬──────┬──────┬──────┐
│  80  │  20  │  00  │  00  │  08  │
└──────┴──────┴──────┴──────┴──────┘
 CLA   INS=   P1    P2     Le=8bytes
       GET_BAL

R-APDU:
┌────────────────────────────┬──────┬──────┐
│  00 00 00 00 00 00 27 10   │  90  │  00  │
└────────────────────────────┴──────┴──────┘
 Saldo in centesimi (big-endian) = 10000 = 100.00€
```

### Fase 3: INITIATE_PAYMENT (da Bob ad Alice)

```
C-APDU (Bob → Alice):
┌──────┬──────┬──────┬──────┬──────────────────────────────────────────┐
│  80  │  40  │  00  │  00  │ [8B: importo] [65B: pubkey_bob] [4B: cnt]│
└──────┴──────┴──────┴──────┴──────────────────────────────────────────┘
 CLA   INS=   P1    P2     DATA (77 bytes totali)
       INIT

Dettaglio DATA:
  Byte 0-7:   Importo in centesimi (big-endian uint64)
              es. 0x0000000000000DAC = 3500 = 35.00€
  Byte 8-72:  Chiave pubblica di Bob (ECDSA P-256, non compressa, 65 byte)
              0x04 || X(32B) || Y(32B)
  Byte 73-76: Contatore corrente di Bob (big-endian uint32)

R-APDU (Alice risponde):
┌──────────────────────────────────────────────────────────────┬────┬────┐
│ [65B: pubkey_alice] [4B: cnt_alice] [72B: firma_ECDSA]       │ 90 │ 00 │
└──────────────────────────────────────────────────────────────┴────┴────┘
 141 bytes di dati + status OK
```

### Fase 4: PROCESS_PAYMENT (dati firmati)

```
C-APDU (Alice → Bob, via chip):
┌──────┬──────┬──────┬──────┬───────────────────────────────────────────────┐
│  80  │  50  │  00  │  00  │ [8B: importo] [4B: cnt_alice] [72B: firma]    │
└──────┴──────┴──────┴──────┴───────────────────────────────────────────────┘

Il chip di Bob verifica:
  1. firma_alice valida? (ECDSA verify con pubkey_alice)
  2. cnt_alice > cnt_alice_precedente? (anti-replay)
  3. importo == importo richiesto?

R-APDU (conferma):
┌────────────────────────────┬──────┬──────┐
│  00 00 00 00 00 00 1D 4C   │  90  │  00  │
└────────────────────────────┴──────┴──────┘
 Nuovo saldo di Bob = 7500 = 75.00€
```

### Fase 5: CONFIRM_PAYMENT

```
C-APDU (Bob → Alice):
┌──────┬──────┬──────┬──────┬──────────────────────────────┐
│  80  │  60  │  00  │  00  │ [8B: nuovo_saldo_bob] [72B: firma_bob] │
└──────┴──────┴──────┴──────┴──────────────────────────────┘

Alice verifica la firma di Bob e aggiorna il proprio saldo.

R-APDU:
┌──────────────────────┬──────┬──────┐
│  00 00 00 00 00 12 6C│  90  │  00  │
└──────────────────────┴──────┴──────┘
 Nuovo saldo di Alice = 4716 = 47.16€
```

---

## Codici di risposta

| SW1 | SW2 | Significato |
|-----|-----|-------------|
| `90` | `00` | ✅ Successo |
| `6A` | `82` | ❌ File o applet non trovato |
| `6D` | `00` | ❌ Istruzione non supportata |
| `69` | `82` | ❌ Condizioni di sicurezza non soddisfatte |
| `69` | `85` | ❌ Condizioni d'uso non soddisfatte |
| `6A` | `86` | ❌ Parametri P1/P2 non corretti |
| `67` | `00` | ❌ Lunghezza dati errata |
| `91` | `10` | ❌ Saldo insufficiente |
| `91` | `20` | ❌ Contatore non valido (anti-replay) |
| `91` | `30` | ❌ Firma ECDSA non valida |
| `91` | `40` | ❌ Importo non valido (zero o negativo) |
| `91` | `50` | ❌ Limite offline superato |

---

## Esempi di payload in bytes

### Esempio 1: Pagamento di 3.50€

```python
# Importo: 350 centesimi = 0x0000000000000156
importo_bytes = b'\x00\x00\x00\x00\x00\x00\x01\x56'

# Costruzione C-APDU INITIATE_PAYMENT
apdu = bytes([
    0x80,        # CLA: comandi proprietari
    0x40,        # INS: INITIATE_PAYMENT
    0x00,        # P1
    0x00,        # P2
    0x4D,        # Lc: 77 bytes di dati
]) + importo_bytes + pubkey_bob_65bytes + counter_bob_4bytes
```

### Esempio 2: Risposta GET_BALANCE

```python
# Saldo: 10000 centesimi = 100.00€
risposta_raw = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x10,
                      0x90, 0x00])

# Parsing
data = risposta_raw[:-2]          # senza SW
sw   = risposta_raw[-2:]          # SW1=0x90, SW2=0x00
saldo_centesimi = int.from_bytes(data, 'big')  # 10000
saldo_euro      = saldo_centesimi / 100        # 100.00
```

---

*Precedente: [01_COME_FUNZIONA.md](01_COME_FUNZIONA.md) — Prossimo: [03_SICUREZZA.md](03_SICUREZZA.md)*
