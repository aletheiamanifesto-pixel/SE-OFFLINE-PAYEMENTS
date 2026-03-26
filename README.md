# 🔐 SE-OFFLINE-PAYMENTS

**Pagamenti Euro Digitali Offline su Chip NFC — Secure Element**

> Sistema di pagamento peer-to-peer offline basato su Secure Element (chip NFC) per il token AEGIS Euro.
> Parte del progetto [AEGIS Protocol](https://github.com/aletheiamanifesto-pixel/aegis-protocol).

[![CI](https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS/actions/workflows/ci.yml/badge.svg)](https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS/actions/workflows/ci.yml)
[![Licenza MIT](https://img.shields.io/badge/licenza-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-green.svg)](https://www.python.org/)

---

## 📋 Indice

1. [Cos'è questo progetto](#cosè-questo-progetto)
2. [Come funziona](#come-funziona)
3. [Struttura del repository](#struttura-del-repository)
4. [Avvio rapido](#avvio-rapido)
5. [Hardware necessario](#hardware-necessario)
6. [Documentazione](#documentazione)
7. [Glossario](#glossario)
8. [Contribuire](#contribuire)
9. [Licenza](#licenza)

---

## Cos'è questo progetto

Questo progetto implementa un sistema di **pagamento offline peer-to-peer** usando chip **Secure Element (SE)** con comunicazione **NFC**. Permette ad Alice di pagare Bob anche senza connessione internet, con le stesse garanzie di sicurezza di una carta bancaria fisica.

Il sistema è progettato per il token **AEGIS Euro** — una valuta digitale europea che può vivere su un chip fisico, esattamente come le monete vivono in un portafoglio.

### Analogia semplice

> Immagina di avere una banconota da 50€ "intelligente" dentro il tuo telefono.
> Quando la avvicini al telefono di un amico, la banconota si divide: tu ne dai 20€ e lui li riceve — tutto senza internet, tutto crittografato, tutto verificabile.

---

## Come funziona

```
📱 ALICE (PAGANTE)                    📱 BOB (RICEVENTE)
┌─────────────────────┐  NFC TAP     ┌─────────────────────┐
│  ┌───────────────┐  │◄────────────►│  ┌───────────────┐  │
│  │  Secure       │  │   APDU cmds  │  │  Secure       │  │
│  │  Element      │  │◄────────────►│  │  Element      │  │
│  │               │  │              │  │               │  │
│  │ Saldo: 100€   │  │              │  │ Saldo: 50€    │  │
│  │ Contatore: 42 │  │              │  │ Contatore: 18 │  │
│  │ Chiave ECDSA  │  │              │  │ Chiave ECDSA  │  │
│  └───────────────┘  │              │  └───────────────┘  │
└─────────────────────┘              └─────────────────────┘

           DOPO IL PAGAMENTO DI 25€:
           Alice: 75€, Cnt 43 ✓      Bob: 75€, Cnt 19 ✓
```

### Passi del pagamento

| Passo | Chi fa cosa | Descrizione |
|-------|-------------|-------------|
| 1 | Bob → Alice | Bob richiede 25€ e invia la sua chiave pubblica |
| 2 | Alice | Alice verifica saldo (100€ ≥ 25€) ✓ |
| 3 | Alice | Alice firma la transazione con ECDSA |
| 4 | Alice → Bob | Alice invia importo + firma digitale |
| 5 | Bob | Bob verifica la firma di Alice |
| 6 | Bob | Bob aggiorna il suo saldo (50€ → 75€) |
| 7 | Alice | Alice aggiorna il suo saldo (100€ → 75€) |
| 8 | Entrambi | I contatori anti-frode aumentano |

---

## Struttura del repository

```
SE-OFFLINE-PAYEMENTS/
│
├── 📖 README.md                          ← Questa guida
│
├── 📚 docs/
│   ├── 01_COME_FUNZIONA.md               ← Spiegazione dettagliata con analogie
│   ├── 02_FLUSSO_APDU.md                 ← Diagrammi messaggi tra chip
│   ├── 03_SICUREZZA.md                   ← Modello di sicurezza
│   └── 04_HARDWARE_GUIDA.md              ← Lista della spesa hardware
│
├── 💳 applet/
│   └── src/main/java/com/aegis/se/
│       ├── OfflineDigitalEuroApplet.java ← Applet principale JavaCard
│       ├── WalletState.java              ← Stato portafoglio nel chip
│       ├── CryptoManager.java            ← Crittografia ECDSA
│       ├── APDUConstants.java            ← Costanti comandi APDU
│       └── MonotonicCounter.java         ← Contatore anti-frode
│
├── 🐍 host-app/python/
│   ├── se_simulator.py                   ← Simulatore chip in Python
│   └── payment_flow.py                   ← Pagamento eseguibile
│
├── 🌉 bridge/
│   └── reconciliation_bridge.py          ← Ponte verso aegis-protocol
│
├── 🧪 tests/
│   └── test_payment_flow.py              ← 7+ test automatici
│
├── ☕ examples/
│   └── scenario_caffe.py                 ← "Alice paga un caffè a Bob"
│
└── ⚙️ .github/workflows/
    └── ci.yml                            ← CI automatica
```

---

## Avvio rapido

### Prerequisiti

- Python 3.9+
- (Opzionale) Java 11+ e JavaCard SDK per il chip reale

### Installazione

```bash
git clone https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS.git
cd SE-OFFLINE-PAYEMENTS
pip install cryptography pytest
```

### Esegui il simulatore

```bash
# Scenario completo: Alice paga un caffè a Bob
python examples/scenario_caffe.py

# Pagamento interattivo
python host-app/python/payment_flow.py

# Test automatici
python -m pytest tests/ -v
```

### Output atteso (scenario_caffe.py)

```
☕ === SCENARIO: Alice paga un caffè a Bob ===

[SETUP] Creazione portafogli...
  Alice: saldo iniziale = 50.00€
  Bob:   saldo iniziale = 10.00€

[PAGAMENTO] Alice paga 3.50€ per un caffè...
  ✓ Firma ECDSA verificata
  ✓ Transazione completata

[RISULTATO]
  Alice: 50.00€ → 46.50€  (contatore: 1)
  Bob:   10.00€ → 13.50€  (contatore: 1)
```

---

## Hardware necessario

Per eseguire il sistema su chip fisici NFC reali:

| Componente | Descrizione | Costo stimato |
|------------|-------------|---------------|
| JavaCard NFC | Chip programmabile (es. J3H145, JCOP4) | 5-15€ |
| Lettore NFC | ACR122U o ACS ACR1252U | 25-40€ |
| Raspberry Pi | Per testare senza smartphone | 35-50€ |
| Smartphone NFC | Android con NFC abilitato | già presente |

👉 Vedi [docs/04_HARDWARE_GUIDA.md](docs/04_HARDWARE_GUIDA.md) per la lista completa e i link di acquisto.

---

## Documentazione

| File | Contenuto |
|------|-----------|
| [01_COME_FUNZIONA.md](docs/01_COME_FUNZIONA.md) | Spiegazione passo-passo con analogie dal mondo reale |
| [02_FLUSSO_APDU.md](docs/02_FLUSSO_APDU.md) | Diagrammi tecnici dei messaggi APDU tra i chip |
| [03_SICUREZZA.md](docs/03_SICUREZZA.md) | Modello di sicurezza, attacchi possibili e contromisure |
| [04_HARDWARE_GUIDA.md](docs/04_HARDWARE_GUIDA.md) | Lista della spesa hardware con prezzi e link |

---

## Glossario

| Termine | Significato |
|---------|-------------|
| **SE** | Secure Element — chip blindato che protegge i dati sensibili |
| **NFC** | Near Field Communication — comunicazione wireless a corto raggio (≤4cm) |
| **APDU** | Application Protocol Data Unit — "pacchetto" di comunicazione tra chip |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm — firma digitale sicura |
| **JavaCard** | Versione di Java che gira direttamente su chip fisici |
| **Contatore monotonico** | Numero che può solo aumentare, mai diminuire (anti-frode) |
| **Applet** | Programma che gira dentro il chip Secure Element |
| **AEGIS Euro** | Token digitale euro del progetto Aegis Protocol |
| **P2P** | Peer-to-peer — comunicazione diretta tra due dispositivi |
| **Riconciliazione** | Processo di sincronizzazione con la blockchain quando torna la connessione |

---

## Architettura di sicurezza

```
┌─────────────────────────────────────────────────────────┐
│                    LIVELLI DI SICUREZZA                  │
├─────────────────────────────────────────────────────────┤
│  L3: Riconciliazione blockchain (quando c'è internet)   │
├─────────────────────────────────────────────────────────┤
│  L2: Firma ECDSA (autenticità della transazione)        │
├─────────────────────────────────────────────────────────┤
│  L1: Contatore monotonic (anti-replay, anti-frode)      │
├─────────────────────────────────────────────────────────┤
│  L0: Secure Element (isolamento hardware del chip)      │
└─────────────────────────────────────────────────────────┘
```

---

## Contribuire

1. Fai un fork del repository
2. Crea un branch: `git checkout -b feature/mia-funzione`
3. Fai commit: `git commit -m "Aggiungi: mia funzione"`
4. Push: `git push origin feature/mia-funzione`
5. Apri una Pull Request

---

## Licenza

MIT License — vedi [LICENSE](LICENSE) per i dettagli.

---

*Parte del progetto [AEGIS Protocol](https://github.com/aletheiamanifesto-pixel/aegis-protocol) — Infrastruttura finanziaria decentralizzata per l'Europa.*