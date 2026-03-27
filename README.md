# 🔐 SE-OFFLINE-PAYMENTS

**Pagamenti Euro Digitali Offline su Chip NFC — Secure Element**

> Sistema di pagamento peer-to-peer offline basato su Secure Element (chip NFC) per il token AEGIS Euro.
> Parte del progetto [AEGIS Protocol](https://github.com/aletheiamanifesto-pixel/aegis-protocol).

## Come funziona

```
📱 Alice (PAGA)              📱 Bob (RICEVE)
┌──────────────┐  NFC TAP   ┌──────────────┐
│ Chip blindato│◄───────────►│ Chip blindato│
│ Saldo: 100€  │             │ Saldo: 50€   │
│ Contatore: 42│             │ Contatore: 18│
└──────────────┘             └──────────────┘

DOPO IL PAGAMENTO DI 25€:
Alice: 75€, Cnt 43           Bob: 75€, Cnt 19
```

## Struttura del Progetto

```
SE-OFFLINE-PAYMENTS/
├── se-applet/                  # Java Card applet per Secure Element
│   └── src/com/aegis/se/
│       ├── AegisPaymentApplet.java   # Dispatcher APDU principale
│       ├── TransactionManager.java   # Gestione saldo, contatore, ricevute
│       ├── CryptoEngine.java         # ECDSA secp256k1, SHA-256
│       └── Constants.java            # Costanti del protocollo
│
├── host-sdk/                   # SDK Python per il dispositivo host
│   └── aegis_se/
│       ├── apdu.py             # Builder/parser comandi APDU
│       ├── secure_element.py   # Comunicazione con il SE
│       ├── payment.py          # Protocollo di pagamento P2P
│       ├── transaction.py      # Modello ricevuta transazione
│       ├── sync.py             # Sincronizzazione online
│       └── exceptions.py       # Gerarchia eccezioni
│
├── simulator/                  # Simulatore SE senza hardware
│   ├── se_simulator.py         # Emulazione completa del chip SE
│   └── demo.py                 # Demo interattiva P2P
│
├── tests/                      # Test suite
│   ├── test_applet.py          # Test simulatore e APDU
│   ├── test_payment.py         # Test protocollo pagamento
│   └── test_protocol.py        # Test edge cases e sicurezza
│
├── docs/                       # Documentazione
│   ├── architecture.md         # Architettura del sistema
│   └── protocol.md             # Specifica protocollo APDU
│
├── pyproject.toml              # Configurazione progetto Python
├── requirements.txt            # Dipendenze
└── LICENSE                     # MIT
```

## Quick Start

### Installazione

```bash
# Clona il repository
git clone https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS.git
cd SE-OFFLINE-PAYEMENTS

# Installa le dipendenze
pip install -r requirements.txt

# Installa in modalità sviluppo (opzionale)
pip install -e ".[dev]"
```

### Esegui la Demo

```bash
python simulator/demo.py
```

Output:
```
╔══════════════════════════════════════════════════════╗
║     🔐  AEGIS Offline Payments — Demo               ║
║     Secure Element P2P Payment Simulator             ║
╚══════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════
  STEP 1: Initialize Secure Elements
═══════════════════════════════════════════════════════
  ✅ Alice's SE initialized
  ✅ Bob's SE initialized
  ...
  Alice: 85.00 €  (counter: 2)
  Bob:   65.00 €  (counter: 2)
```

### Esegui i Test

```bash
pytest tests/ -v
```

## Flusso di Pagamento

```
    Alice (Mittente)                    Bob (Destinatario)
    ┌──────────┐                        ┌──────────┐
    │   Host   │                        │   Host   │
    └────┬─────┘                        └────┬─────┘
         │                                   │
    ①  GET_PUBLIC_KEY ──── NFC ────────────► │
         │  ◄──── bob_pubkey (33B) ────────  │
         │                                   │
    ②  INITIATE_PAYMENT(bob_pk, 25€, ts)     │
         │  SE: -25€, cnt++, firma           │
         │  ◄── ricevuta firmata             │
         │                                   │
    ③  ricevuta ──── NFC ─────────────────► │
         │                                   │
         │               ④  RECEIVE_PAYMENT  │
         │                  SE: verifica,    │
         │                      +25€, cnt++ │
         │                                   │
    ⑤  Entrambi salvano la ricevuta          │
    ┌────┴─────┐                        ┌────┴─────┐
    │   Fatto  │                        │   Fatto  │
    └──────────┘                        └──────────┘
```

## Sicurezza

| Minaccia | Mitigazione |
|---|---|
| Estrazione chiave privata | Generata e custodita nel SE; mai esportata |
| Manomissione saldo | Saldo in memoria persistente SE; aggiornamenti atomici |
| Doppia spesa | Contatore monotonico + sincronizzazione ledger |
| Replay attack | Contatore + timestamp nella ricevuta firmata |
| Man-in-the-middle | Firma ECDSA copre tutti i campi della ricevuta |
| Brute force PIN | Blocco dopo 3 tentativi |

## Crittografia

| Primitiva | Algoritmo | Standard |
|---|---|---|
| Coppia chiavi | ECDSA secp256k1 | SEC 2 |
| Firma | ECDSA SHA-256 | FIPS 186-4 |
| Hash | SHA-256 | FIPS 180-4 |
| Formato firma | DER-encoded | X.690 |

## Documentazione

- [Architettura del Sistema](docs/architecture.md)
- [Specifica Protocollo APDU](docs/protocol.md)

## Licenza

MIT License — vedi [LICENSE](LICENSE)