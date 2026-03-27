# 🔐 SE-OFFLINE-PAYMENTS

**Pagamenti Euro Digitali Offline su Chip NFC — Secure Element**

[![CI](https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS/actions/workflows/ci.yml/badge.svg)](https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS/actions/workflows/ci.yml)

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

Il pagamento avviene **completamente offline** tramite 7 passaggi APDU:
1. `SELECT` — attivazione applet su entrambi i chip
2. `GET_BALANCE` — verifica saldi iniziali
3. `DEBIT` — addebito su Alice
4. `CREDIT` — accredito su Bob
5. `SIGN` — Alice firma la ricevuta digitale con ECDSA
6. `VERIFY` — Bob verifica la firma con la chiave pubblica di Alice
7. `GET_COUNTER` — aggiornamento contatori anti-replay

Quando torna la connessione, il `ReconciliationBridge` riconcilia le transazioni con la blockchain AEGIS.

## 🚀 Quick Start

### 1. Clona il repository

```bash
git clone https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS.git
cd SE-OFFLINE-PAYEMENTS
```

### 2. Crea un ambiente virtuale

```bash
python3.11 -m venv venv
source venv/bin/activate   # Linux/macOS
# oppure: venv\Scripts\activate  # Windows
```

### 3. Installa in modalità sviluppo

```bash
pip install -e ".[dev]"
```

### 4. Esegui i test

```bash
python -m pytest tests/ -v
```

### 5. Esegui la demo del flusso di pagamento

```bash
python host-app/python/payment_flow.py
```

### 6. Esegui lo scenario caffè ☕

```bash
python examples/scenario_caffe.py
```

Alice entra al bar di Bob, ordina un espresso e un cornetto (2.70€), e paga offline con il suo Secure Element.

## 🐳 Docker

```bash
docker build -t aegis-offline-payments .
docker run --rm aegis-offline-payments
```

## 📁 Struttura del Progetto

```
SE-OFFLINE-PAYEMENTS/
├── host-app/python/
│   ├── se_simulator.py        # Simulatore Secure Element (ECDSA reale, comandi APDU)
│   └── payment_flow.py        # Flusso pagamento offline completo
├── bridge/
│   └── reconciliation_bridge.py  # Riconciliazione offline → blockchain AEGIS
├── applet/                    # Applet JavaCard per chip NFC reali
│   ├── build.gradle
│   ├── README.md
│   └── src/ecb/deuro/offline/
├── tests/
│   └── test_payment_flow.py   # Suite di test completa
├── examples/
│   └── scenario_caffe.py      # Demo: Alice compra un caffè
├── docs/                      # Documentazione tecnica
├── pyproject.toml             # Packaging Python
└── Dockerfile
```

## 🔒 Sicurezza

- **ECDSA secp256r1** per firme digitali (standard passaporti elettronici e carte bancarie)
- **Contatore monotònico** anti-replay: ogni transazione incrementa un contatore non azzerabile
- **Flag `_selected`**: i comandi proprietari richiedono la selezione dell'applet (SELECT) come precondizione
- **Saldo massimo**: protezione da overflow — limite di 10.000,00€ per portafoglio
- **Verifica ECDSA nel bridge**: il `ReconciliationBridge` può verificare crittograficamente le firme tramite un registry di chiavi pubbliche

Per segnalare vulnerabilità, leggi [`SECURITY.md`](SECURITY.md) — **non aprire issue pubbliche**.

## 📚 Documentazione

| Documento | Contenuto |
|---|---|
| [`docs/01_COME_FUNZIONA.md`](docs/01_COME_FUNZIONA.md) | Architettura del sistema |
| [`docs/02_FLUSSO_APDU.md`](docs/02_FLUSSO_APDU.md) | Dettaglio comandi APDU |
| [`docs/03_SICUREZZA.md`](docs/03_SICUREZZA.md) | Modello di sicurezza |
| [`docs/04_HARDWARE_GUIDA.md`](docs/04_HARDWARE_GUIDA.md) | Guida all'hardware reale |
| [`applet/README.md`](applet/README.md) | Compilazione e deploy JavaCard |

## Contribuire

Contribuzioni benvenute! Leggi [`CONTRIBUTING.md`](CONTRIBUTING.md) per sapere come iniziare.

## Licenza

[MIT License](LICENSE) — Copyright (c) 2026 aletheiamanifesto-pixel