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

> ⚠️ Il flusso v1 qui sopra è didattico: `CREDIT` non è autenticato e chiunque potrebbe creare denaro.
> Il **protocollo v2** (`PAY` → `RECEIVE`, token firmati, certificati dell'Emittente, revoche) chiude queste falle.
> Dettagli in [`docs/05_PROTOCOLLO_V2.md`](docs/05_PROTOCOLLO_V2.md).

## 🎬 Demo in un comando

```bash
pip install cryptography
python demo.py --passo
```

Su Windows basta un doppio clic su **`avvia_demo.bat`**.

La demo simula una giornata in una mini-rete di pagamento (Emittente, il tuo telefono, il POS di un bar e quello di un'edicola):

| # | Scenario | Cosa dimostra |
|---|---|---|
| 1 | Carica 50 € dal conto al chip | Il denaro entra solo con un ordine firmato dall'Emittente; limite di detenzione 300 € |
| 2 | Paghi un caffè offline | Un tap NFC: pacchetto firmato di 237 byte |
| 3 | Sei attacchi | Replay, token manomesso, destinatario sbagliato, auto-accredito v1, chip falso, saldo insufficiente: tutti bloccati dal chip, offline |
| 4 | NFC interrotto a metà | Il token resta nel chip del pagatore e si recupera al secondo tap: niente denaro perso |
| 5 | Chip clonato | La doppia spesa offline passa: è il limite intrinseco dell'offline |
| 6 | Riconciliazione | L'Emittente scopre la frode, revoca il chip e distribuisce la lista revoche |
| 7 | Scarico e bilancio | Il bar versa l'incasso sul conto; i conti quadrano, perdite incluse |

Senza `--passo` la demo gira tutta di fila ed esce con codice 1 se un controllo non dà il risultato atteso (la usa la CI).

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
python demo.py                          # protocollo v2, scenari completi
python host_app/python/payment_flow.py  # protocollo v1, flusso APDU base
```

### 6. Esegui lo scenario caffè ☕

```bash
python examples/scenario_caffe.py
```

Alice entra al bar di Bob, ordina un espresso e un cornetto (2.70€), e paga offline con il suo Secure Element.

## 🐳 Docker

```bash
docker build -t aegis-offline-payments .
docker run --rm aegis-offline-payments                              # demo
docker run --rm aegis-offline-payments python -m pytest tests/ -v   # test
```

## 📁 Struttura del Progetto

```
SE-OFFLINE-PAYEMENTS/
├── demo.py                    # Demo completa del protocollo v2 (7 scenari)
├── avvia_demo.bat / .sh       # Lanciatori con un clic
├── host_app/python/
│   ├── se_simulator.py        # Simulatore Secure Element (ECDSA reale, comandi APDU v1 + v2)
│   ├── protocollo_v2.py       # Formati binari e crittografia del protocollo v2
│   ├── pagamento_v2.py        # Terminale/POS: PAY, RECEIVE, recupero NFC interrotto
│   └── payment_flow.py        # Flusso pagamento v1 (didattico)
├── bridge/
│   ├── emittente.py           # Emittente: certifica, carica/scarica, riconcilia, revoca
│   └── reconciliation_bridge.py  # Riconciliazione offline → blockchain AEGIS
├── applet/                    # Applet JavaCard per chip NFC reali
│   ├── build.gradle
│   ├── README.md
│   └── src/ecb/deuro/offline/
├── tests/
│   ├── test_payment_flow.py   # Test del protocollo v1
│   └── test_protocollo_v2.py  # Test del protocollo v2 e della demo
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
- **Protocollo v2**: denaro in ingresso solo con ordini firmati dall'Emittente o token firmati da chip certificati; `PAY` atomico; firme con separazione di dominio; scoperta delle doppie spese e lista revoche

### Stato del progetto

| Componente | Stato |
|---|---|
| Simulatore Python, protocollo v2, Emittente, demo | ✅ Funzionante e testato |
| Applet JavaCard | ⚠️ Implementa ancora il protocollo v1 (saldo massimo 327,67 €, `CREDIT` non autenticato): il porting del v2 è il prossimo passo |
| Privacy "tipo contante" (e-cash / ZK) | 🔜 Da progettare: oggi l'Emittente vede i pagamenti riconciliati |

Per segnalare vulnerabilità, leggi [`SECURITY.md`](SECURITY.md) — **non aprire issue pubbliche**.

## 📚 Documentazione

| Documento | Contenuto |
|---|---|
| [`docs/01_COME_FUNZIONA.md`](docs/01_COME_FUNZIONA.md) | Architettura del sistema |
| [`docs/02_FLUSSO_APDU.md`](docs/02_FLUSSO_APDU.md) | Dettaglio comandi APDU |
| [`docs/03_SICUREZZA.md`](docs/03_SICUREZZA.md) | Modello di sicurezza |
| [`docs/04_HARDWARE_GUIDA.md`](docs/04_HARDWARE_GUIDA.md) | Guida all'hardware reale |
| [`docs/05_PROTOCOLLO_V2.md`](docs/05_PROTOCOLLO_V2.md) | Protocollo v2: falle del v1, comandi, formati, doppia spesa |
| [`applet/README.md`](applet/README.md) | Compilazione e deploy JavaCard |

## Contribuire

Contribuzioni benvenute! Leggi [`CONTRIBUTING.md`](CONTRIBUTING.md) per sapere come iniziare.

## Licenza

[MIT License](LICENSE) — Copyright (c) 2026 aletheiamanifesto-pixel