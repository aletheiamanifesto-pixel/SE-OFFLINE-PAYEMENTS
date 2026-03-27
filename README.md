# 🔐 SE-OFFLINE-PAYMENTS

**Pagamenti Euro Digitali Offline su Chip NFC — Secure Element**

> Sistema di pagamento peer-to-peer offline basato su Secure Element (chip NFC) per il token AEGIS Euro.
> Parte del progetto [AEGIS Protocol](https://github.com/aletheiamanifesto-pixel/aegis-protocol).

⏳ **Struttura completa in arrivo...** La Pull Request con tutto il codice è in preparazione.

## Come funziona (anteprima)

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

## Contribuire

Contribuzioni benvenute! Leggi [`CONTRIBUTING.md`](CONTRIBUTING.md) per sapere come iniziare.

Per segnalare vulnerabilità di sicurezza, segui le istruzioni in [`SECURITY.md`](SECURITY.md) — **non aprire issue pubbliche**.

## Licenza

[MIT License](LICENSE) — Copyright (c) 2026 aletheiamanifesto-pixel