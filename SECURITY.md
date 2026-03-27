# 🔐 Politica di Sicurezza

Questo documento descrive la politica di sicurezza del progetto **SE-OFFLINE-PAYMENTS** e le istruzioni per segnalare vulnerabilità in modo responsabile.

> ⚠️ **Nota**: il progetto è attualmente in **fase di sviluppo attivo** (simulazione). Il codice non è ancora in produzione su hardware reale. Tieni presente questo contesto quando valuti i rischi.

---

## 📋 Versioni supportate

| Versione | Supportata |
|----------|-----------|
| `main` (HEAD) | ✅ Sì |
| Branch di feature / PR | ⚠️ Solo durante la review |
| Release precedenti | ❌ No |

---

## 🚨 Come segnalare una vulnerabilità

**NON aprire una issue pubblica** per segnalare vulnerabilità di sicurezza. Le issue pubbliche sono visibili a tutti e potrebbero esporre la vulnerabilità prima che sia risolta.

### Canali preferiti

1. **GitHub Security Advisories** (preferito): usa la funzione integrata di GitHub per segnalare vulnerabilità in modo privato:
   - Vai su [Security → Advisories](https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS/security/advisories/new)
   - Clicca su "Report a vulnerability"
   - Compila il form con tutti i dettagli

2. **Email privata**: se non riesci ad usare GitHub Security Advisories, contatta il maintainer direttamente tramite il profilo GitHub [@aletheiamanifesto-pixel](https://github.com/aletheiamanifesto-pixel).

### Cosa includere nella segnalazione

Per aiutarci a valutare e risolvere il problema rapidamente, includi:

- **Descrizione** chiara della vulnerabilità
- **Componente interessato** (applet Java Card, simulatore Python, bridge di riconciliazione, protocollo APDU)
- **Passi per riprodurre** il problema
- **Impatto potenziale** (es. double-spending, bypass dell'autenticazione, perdita di fondi)
- **Proof-of-concept** (codice o sequenza APDU, se disponibile)
- **Versione/commit** in cui hai riscontrato il problema

---

## ⏱️ Tempi di risposta attesi

| Fase | Tempo atteso |
|------|-------------|
| **Acknowledgment** (conferma ricezione) | Entro 48 ore |
| **Valutazione iniziale** (triage e priorità) | Entro 7 giorni |
| **Aggiornamento sullo stato** | Ogni 14 giorni (mentre il fix è in lavorazione) |
| **Fix e disclosure coordinata** | Dipende dalla complessità (tipicamente 30–90 giorni) |

---

## 🎯 Scope — Cosa è in-scope

Le seguenti componenti sono **in-scope** per le segnalazioni di sicurezza:

| Componente | Esempi di vulnerabilità rilevanti |
|------------|----------------------------------|
| **Applet Java Card** (`se-applet/`) | Bypass del contatore monotono, manipolazione del saldo, autenticazione APDU debole |
| **Simulatore Python** (`host-sdk/`, `simulator/`) | Race condition nel flusso di pagamento, validazione insufficiente delle transazioni |
| **Bridge di riconciliazione** (`bridge/`) | Doppia spesa non rilevata, manipolazione dei log di transazione |
| **Protocollo APDU** | Attacchi replay, man-in-the-middle NFC, debolezze crittografiche |
| **Logica anti double-spending** | Qualsiasi scenario in cui Alice può spendere lo stesso importo due volte |

---

## ❌ Cosa NON segnalare come vulnerabilità

I seguenti elementi **non** sono vulnerabilità di sicurezza e vanno segnalati come normali issue:

- Bug funzionali che non hanno impatto sulla sicurezza
- Richieste di nuove funzionalità
- Problemi di performance
- Errori di documentazione
- Problemi di compatibilità con versioni specifiche di Python o Java

---

## 🔄 Processo di gestione delle vulnerabilità

Una volta ricevuta la segnalazione, seguiamo questo processo:

```
📥 Ricezione
    │
    ▼
🔍 Triage (priorità e verifica)
    │
    ├── Non riproducibile → chiusa con spiegazione
    │
    ├── Out of scope → reindirizzata a issue normale
    │
    └── Confermata → ✅
            │
            ▼
        🛠️  Sviluppo del fix (branch privato)
            │
            ▼
        🧪  Test e review interna
            │
            ▼
        📢  Disclosure coordinata con il ricercatore
            │
            ▼
        🚀  Rilascio pubblico del fix + CVE (se applicabile)
```

Il ricercatore che ha segnalato la vulnerabilità viene **sempre coinvolto** nel processo di disclosure coordinata e può rivedere il fix prima della pubblicazione.

---

## 🏆 Riconoscimenti

Crediamo nella **responsible disclosure** e nel valore enorme che i ricercatori di sicurezza portano ai progetti open-source.

I ricercatori che segnalano vulnerabilità valide in modo responsabile verranno:
- **Ringraziati pubblicamente** nella sezione "Security Acknowledgments" del README (se lo desiderano)
- **Citati** nel Security Advisory pubblico al momento della disclosure

Non offriamo bug bounty monetari al momento, ma il riconoscimento pubblico nella community è garantito.

---

## 📌 Note sul contesto del progetto

- Il progetto gestisce **pagamenti in euro digitali** — la sicurezza è una priorità assoluta
- Il codice è attualmente in **fase di simulazione** (Python puro) e non ancora deployato su hardware Secure Element reale (JCOP4 o simili)
- Il modello di sicurezza è descritto in [`docs/03_SICUREZZA.md`](docs/03_SICUREZZA.md)
- Il protocollo APDU è documentato in [`docs/02_FLUSSO_APDU.md`](docs/02_FLUSSO_APDU.md)
