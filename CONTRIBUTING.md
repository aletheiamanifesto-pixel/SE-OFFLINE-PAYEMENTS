# 🤝 Guida per i Contributori

Benvenuto/a nel progetto **SE-OFFLINE-PAYMENTS**! 🎉

Siamo felici che tu voglia contribuire. Questo progetto nasce come sistema didattico e sperimentale per pagamenti offline peer-to-peer su Secure Element (chip NFC), e ogni contributo — grande o piccolo — è prezioso.

Leggi questa guida prima di aprire una PR o un'issue: ti aiuterà a capire lo stile del progetto e come lavorare insieme in modo efficace.

---

## 📚 Come funziona il progetto

Prima di contribuire, ti consigliamo di leggere:

- [`README.md`](README.md) — panoramica generale
- [`docs/01_COME_FUNZIONA.md`](docs/01_COME_FUNZIONA.md) — architettura e analogie del mondo reale
- [`docs/02_FLUSSO_APDU.md`](docs/02_FLUSSO_APDU.md) — protocollo di comunicazione NFC
- [`docs/03_SICUREZZA.md`](docs/03_SICUREZZA.md) — modello di sicurezza

---

## 🚀 Come contribuire

### 1. Fork del repository

Clicca sul pulsante **Fork** in alto a destra su GitHub per creare la tua copia del repository.

```bash
git clone https://github.com/TUO-USERNAME/SE-OFFLINE-PAYEMENTS.git
cd SE-OFFLINE-PAYEMENTS
```

### 2. Crea un branch descrittivo

Usa nomi di branch che spiegano chiaramente cosa stai facendo:

```bash
# ✅ Buoni esempi
git checkout -b fix/contatore-monotono-overflow
git checkout -b feature/app-android-nfc
git checkout -b docs/traduzione-francese
git checkout -b test/simulatore-edge-cases

# ❌ Evita nomi generici
git checkout -b fix
git checkout -b mia-modifica
```

### 3. Scrivi il codice

Segui le linee guida di stile descritte nella sezione apposita qui sotto.

### 4. Testa le modifiche

```bash
# Installa le dipendenze
pip install -r requirements.txt

# Esegui i test
pytest tests/

# Per test specifici
pytest tests/test_payment_flow.py -v
```

### 5. Apri una Pull Request

- Vai sul tuo fork su GitHub
- Clicca su **Compare & pull request**
- Scrivi una descrizione chiara di **cosa** hai fatto e **perché**
- Collega eventuali issue correlate con `Closes #123`

---

## 🎨 Stile del codice

### Python

- Segui **PEP 8** per la formattazione
- Usa **type hints** dove possibile — rendono il codice più leggibile e aiutano i nuovi contributori
- Commenti e docstring in **ITALIANO**, coerente con lo stile del progetto

```python
# ✅ Buon esempio — commento in italiano con analogia del mondo reale
def trasferisci_saldo(importo: int, mittente: SESimulator, destinatario: SESimulator) -> bool:
    """
    Trasferisce un importo dal chip di Alice al chip di Bob.
    
    È come passare banconote fisiche di mano in mano: il chip del mittente
    "consegna" i token e il chip del destinatario li "riceve".
    Non c'è banca di mezzo — è tutto peer-to-peer.
    
    Args:
        importo: importo in centesimi di euro (es. 500 = 5,00 €)
        mittente: il chip NFC di chi paga
        destinatario: il chip NFC di chi riceve
    
    Returns:
        True se il trasferimento è andato a buon fine, False altrimenti
    """
    ...
```

- Usa `snake_case` per variabili e funzioni
- Usa `UPPER_CASE` per le costanti

### Java Card

- Commenti abbondanti in **ITALIANO**
- Spiega il **PERCHÉ** di una scelta, non solo il **cosa** fa il codice
- Usa analogie del mondo reale per spiegare concetti astratti

```java
// ✅ Buon esempio — spiega il perché con un'analogia
// Il contatore monotono è come il numero di serie stampato su una banconota:
// una volta emessa con numero 42, non può tornare al 41.
// Questo impedisce gli attacchi "replay" — qualcuno che registra una transazione
// e tenta di ripeterla troverà il contatore già avanzato.
counter.increment();
```

### Documentazione

- Scrivi in **italiano** (con rare eccezioni per termini tecnici standard come APDU, NFC, ecc.)
- Usa **analogie del mondo reale**: la cassaforte, il contante, la ricevuta, il bancomat, il cassiere
- Preferisci esempi concreti (Alice paga il caffè a Bob) a descrizioni astratte
- Usa emoji con moderazione per rendere i documenti più navigabili

---

## 🛠️ Aree dove servono contributi

Ecco le aree in cui il progetto ha più bisogno di aiuto:

| Area | Difficoltà | Descrizione |
|------|-----------|-------------|
| 🔬 **Test su hardware reale** | Alta | Testare l'applet Java Card su chip JCOP4 o G+D SmartCafé |
| 📱 **App Android NFC** | Alta | Sviluppare l'app host Android che comunica col chip via NFC |
| 🧪 **Miglioramenti al simulatore** | Media | Aggiungere casi limite, attacchi simulati, scenari di errore |
| 🧪 **Test aggiuntivi** | Bassa/Media | Aumentare la copertura dei test Python con pytest |
| 🌍 **Traduzioni della documentazione** | Bassa | Tradurre i documenti in inglese, francese, tedesco, ecc. |
| 🔐 **Review del modello di sicurezza** | Alta | Analisi critica del protocollo anti double-spending |
| 📖 **Esempi e tutorial** | Bassa | Aggiungere scenari dimostrativi (oltre al caffè già presente) |
| 🐛 **Bug fix** | Variabile | Guarda le [issue aperte](https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS/issues) |

---

## 🐛 Aprire una Issue

Prima di aprire una issue, verifica che non esista già una simile.

### Per bug

Includi:
- **Descrizione** del problema
- **Passi per riprodurlo** (con codice o comandi)
- **Comportamento atteso** vs **comportamento effettivo**
- **Versione di Python** e sistema operativo

### Per richieste di funzionalità

Includi:
- **Problema che vuoi risolvere** (non solo la soluzione proposta)
- **Proposta di implementazione** (opzionale, ma utile)
- **Perché è importante** per il progetto

> 🔐 **Segnalazioni di sicurezza**: NON aprire issue pubbliche per vulnerabilità. Segui invece le istruzioni in [`SECURITY.md`](SECURITY.md).

---

## ✅ Checklist per le Pull Request

Prima di aprire una PR, verifica:

- [ ] I test esistenti passano: `pytest tests/`
- [ ] Hai aggiunto test per le nuove funzionalità (se applicabile)
- [ ] Il codice segue lo stile del progetto (italiano, analogie, type hints)
- [ ] La descrizione della PR spiega chiaramente **cosa** e **perché**
- [ ] Hai collegato eventuali issue correlate

---

## 🤝 Codice di condotta

Questo progetto adotta un approccio collaborativo e rispettoso:

- **Rispetta** le opinioni e le esperienze diverse
- **Sii costruttivo** nei feedback — critica il codice, non la persona
- **Sii paziente** con i nuovi contributori — tutti siamo stati alle prime armi
- **Sii inclusivo** — il progetto è aperto a chiunque voglia imparare o contribuire
- **Comunicazione in italiano** preferita (ma l'inglese è accettato se è più comodo per te)

Comportamenti irrispettosi, discriminatori o aggressivi non sono tollerati e potranno portare all'esclusione dal progetto.

---

## ❓ Domande?

Se hai dubbi o domande che non trovano risposta in questa guida:

1. Cerca nelle [issue esistenti](https://github.com/aletheiamanifesto-pixel/SE-OFFLINE-PAYEMENTS/issues)
2. Apri una nuova issue con il tag `domanda`
3. Contatta il maintainer tramite il profilo GitHub [@aletheiamanifesto-pixel](https://github.com/aletheiamanifesto-pixel)

Grazie per il tuo contributo! 🚀
