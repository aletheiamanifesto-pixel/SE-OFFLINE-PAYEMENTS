# 📖 Come Funziona un Pagamento Offline

> **Per chi:** chiunque voglia capire il sistema senza avere un background tecnico.
> **Obiettivo:** spiegare il pagamento offline come se stessimo parlando di banconote fisiche.

---

## Indice

1. [L'analogia della banconota intelligente](#lanalog-ia-della-banconota-intelligente)
2. [I protagonisti del sistema](#i-protagonisti-del-sistema)
3. [Il chip Secure Element: la cassaforte tascabile](#il-chip-secure-element-la-cassaforte-tascabile)
4. [Passo per passo: cosa succede durante un pagamento](#passo-per-passo-cosa-succede-durante-un-pagamento)
5. [Il problema del doppio utilizzo](#il-problema-del-doppio-utilizzo)
6. [Cosa succede quando torna internet](#cosa-succede-quando-torna-internet)
7. [Domande frequenti](#domande-frequenti)

---

## L'analogia della banconota intelligente

Immagina che le banconote fisiche potessero fare cose magiche:

```
BANCONOTA TRADIZIONALE         BANCONOTA "INTELLIGENTE" (SE)
─────────────────────         ──────────────────────────────
📄 Pezzo di carta              💳 Chip dentro al telefono
🔢 Numero seriale stampato      🔐 Chiave crittografica unica
👁️ Visibile a tutti             🔒 Dati protetti dall'hardware
✂️ Può essere falsificata        ✅ Non falsificabile
📊 Nessuna cronologia           📋 Storico delle transazioni
```

La "banconota intelligente" è il tuo **saldo nel chip**. Quando paghi, non "spedisci" una banconota — firmi digitalmente un documento che dice "trasferisco X euro dal mio chip al tuo chip".

---

## I protagonisti del sistema

### Alice — la pagante

```
┌─────────────────────────────────┐
│  📱 Telefono di Alice           │
│  ┌───────────────────────────┐  │
│  │  💳 Chip Secure Element   │  │
│  │                           │  │
│  │  Saldo: 100€              │  │
│  │  Contatore: 42            │  │
│  │  🔑 Chiave privata (segreta│  │
│  │  🗝️ Chiave pubblica (nota) │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

### Bob — il ricevente

```
┌─────────────────────────────────┐
│  📱 Telefono di Bob             │
│  ┌───────────────────────────┐  │
│  │  💳 Chip Secure Element   │  │
│  │                           │  │
│  │  Saldo: 50€               │  │
│  │  Contatore: 18            │  │
│  │  🔑 Chiave privata (segreta│  │
│  │  🗝️ Chiave pubblica (nota) │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

---

## Il chip Secure Element: la cassaforte tascabile

Il **Secure Element** è un chip fisico — come quelli nelle carte bancarie — che:

| Proprietà | Spiegazione |
|-----------|-------------|
| 🔒 **Isolato** | Il sistema operativo del telefono NON può accedere ai suoi dati |
| 🔑 **Genera chiavi** | Crea coppie di chiavi crittografiche che non escono mai dal chip |
| ✍️ **Firma** | Firma digitalmente le transazioni con la chiave privata |
| 🧮 **Conta** | Mantiene un contatore che può solo aumentare (anti-frode) |
| 💾 **Persiste** | I dati rimangono anche senza corrente (memoria flash) |

### Analogia della cassaforte

> Immagina di avere una cassaforte in tasca con uno sportellino speciale.
> Puoi dirle "firma questo documento" e lei lo firma con il suo timbro segreto.
> Ma non puoi mai aprirla e vedere il timbro — solo il risultato della firma esce dallo sportellino.

---

## Passo per passo: cosa succede durante un pagamento

Scenario: **Alice vuole pagare 25€ a Bob**.

### Fase 1: Avvicinamento dei telefoni (NFC handshake)

```
Alice 📱 ←─────── 4cm ───────→ 📱 Bob
              )))NFC(((
```

I chip si "accorgono" l'uno dell'altro e stabiliscono un canale di comunicazione sicuro.

### Fase 2: Bob fa la richiesta di pagamento

```
Bob dice ad Alice:
┌─────────────────────────────────────────────┐
│ "Voglio ricevere 25€"                       │
│ "La mia chiave pubblica è: 04:AB:CD:..."   │
│ "Il mio contatore attuale è: 18"           │
└─────────────────────────────────────────────┘
```

Questo è il messaggio **INITIATE_PAYMENT** in formato APDU.

### Fase 3: Alice verifica e firma

Il chip di Alice controlla:

```
✅ Saldo Alice (100€) ≥ Importo richiesto (25€)?  → SÌ, procedi
✅ Contatore Bob (18) > ultimo pagamento noto?     → SÌ, ok
✅ Chiave pubblica di Bob è valida?               → SÌ, ok
```

Poi **firma** il pacchetto transazione:

```
Pacchetto transazione:
┌─────────────────────────────────────────────┐
│ Importo:           25€                      │
│ Timestamp:         2024-01-15 14:32:00      │
│ Chiave pub. Alice: 04:11:22:...             │
│ Chiave pub. Bob:   04:AB:CD:...             │
│ Contatore Alice:   42 → 43                  │
│ Firma ECDSA:       [calcolata dal chip]     │
└─────────────────────────────────────────────┘
```

### Fase 4: Bob riceve e verifica

```
Bob riceve il pacchetto e verifica:
✅ La firma di Alice è autentica?  → Usa la chiave pubblica di Alice
✅ Il contatore è aumentato?       → 42 → 43, ok (non replay)
✅ L'importo è quello richiesto?   → 25€ = 25€, ok
```

### Fase 5: Aggiornamento saldi

```
PRIMA:                    DOPO:
Alice: 100€, Cnt:42      Alice: 75€,  Cnt:43
Bob:    50€, Cnt:18      Bob:   75€,  Cnt:19
```

### Diagramma completo

```
ALICE                                BOB
  │                                    │
  │         ←── RICHIESTA ───          │
  │   {"importo": 25, "pubkey_bob": …} │
  │                                    │
  │  [verifica saldo]                  │
  │  [firma transazione]               │
  │                                    │
  │         ─── TRANSAZIONE ──→        │
  │   {"importo": 25, "firma": …}      │
  │                                    │
  │                      [verifica firma]
  │                      [aggiorna saldo]
  │                                    │
  │         ←── CONFERMA ───           │
  │   {"status": "OK", "nuovo_saldo":} │
  │                                    │
  │  [aggiorna saldo Alice]            │
  │                                    │
  ✓                                    ✓
```

---

## Il problema del doppio utilizzo

### Il problema (senza contatore)

```
⚠️ ATTACCO "DOPPIO UTILIZZO"

Alice ha 100€ nel chip.
Alice paga Bob 100€ → Bob: ✓ ricevuto
Alice "resetta" il chip → saldo torna a 100€
Alice paga Carlo 100€ → Carlo: ✓ ricevuto

Risultato: Alice ha speso 200€ ma ne aveva solo 100€ ❌
```

### La soluzione (con contatore monotonico)

```
✅ PROTEZIONE CON CONTATORE

Il chip di Alice ha: Saldo=100€, Contatore=42

Alice paga Bob 100€:
  → Contatore diventa 43, registrato in blockchain

Alice prova a "resettare" il chip:
  → Il chip NON permette di diminuire il contatore
  → La blockchain rifiuta transazioni con Cnt < 43

✓ Il doppio utilizzo è impossibile
```

Il contatore è come un sigillo di cera su una busta — una volta rotto, non si può rifarlo uguale.

---

## Cosa succede quando torna internet

Quando Alice o Bob si riconnettono, il bridge di riconciliazione:

```
OFFLINE (fino a 30 giorni)           ONLINE (sincronizzazione)
──────────────────────────           ─────────────────────────

Alice paga Bob 25€    ──────────────→ [bridge] → blockchain
Bob paga Carlo 10€    ──────────────→ [bridge] → blockchain
Carlo paga Diana 5€   ──────────────→ [bridge] → blockchain

                                     La blockchain verifica:
                                     ✓ Firme valide
                                     ✓ Contatori crescenti
                                     ✓ Saldi mai negativi
```

Il bridge salva ogni transazione in un log locale e le invia in ordine quando la connessione è disponibile.

---

## Domande frequenti

**❓ Cosa succede se il telefono di Alice muore durante il pagamento?**

> La transazione è atomica: o va a buon fine completamente, o non parte. Se il telefono muore a metà, il saldo non cambia (né di Alice né di Bob) e si può riprovare.

**❓ Alice può modificare il codice del chip?**

> No. Il Secure Element è blindato fisicamente. Anche con accesso fisico al chip, estrarre o modificare il codice richiederebbe attrezzature da laboratorio che costano milioni di euro.

**❓ Quante transazioni offline si possono fare?**

> Dipende dai limiti impostati (es. max 500€ totali offline, o max 10 transazioni). Questi limiti si resettano ad ogni sincronizzazione con la blockchain.

**❓ Funziona senza NFC (Bluetooth, WiFi)?**

> L'architettura supporta qualsiasi canale di comunicazione. NFC è il default perché è il più sicuro (range massimo 4cm), ma Bluetooth e WiFi Direct sono possibili con minori garanzie fisiche.

**❓ È compatibile con le carte bancarie normali?**

> No, è un sistema separato. Ma può coesistere sulla stessa app con i pagamenti tradizionali.

---

*Prossimo: [02_FLUSSO_APDU.md](02_FLUSSO_APDU.md) — I messaggi tecnici tra i chip*
