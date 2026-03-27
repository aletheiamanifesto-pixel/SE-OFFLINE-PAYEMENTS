# 🛒 Guida Hardware — Cosa Comprare e Come Iniziare

## Introduzione

Per sperimentare con i pagamenti offline su Secure Element, servono
pochi componenti dal costo contenuto. Questa guida ti accompagna
passo dopo passo: dalla lista della spesa all'installazione dell'applet.

---

## Lista della Spesa

### Componenti Essenziali

| Componente | Descrizione | Prezzo | Dove comprare |
|-----------|-------------|--------|---------------|
| **JCOP4 J3R180** | Smart card Java Card 3.0.4+ | ~15€ | Amazon, CardLogix |
| **ACR122U** | Lettore NFC USB per PC | ~35€ | Amazon, eBay |
| **Cavo USB** | Per collegare il lettore al PC | ~3€ | Qualsiasi negozio |

### Componenti Opzionali

| Componente | Descrizione | Prezzo | Dove comprare |
|-----------|-------------|--------|---------------|
| **SIM Java Card** | Formato mini-SIM con Java Card | ~8€ | eBay, AliExpress |
| **Portacarte NFC** | Per trasportare la smart card | ~5€ | Amazon |
| **Smartphone NFC** | Android con NFC (per test mobile) | Già posseduto | — |

### Budget Totale

```
   ┌────────────────────────────────────┐
   │       BUDGET MINIMO                │
   │                                    │
   │  JCOP4 J3R180:     ~15€           │
   │  ACR122U reader:   ~35€           │
   │  Cavo USB:         ~ 3€           │
   │  ──────────────────────────       │
   │  TOTALE:           ~53€           │
   │                                    │
   │  Con opzionali:    ~60€           │
   └────────────────────────────────────┘
```

---

## Dove Comprare

### Amazon (Consigliato per velocità)

- **JCOP4 J3R180**: cerca "JCOP4 Java Card" o "J3R180 smart card"
  - Venditore consigliato: cerca quelli con "Java Card 3.0.4" nel titolo
  - Verifica che supporti **GlobalPlatform 2.2.1** o superiore
  - Prezzo tipico: 12-18€ per singola carta

- **ACR122U**: cerca "ACR122U NFC reader"
  - È il lettore NFC più diffuso e supportato
  - Compatibile con Windows, Linux e macOS
  - Prezzo tipico: 30-40€

### CardLogix (Specializzati in smart card)

- Sito: https://www.cardlogix.com
- Vendono JCOP4 singole o in pacchetti da 5/10
- Spedizione internazionale disponibile
- Ideale per chi vuole carte certificate

### eBay (Per risparmiare)

- Cerca "JCOP4" o "Java Card blank"
- Prezzo spesso più basso ma tempi di spedizione più lunghi
- Verifica la versione Java Card (minimo 3.0.4)
- Attenzione ai venditori dalla Cina: qualità variabile

---

## Confronto Form Factor

| Form Factor | Pro | Contro | Prezzo | Uso ideale |
|-------------|-----|--------|--------|------------|
| **Smart Card ISO** | Standard, facile da usare con ACR122U | Grande, serve lettore | ~15€ | Sviluppo e test su PC |
| **SIM Card** | Piccola, entra nel telefono | Serve adattatore, limitata | ~8€ | Test su Android |
| **MicroSD Java Card** | Entra nello slot SD | Rara, costosa, poca scelta | ~25€ | Dispositivi senza NFC |
| **Wearable (anello/bracciale)** | Pratico, sempre addosso | Costoso, poca memoria | ~30€+ | Uso quotidiano futuro |
| **Sticker NFC** | Adesivo, si attacca ovunque | Fragile, poca sicurezza | ~5€ | Solo prototipazione |

### Consiglio per Iniziare

Per lo sviluppo, consigliamo la **Smart Card ISO + ACR122U**.
È la combinazione più affidabile e meglio supportata dalla comunità.

---

## Come Caricare l'Applet sul Chip

### Prerequisiti Software

1. **Java JDK 8 o 11** (non versioni più recenti per compatibilità)
2. **GlobalPlatformPro** (gp.jar) — tool per caricare applet su Java Card
3. **Java Card SDK 3.0.4** — per compilare l'applet
4. **Driver ACR122U** — su Linux di solito non servono

### Passo 1: Scaricare GlobalPlatformPro

```bash
# Scarica l'ultima versione da GitHub
# https://github.com/martinpaljak/GlobalPlatformPro/releases
wget https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar
```

### Passo 2: Verificare la Connessione

```bash
# Inserisci la smart card nel lettore ACR122U
# Collega il lettore al PC via USB

# Verifica che il lettore veda la carta
java -jar gp.jar --info

# Output atteso:
# Reader: ACS ACR122U
# ATR: 3B...
# ISD: A000000003000000 (Issuer Security Domain)
```

### Passo 3: Compilare l'Applet

```bash
# Compila con il Java Card SDK
# (il percorso dipende dalla tua installazione)
javac -target 1.6 -source 1.6 \
  -cp /path/to/javacard-sdk/lib/api_classic.jar \
  -d build/ \
  applet/src/ecb/deuro/offline/*.java

# Crea il file CAP (Java Card Archive Package)
# Questo passo richiede il converter del Java Card SDK
```

### Passo 4: Caricare l'Applet

```bash
# Carica il file CAP sulla smart card
java -jar gp.jar --install applet.cap

# Verifica che l'applet sia installato
java -jar gp.jar --list

# Output atteso:
# AID: D2760000604101 (il nostro applet)
# State: SELECTABLE
```

### Passo 5: Test Rapido

```bash
# Seleziona l'applet
java -jar gp.jar --apdu 00A4040007D2760000604101

# Leggi il saldo
java -jar gp.jar --apdu 8010000000

# Se tutto OK, vedrai la risposta con il saldo e SW=9000
```

---

## Setup Android NFC

### Requisiti

- Smartphone Android con **NFC** (quasi tutti i telefoni dal 2018 in poi)
- Android 6.0 (Marshmallow) o superiore
- NFC attivato nelle impostazioni

### Come Attivare NFC su Android

1. Vai in **Impostazioni** → **Connessioni** (o "Wireless")
2. Cerca **NFC** e attivalo
3. Assicurati che "Android Beam" o "Tocca e paga" sia attivo
4. Posiziona la smart card sul retro del telefono (zona NFC)

### Test con App Generica

Prima di usare la nostra app, verifica che l'NFC funzioni:
1. Scarica **NFC Tools** dal Play Store (gratuita)
2. Avvicina la smart card al telefono
3. Dovresti vedere le informazioni della carta (ATR, tecnologie)
4. Se funziona, il tuo telefono è pronto!

---

## Risoluzione Problemi Comuni

### Il lettore ACR122U non viene riconosciuto

```
Problema: Il PC non vede il lettore USB
Soluzioni:
1. Prova un'altra porta USB (preferibilmente USB 2.0)
2. Su Linux: installa pcscd → sudo apt install pcscd
3. Su Linux: avvia il demone → sudo systemctl start pcscd
4. Su Windows: installa i driver dal sito ACS
5. Prova con un altro cavo USB
```

### La smart card non risponde

```
Problema: Il lettore vede la carta ma non risponde ai comandi
Soluzioni:
1. Verifica che la carta sia JCOP (non tutte le carte NFC sono Java Card)
2. Controlla l'orientamento della carta nel lettore
3. Pulisci i contatti della carta con un panno morbido
4. Prova con gp.jar --info per diagnostica
5. La carta potrebbe essere bloccata (locked) — serve sbloccarla
```

### Errore "Card not found" su Android

```
Problema: L'app non trova la smart card via NFC
Soluzioni:
1. Assicurati che NFC sia attivo nelle impostazioni
2. Prova a posizionare la carta in punti diversi del telefono
3. La zona NFC varia per ogni modello (di solito al centro-alto)
4. Rimuovi la cover del telefono (alcune bloccano NFC)
5. Riavvia il telefono e riprova
```

### Errore durante il caricamento dell'applet

```
Problema: gp.jar restituisce errori durante l'installazione
Soluzioni:
1. Verifica la versione Java: java -version (serve JDK 8 o 11)
2. Controlla che il file CAP sia compilato per la versione giusta
3. Se "Card locked": serve la chiave di default o una nuova
4. Se "Insufficient memory": l'applet è troppo grande per la carta
5. Prova --force per forzare la reinstallazione
```

---

## Risorse Utili

| Risorsa | Link | Descrizione |
|---------|------|-------------|
| GlobalPlatformPro | github.com/martinpaljak/GlobalPlatformPro | Tool per gestire smart card |
| Java Card SDK | oracle.com/java/technologies/javacard-sdk | SDK ufficiale Oracle |
| ACR122U Docs | acs.com.hk/en/products/3/acr122u | Documentazione del lettore |
| Java Card Forum | javacardforum.com | Comunità di sviluppatori |
| NFC Tools (Android) | Play Store | App per test NFC |

---

## Usare il Codice con Hardware Reale

### Switchare tra Simulatore e Hardware con la Factory

Il modo più semplice per cambiare backend è usare la factory `create_secure_element`.
Basta cambiare il parametro `backend` — il resto del codice rimane identico.

```python
from host_app.python.se_factory import create_secure_element

# In sviluppo — nessun hardware necessario
se = create_secure_element("simulator", initial_balance=10000)

# In produzione — smart card fisica con ACR122U
se = create_secure_element("pcscard", reader_name="ACS ACR122U", timeout_ms=5000)

# Entrambi si usano allo stesso modo grazie all'interfaccia comune
saldo = se.get_balance()
print(f"Saldo: {saldo / 100:.2f}€")
```

### Usare i Profili Hardware

I profili di configurazione in `config/hardware_profiles.yaml` permettono
di definire i parametri una volta sola e riutilizzarli in tutto il progetto.

```python
import yaml
from host_app.python.se_factory import create_from_profile

# Carica i profili dal file di configurazione
with open("config/hardware_profiles.yaml") as f:
    config = yaml.safe_load(f)

# Seleziona il profilo in base all'ambiente
profilo_nome = os.environ.get("SE_PROFILE", "development")
profilo = config["profiles"][profilo_nome]

# Crea il Secure Element con i parametri del profilo
se = create_from_profile(profilo)
print(f"Backend attivo: {profilo['backend']}")
```

Profili disponibili:
- `development` — simulatore Python (per sviluppo locale)
- `test_acr122u` — smart card fisica con lettore ACR122U
- `test_android` — smartphone Android con NFC
- `staging` — pre-produzione con hardware reale
- `ci` — integrazione continua senza hardware

### Esempio Completo: Pagamento su Carta Reale

```python
import yaml
from host_app.python.se_factory import create_from_profile
from host_app.python.resilient_payment import ResilientPaymentFlow

# Carica la configurazione per hardware reale
with open("config/hardware_profiles.yaml") as f:
    config = yaml.safe_load(f)

profilo_acr122u = config["profiles"]["test_acr122u"]

# Crea i due Secure Element (pagatore e ricevente)
# In un caso reale, sarebbero due carte fisiche diverse
pagatore = create_from_profile(profilo_acr122u)
ricevente = create_from_profile(profilo_acr122u)

# Usa il flusso resiliente con retry automatico e rollback
flusso = ResilientPaymentFlow(max_retries=3)

try:
    importo = 2500  # 25.00€
    successo = flusso.esegui_pagamento(pagatore, ricevente, importo=importo)
    
    if successo:
        print(f"✅ Pagamento di {importo/100:.2f}€ completato!")
        print(f"   Saldo pagatore:  {pagatore.get_balance()/100:.2f}€")
        print(f"   Saldo ricevente: {ricevente.get_balance()/100:.2f}€")
    else:
        print("❌ Pagamento non riuscito (saldo insufficiente o errore)")

except TornTransactionError as e:
    print(f"⚠️  TORN TRANSACTION: {e}")
    print(f"   Importo coinvolto: {e.amount/100:.2f}€")
    print(f"   Debit avvenuto: {e.payer_debited}")
    print(f"   Credit avvenuto: {e.receiver_credited}")
    print("   Avvia la riconciliazione manuale!")
```

### Eseguire i Test Hardware

I test hardware sono marcati con `@pytest.mark.hardware` e vengono
automaticamente saltati se il lettore non è collegato.

```bash
# Esegui tutti i test (i test hardware vengono saltati se non c'è lettore)
pytest tests/ -v

# Esegui SOLO i test hardware (richiede ACR122U + smart card)
pytest tests/ -v -m hardware

# Esegui SOLO i test dell'architettura (nessun hardware)
pytest tests/test_hardware_integration.py -v -m "not hardware"
```

---

*Documento parte del progetto SE-OFFLINE-PAYMENTS — AEGIS Protocol*
