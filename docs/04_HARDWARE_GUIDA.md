# 🛒 Guida Hardware — Lista della Spesa

> Tutto ciò che ti serve per eseguire il sistema su hardware reale,
> con prezzi aggiornati e link di acquisto.

---

## Indice

1. [Configurazioni disponibili](#configurazioni-disponibili)
2. [Configurazione Base — Solo Simulatore](#configurazione-base--solo-simulatore)
3. [Configurazione Standard — NFC Reale](#configurazione-standard--nfc-reale)
4. [Configurazione Avanzata — Chip JavaCard](#configurazione-avanzata--chip-javacard)
5. [Configurazione Sviluppatore — Lab Completo](#configurazione-sviluppatore--lab-completo)
6. [Guida all'acquisto chip JavaCard](#guida-allacquisto-chip-javacard)
7. [Installazione e configurazione](#installazione-e-configurazione)

---

## Configurazioni disponibili

| Configurazione | Hardware | Costo | Adatta a |
|---------------|----------|-------|----------|
| **Base** | Solo PC/Mac | 0€ | Sviluppo, testing |
| **Standard** | Lettore NFC + Raspberry Pi | ~60€ | Demo, prototipo |
| **Avanzata** | Chip JavaCard + Lettore NFC | ~80€ | Test reali |
| **Lab** | Setup completo dual-chip | ~200€ | Ricerca, produzione |

---

## Configurazione Base — Solo Simulatore

Non hai bisogno di hardware. Il simulatore Python emula il comportamento del chip.

### Requisiti software

```
Python 3.9+
pip install cryptography pytest
```

### Avvio

```bash
python examples/scenario_caffe.py
python -m pytest tests/ -v
```

✅ Perfetta per iniziare, sviluppare nuove funzionalità, e testare la logica.

---

## Configurazione Standard — NFC Reale

### Lista della spesa

| # | Componente | Modello consigliato | Prezzo | Dove comprare |
|---|-----------|--------------------|----|---------------|
| 1 | **Lettore NFC USB** | ACS ACR122U | ~30€ | Amazon, AliExpress |
| 2 | **Raspberry Pi 4** (opzionale) | 4GB RAM | ~50€ | rs-online.com |
| 3 | **Tag NFC** (per test) | NTAG215 pack 10pz | ~8€ | Amazon |

**Totale stimato: ~38€ (solo lettore) o ~88€ (con Raspberry Pi)**

### ACR122U — Il lettore NFC consigliato

```
📦 ACR122U — Specifiche
────────────────────────
✓ Interfaccia: USB (plug & play)
✓ Standard: ISO 14443 A/B, ISO 18092
✓ Frequenza: 13.56 MHz
✓ Velocità: 424 kbps
✓ Compatibilità: Windows, macOS, Linux
✓ Driver: PCSC (già incluso nel OS)
✓ Range: ≤ 5cm
```

**Link acquisto ACR122U:**
- Amazon IT: cerca "ACR122U NFC Reader"
- ACS Store ufficiale: https://www.acs.com.hk/
- Prezzo medio: 25-40€

### Installazione driver (Linux)

```bash
# Ubuntu/Debian
sudo apt-get install pcscd pcsc-tools python3-pyscard libpcsclite-dev

# Verifica connessione
pcsc_scan

# Installa libreria Python
pip install pyscard
```

### Installazione driver (macOS)

```bash
brew install pcsc-lite
pip install pyscard
```

### Test del lettore

```python
from smartcard.System import readers

r = readers()
print(f"Lettori trovati: {r}")
# Output atteso: [<ACR122U PICC Interface 00 00>]
```

---

## Configurazione Avanzata — Chip JavaCard

### Chip JavaCard consigliati

| Chip | Standard | RAM | EEPROM | Prezzo unit. | Note |
|------|----------|-----|--------|-------------|------|
| **NXP J3H145** | JavaCard 3.0.4 | 6KB | 144KB | ~8€ | Consigliato |
| **NXP JCOP4** | JavaCard 3.0.5 | 8KB | 128KB | ~15€ | Premium |
| **Infineon SLJ 9CF5120P** | JavaCard 3.0.4 | 5KB | 512KB | ~10€ | Più memoria |
| **STMicro ST33G1M2** | JavaCard 3.0.4 | 6KB | 1MB | ~12€ | Alta durabilità |

### Lista della spesa avanzata

| # | Componente | Modello | Prezzo | Link |
|---|-----------|---------|--------|------|
| 1 | **Chip JavaCard** | NXP J3H145 | ~8€ | javacard.pro, smartcardfocus.com |
| 2 | **Lettore NFC** | ACR122U | ~30€ | Amazon |
| 3 | **Adattatore ISO7816** | ACS ACR38U | ~25€ | ACS Store |
| 4 | **GlobalPlatformPro** | Software gratuito | 0€ | github.com/martinpaljak/GlobalPlatformPro |
| 5 | **JavaCard SDK** | JC 3.0.4 | 0€ | Oracle (download gratuito) |

**Totale: ~63€**

### Dove acquistare chip JavaCard

**Europa:**
- **SmartCardFocus** (UK): https://www.smartcardfocus.com/
  - NXP J3H145, NXP JCOP - da 5€ a 20€
  - Spedisce in Italia, 5-7 giorni

- **JavaCard.pro**: https://javacard.pro/
  - Vasta selezione di chip JavaCard
  - Prezzi competitivi, spedizione EU

- **CardLogix**: https://www.cardlogix.com/
  - Chip professionali con test garantiti
  - Minimo ordine più alto

**Asia (più economico, tempi lunghi):**
- **AliExpress**: cerca "JavaCard NFC" o "JCOP NFC card"
  - Prezzi 2-5€ per chip
  - Attenzione: verificare la versione JavaCard supportata
  - Tempi: 2-4 settimane

**Avvertimento**: Alcuni chip venduti online come "JavaCard" sono chip NFC semplici (NTAG) senza supporto per applet. Verifica sempre che supporti JavaCard 3.0.x.

---

## Configurazione Sviluppatore — Lab Completo

Setup per testare il sistema end-to-end con due chip reali.

### Lista della spesa completa

| # | Componente | Q.tà | Prezzo unit. | Totale | Note |
|---|-----------|------|-------------|--------|------|
| 1 | Chip JavaCard NXP J3H145 | 5 | 8€ | 40€ | Scorta |
| 2 | Lettore ACR122U | 2 | 30€ | 60€ | Uno per Alice, uno per Bob |
| 3 | Raspberry Pi 4 (4GB) | 1 | 50€ | 50€ | Server bridge |
| 4 | MicroSD 32GB | 1 | 8€ | 8€ | Per Raspberry Pi |
| 5 | Alimentatore USB-C RPi | 1 | 10€ | 10€ | |
| 6 | Cavi USB-A | 2 | 5€ | 10€ | Per i lettori |
| 7 | Case Raspberry Pi | 1 | 10€ | 10€ | Protezione |

**Totale: ~188€**

### Diagramma setup lab

```
┌─────────────────┐     USB     ┌───────────────────────────────┐
│  Laptop/PC      │─────────────│  Raspberry Pi 4               │
│  (sviluppo)     │             │  (bridge/server)              │
└─────────────────┘             │                               │
                                │  USB ──► ACR122U #1 (Alice)   │
                                │  USB ──► ACR122U #2 (Bob)     │
                                └───────────────────────────────┘
                                         │              │
                                         ▼              ▼
                                    [Chip Alice]   [Chip Bob]
                                    JavaCard NFC  JavaCard NFC
```

---

## Guida all'acquisto chip JavaCard

### Come scegliere il chip giusto

```
CHECKLIST ACQUISTO CHIP JAVACARD:
──────────────────────────────────
□ Supporta JavaCard 3.0.4 o superiore?
□ Ha almeno 4KB di RAM transiente?
□ Ha almeno 64KB di EEPROM?
□ Supporta ECDSA P-256 in hardware?
□ Ha il certificato CC EAL5+ o superiore?
□ È fornito in formato NFC (ISO 14443 A)?
□ Il venditore fornisce la specifica tecnica?
□ Ha chiavi di default GlobalPlatform (80/GP/GP)?
```

### Versioni JavaCard da usare

```
JavaCard 3.0.4 — MINIMO RICHIESTO
  ✓ ECDSA P-256
  ✓ SHA-256
  ✓ Array estesi (>255 byte)
  ✓ Transient objects

JavaCard 3.0.5 — CONSIGLIATO
  ✓ Tutto il 3.0.4 +
  ✓ API crittografiche migliorate
  ✓ Migliore gestione errori

NON USARE:
  ✗ JavaCard 2.2.x (manca ECDSA P-256 nativo)
  ✗ Chip "NFC" senza JavaCard (non supportano applet)
```

---

## Installazione e configurazione

### Passo 1: Preparare l'ambiente Java

```bash
# Scarica JavaCard SDK 3.0.4 da Oracle
# https://www.oracle.com/java/technologies/javacard-downloads.html

# Installa Apache Ant per compilare
sudo apt-get install ant

# Struttura cartelle
export JC_HOME=/path/to/javacard-sdk-304
```

### Passo 2: Compilare l'applet

```bash
cd applet
ant build

# Output: applet/build/OfflineDigitalEuroApplet.cap
```

### Passo 3: Caricare l'applet sul chip

```bash
# Scarica GlobalPlatformPro
wget https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar

# Carica l'applet (usa chiavi di default del chip vergine)
java -jar gp.jar --install applet/build/OfflineDigitalEuroApplet.cap

# Verifica installazione
java -jar gp.jar --list
# Output: APP: A0000008484145470100 (SELECTABLE)
```

### Passo 4: Testare con il simulatore Python

```bash
# Prima testa con il simulatore (senza chip fisico)
python examples/scenario_caffe.py

# Poi testa con chip fisico (richiede pyscard)
pip install pyscard
python host-app/python/payment_flow.py --real-chip
```

### Passo 5: Avviare il bridge di riconciliazione

```bash
# Configura il bridge
cp bridge/config.example.json bridge/config.json
# Modifica bridge/config.json con i tuoi endpoint AEGIS

# Avvia il bridge
python bridge/reconciliation_bridge.py
```

---

## Risoluzione problemi comuni

### "No readers found"

```bash
# Verifica che pcscd sia in esecuzione
sudo systemctl start pcscd
sudo systemctl status pcscd

# Verifica dispositivo USB
lsusb | grep ACS
# Output: Bus 001 Device 004: ID 072f:2200 Advanced Card Systems, Ltd ACR122U
```

### "Card not responding"

```
Possibili cause:
1. Il chip è posizionato male sul lettore (avvicinalo di più)
2. Il chip è un NTAG, non un JavaCard (controlla l'etichetta)
3. L'applet non è stata installata correttamente
4. Chiavi GlobalPlatform cambiate (chip non vergine)

Soluzione chiavi cambiate:
java -jar gp.jar --list  # mostrà le app installate
java -jar gp.jar --delete <AID>  # rimuovi vecchia app
java -jar gp.jar --install applet/build/...cap
```

### "ECDSA not supported"

```
Il chip non supporta ECDSA P-256 in hardware.
Opzioni:
1. Usa un chip più recente (J3H145 o JCOP4)
2. Usa il simulatore Python per lo sviluppo
```

---

*Precedente: [03_SICUREZZA.md](03_SICUREZZA.md) — Torna al [README](../README.md)*
