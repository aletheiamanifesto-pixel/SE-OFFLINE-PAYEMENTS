# Applet JavaCard — AEGIS Offline Digital Euro

Questo modulo contiene l'applet JavaCard da installare su un chip Secure Element reale
(es. NXP JCOP, G+D SmartCafe, Infineon SLE97).

## Struttura

```
applet/
├── build.gradle               # Build system Gradle
├── README.md                  # Questa guida
└── src/
    └── ecb/deuro/offline/
        ├── APDUConstants.java          # Costanti comandi APDU
        ├── CryptoManager.java          # Gestione crittografia ECDSA
        ├── MonotonicCounter.java       # Contatore anti-replay
        ├── OfflineDigitalEuroApplet.java  # Entry point applet
        └── WalletState.java            # Stato del portafoglio
```

## Prerequisiti

### 1. Java Development Kit (JDK)

È richiesto JDK 11 o superiore.

```bash
java -version
# java version "11.0.x" ...
```

### 2. JavaCard Development Kit (SDK)

L'applet dipende dalle API JavaCard, **non disponibili su Maven Central**.
È necessario scaricare il SDK da Oracle:

1. Accedere a [https://www.oracle.com/java/technologies/javacard-sdk-downloads.html](https://www.oracle.com/java/technologies/javacard-sdk-downloads.html)
2. Scaricare l'ultima versione del **JavaCard Development Kit** (es. 3.1.0)
3. Estrarre l'archivio in una directory locale (es. `~/javacard-sdk/`)

### 3. Gradle

```bash
# Installare Gradle (o usare il wrapper incluso)
gradle --version
```

## Compilazione

### 1. Configurare il percorso del SDK

Aprire `build.gradle` e decommentare + aggiornare la riga delle dipendenze:

```groovy
compileOnly files('/home/utente/javacard-sdk/api_export_files/api.jar')
```

### 2. Compilare le sorgenti Java

```bash
cd applet/
gradle compileJava
```

Le classi compilate saranno in `build/classes/java/main/`.

### 3. Creare il file .cap (per installazione su chip reale)

Il file `.cap` è il formato binario installabile su una JavaCard.
Utilizzare il **converter** incluso nel JavaCard SDK:

```bash
# Linux/macOS
/path/to/javacard-sdk/bin/converter \
    -classdir build/classes/java/main \
    -exportpath /path/to/javacard-sdk/api_export_files \
    -applet 0xF0:0x41:0x45:0x47:0x49:0x53:0x00 ecb.deuro.offline.OfflineDigitalEuroApplet \
    -package ecb.deuro.offline 1.0

# Windows
converter.bat -classdir build\classes\java\main ...
```

## Installazione su Chip Reale

Una volta creato il file `.cap`, installarlo con **GlobalPlatformPro**:

```bash
# Scaricare GlobalPlatformPro: https://github.com/martinpaljak/GlobalPlatformPro
gp --install OfflineDigitalEuro.cap
```

## Test in Simulazione

Per testare l'applet senza hardware fisico, utilizzare **jCardSim**:

```bash
# Aggiungere a build.gradle:
# testImplementation 'com.klinec:jcardsim:3.0.5.11'
gradle test
```

## Deployment ID Applet

- **AID Applet**: `F0 41 45 47 49 53 00` (prefix AEGIS custom)
- **Package**: `ecb.deuro.offline`
- **Classe principale**: `OfflineDigitalEuroApplet`

## Note di Sicurezza

- La chiave privata ECDSA è generata **on-chip** e non lascia mai il Secure Element
- Il contatore monotònico è persistito in memoria non volatile (EEPROM)
- I comandi proprietari (CLA=0x80) richiedono la selezione dell'applet (SELECT) come precondizione
