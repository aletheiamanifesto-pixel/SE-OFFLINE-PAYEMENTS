# 05 — Protocollo v2: pagamenti offline sicuri

## Perché serve un v2

Il protocollo v1 (`DEBIT` → `CREDIT` → `SIGN` → `VERIFY`) dimostra il flusso APDU, ma ha tre falle che in un sistema con denaro vero sarebbero fatali:

| Falla v1 | Conseguenza |
|---|---|
| `CREDIT` non è autenticato | Chiunque può mandare `CREDIT` al proprio chip e **creare denaro dal nulla** |
| La firma arriva *dopo* addebito e accredito, e non contiene pagatore né beneficiario | Il beneficiario accredita prima di verificare; una ricevuta può essere riusata verso un altro chip |
| `SIGN` firma qualsiasi dato | Il chip diventa un "oracolo": un terminale malevolo può fargli firmare ricevute arbitrarie |
| Nessun certificato | Il beneficiario si fida di qualunque chiave pubblica gli venga presentata |

Il v1 resta disponibile in **modalità sviluppo** (chip non personalizzato) per compatibilità con i test e gli esempi esistenti.

## Le regole del v2

1. **Il denaro entra in un chip solo in due modi**: un ordine `LOAD` firmato dall'Emittente, oppure un token di pagamento firmato da un altro chip certificato (`RECEIVE`).
2. **`PAY` è atomico**: addebito, incremento del contatore e firma del token avvengono in un'unica operazione. Il token contiene pagatore, beneficiario, importo e contatore.
3. **Ogni chip ha un certificato** firmato dall'Emittente, con il limite di detenzione. Il beneficiario lo verifica offline.
4. **Dopo la personalizzazione** `DEBIT` e `CREDIT` v1 sono bloccati (`0x6982`), e `SIGN`/`MUTUAL_AUTH` rifiutano dati che iniziano con il prefisso riservato `AG`.

## Attori

```
          ONLINE                         OFFLINE (solo NFC)                       ONLINE
 Emittente ──LOAD firmato──► [chip pagatore] ──PAY──► pacchetto 237 B ──RECEIVE──► [chip POS]
     ▲                                                                              │
     └──────────── sincronizza (registro POS) · lista revoche · UNLOAD ◄────────────┘
```

| Attore | Codice | Ruolo |
|---|---|---|
| Chip (Secure Element) | `host_app/python/se_simulator.py` | Custodisce saldo, chiave, contatore; verifica tutto da solo |
| Terminale / POS | `host_app/python/pagamento_v2.py` | Fa da "postino" tra i chip, tiene il registro |
| Emittente | `bridge/emittente.py` | Certifica, carica/scarica, riconcilia, revoca |
| Formati | `host_app/python/protocollo_v2.py` | Strutture binarie e crittografia condivise |

## Comandi APDU (CLA `0x80`)

| INS | Nome | Dati in ingresso | Risposta |
|---|---|---|---|
| `0x90` | PERSONALIZE | chiave Emittente (65) + certificato (145) | device_id (8) |
| `0x8E` | GET_DEVICE_ID | — | device_id (8) |
| `0x88` | LOAD | ordine firmato (88) | nuovo saldo (4) |
| `0x8A` | UNLOAD | ordine firmato (88) | firma di conferma del chip (64) |
| `0x82` | PAY | payee_id (8) + importo (4) | pacchetto (237) |
| `0x84` | RECEIVE | pacchetto (237) | nuovo saldo (4) |
| `0x86` | GET_LAST_PAYMENT | — | ultimo pacchetto emesso (237) |
| `0x8C` | UPDATE_REVOCATIONS | lista firmata | versione (4) |

Tutti i messaggi stanno in un APDU *short* (≤ 255 byte), quindi il protocollo è portabile su JavaCard senza APDU estesi.

## Formati binari

```
Token        "AGP2" | payer_id(8) | payee_id(8) | importo(4) | contatore(4)          28 B
Certificato  "AGC2" | device_id(8) | chiave_pubblica(65) | limite(4) | firma(64)    145 B
Pacchetto    token(28) | firma_pagatore(64) | certificato(145)                      237 B
Ordine       "AGL2"|"AGU2" | device_id(8) | importo(4) | nonce(8) | firma(64)        88 B
Revoche      "AGR2" | versione(4) | n(1) | n × device_id(8) | firma(64)
```

- `device_id` = primi 8 byte di SHA-256 della chiave pubblica del chip.
- Firme ECDSA P-256 / SHA-256 in formato grezzo `r||s` (64 byte).
- Ogni tipo di messaggio ha un'etichetta diversa (*domain separation*): una firma valida per un ordine non vale come token.

## Controlli del beneficiario (RECEIVE), tutti offline

1. Il certificato del pagatore è firmato dall'Emittente → altrimenti `0x6982`
2. Il pagatore non è nella lista revoche → `0x6A81`
3. La firma del token corrisponde alla chiave del certificato → `0x6982`
4. Il token è destinato a questo chip → `0x6A80`
5. Il contatore è maggiore dell'ultimo visto da quel pagatore → `0x6A89` (replay)
6. Il nuovo saldo non supera il limite di detenzione → `0x6984`

Lo stato cambia solo dopo che tutti i controlli sono passati.

## Connessione NFC interrotta

Se il telefono si allontana dopo `PAY` ma prima di `RECEIVE`, il saldo del pagatore è già scalato ma il POS non ha il token. Il pacchetto però resta salvato nel chip del pagatore: al secondo tap il POS lo rilegge con `GET_LAST_PAYMENT` e lo consegna. Un'eventuale terza consegna viene bloccata dal contatore, quindi il denaro non si perde né si duplica.

## Il limite dell'offline: il chip clonato

Se un attaccante estrae fisicamente la chiave da un chip, può creare un clone con lo stesso saldo e spendere due volte presso POS diversi. **Offline questo non si può scoprire**, perché i POS non si parlano. Le difese sono:

- **hardware certificato** (Common Criteria EAL5+ o superiore) per rendere l'estrazione molto costosa;
- **limite di detenzione** per chip (default 300 €) per limitare il danno;
- **riconciliazione**: quando i POS si sincronizzano, l'Emittente vede lo stesso `(chip, contatore)` in due token diversi, revoca il chip e contabilizza la perdita;
- **lista revoche** distribuita ai POS: un POS con la lista vecchia resta vulnerabile finché non si aggiorna, e i pagamenti accettati nel frattempo sono contati come perdita.

L'invariante contabile verificato dalla demo è:

```
somma dei saldi dei chip = (caricato − scaricato) + perdite da frode
```

## Privacy

In questa versione i POS inviano all'Emittente i pacchetti completi: l'Emittente vede chi ha pagato chi. È il modello "tracciabile". Un modello "tipo contante" (come quello previsto per l'euro digitale offline) richiederebbe e-cash alla Chaum o prove a conoscenza zero: il pagatore resta anonimo, ma una doppia spesa rivela la sua identità. È il prossimo passo naturale del progetto.

## Stato dell'applet JavaCard

L'applet in `applet/` implementa ancora il **protocollo v1** e ha limiti noti:

- il saldo è un `short` (massimo 327,67 €) e l'importo viene letto solo dagli ultimi 2 dei 4 byte;
- `CREDIT` non è autenticato;
- `isAuthenticated` viene impostato ma mai controllato.

Il porting del v2 sull'applet (comandi `0x82`–`0x90`, certificato in EEPROM, verifica ECDSA on-card) è il passo successivo per i test su carte JCOP4 reali.
