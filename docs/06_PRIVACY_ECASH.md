# 06 — Modalità privacy: monete con firma cieca

## Il problema

Con il protocollo v2 ([05_PROTOCOLLO_V2.md](05_PROTOCOLLO_V2.md)) i pagamenti offline funzionano e le frodi vengono scoperte, ma l'Emittente vede ogni pagamento riconciliato: **chi ha pagato chi, quanto e quando**. Non è il comportamento del contante.

La modalità privacy (`bridge/ecash.py`, `demo_privacy.py`) mostra come ottenere:

- **anonimato per chi paga onestamente**: né il negozio né l'Emittente sanno chi ha speso una moneta;
- **identificazione solo di chi froda**: se la stessa moneta viene spesa due volte, un Garante indipendente identifica il chip, e solo per quella moneta.

## Come funziona

### 1. Prelievo con firma cieca (online)

```
Telefono                                       Emittente
seriale casuale S, fattore casuale r
m = H(taglio, S)
m' = m · r^e  mod n      ── m' ──────────────►  vede solo m' (casuale)
                                                scala il taglio dal conto
                         ◄────────── s' ──────  s' = m'^d  mod n
s = s' · r⁻¹  mod n   →  moneta (taglio, S, s)
```

`s` è una firma RSA valida su `H(taglio, S)`, ma l'Emittente ha visto solo `m'`, che è indistinguibile da un numero casuale. Ogni taglio (2 €, 1 €, 50, 20, 10, 5 cent) ha una chiave diversa, così una moneta da 5 cent non si può spacciare per una da 2 €.

### 2. Pagamento (offline)

Il chip del pagatore sceglie le monete per l'importo esatto (offline non si dà resto), le **cancella dalla propria memoria** e le passa al POS. Per ogni moneta allega una **busta sigillata**: `RSA-OAEP(chiave del Garante, seriale ‖ identità del chip)`.

Il POS verifica offline, con le sole chiavi pubbliche dell'Emittente:

1. la firma dell'Emittente sul taglio e sul seriale (rifiuta monete false o tagli gonfiati);
2. che la moneta sia destinata a lui;
3. che non abbia già ricevuto quella moneta (rifiuta copie presentate allo stesso POS).

### 3. Deposito (online)

Il negozio porta le monete all'Emittente, che controlla la firma e il registro dei seriali già depositati. Se il seriale è nuovo, accredita il conto del negozio. **L'Emittente vede il seriale, ma non può collegarlo a nessun prelievo**: la demo lo verifica con `collega_al_prelievo()`.

### 4. Doppia spesa

Se un attaccante clona il chip e spende la stessa moneta in due negozi, offline nessuno se ne accorge. Al deposito l'Emittente vede lo stesso seriale due volte:

- paga solo il primo deposito, cioè non crea denaro;
- consegna al Garante **le due buste di quella moneta** e nessun'altra;
- il Garante le apre e identifica il chip; tutte le altre buste restano sigillate.

## Confronto

| | Tracciabile (`demo.py`) | Privata (`demo_privacy.py`) |
|---|---|---|
| Chi preleva e quanto | Emittente | Emittente |
| Chi incassa e quanto | Emittente | Emittente |
| Chi ha pagato chi | Emittente, sempre | nessuno |
| Chi ha fatto doppia spesa | Emittente | Garante, solo per quella moneta |
| Il negozio sa chi sei? | sì (id del chip) | no |
| Chi perde con una doppia spesa | l'Emittente (copre la perdita) | il secondo negozio, che si rivale sul colpevole identificato |
| Unità di valore | saldo nel chip | monete di taglio fisso, senza resto offline |

## Limiti

Questa implementazione è **didattica**:

- **RSA "da manuale"** con hash full-domain costruito su SHA-256. In produzione si usano schemi standardizzati come RSA Blind Signatures (RFC 9474), o firme cieche su curve ellittiche più compatte e adatte a una smart card.
- **La busta è affidabile solo se la scrive un chip sicuro.** Il POS non può verificare cosa c'è dentro: un attaccante che estrae la chiave dal chip potrebbe metterci un'identità falsa. Gli schemi alla Chaum-Fiat-Naor risolvono il problema con la matematica (la doppia spesa rivela l'identità senza bisogno di buste), ma sono molto più complessi.
- **Niente resto offline**: si paga con l'importo esatto. Il prelievo include apposta "spiccioli" di ogni taglio.
- **Dimensioni**: una moneta RSA-2048 con la sua busta occupa circa 550 byte. Su JavaCard servirebbero APDU estesi o, meglio, firme su curve ellittiche.

## Codice

| File | Contenuto |
|---|---|
| `bridge/ecash.py` | `EmittentePrivato`, `Garante`, `PortafoglioPrivato`, `NegozioPrivato`, `Moneta`, `Spesa` |
| `demo_privacy.py` | 7 scenari, esce con 1 se un controllo fallisce |
| `tests/test_ecash.py` | Firma cieca, monete false, copie, scoperta della doppia spesa |
