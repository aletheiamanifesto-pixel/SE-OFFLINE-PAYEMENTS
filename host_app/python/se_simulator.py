"""
se_simulator.py — Simulatore di Secure Element (SE) per pagamenti offline

Immagina il Secure Element come una CASSAFORTE DIGITALE miniaturizzata,
saldata direttamente nel chip NFC del tuo telefono o della tua carta.
Dentro questa cassaforte ci sono:
  - Il tuo PORTAFOGLIO (saldo in centesimi di AEGIS Euro)
  - Un CONTATORE MONOTÒNICO (come il contachilometri di un'auto: sale e non torna mai indietro)
  - Una COPPIA DI CHIAVI CRITTOGRAFICHE (come una firma autografa digitale impossibile da falsificare)

Questo modulo simula tutto ciò in Python, usando crittografia ECDSA reale
(curva secp256r1, la stessa usata nelle carte bancarie e nei passaporti elettronici).

Ogni operazione avviene tramite comandi APDU (Application Protocol Data Unit),
lo stesso protocollo che il tuo telefono usa per parlare con la SIM o con la carta NFC.
Pensa agli APDU come a dei "bigliettini" che il telefono infila nella fessura della cassaforte:
  - Il bigliettino dice cosa fare (prelevare, versare, firmare...)
  - La cassaforte risponde con il risultato e un codice di stato (OK, errore, ecc.)
"""

import struct
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from .se_interface import SecureElementInterface
from . import protocollo_v2 as v2


# =============================================================================
# CODICI DI STATO (Status Words)
# Sono come i codici HTTP, ma per le smart card.
# 0x9000 = "Tutto OK" (come 200 OK nel web)
# 0x6985 = "Saldo insufficiente" (come quando il bancomat ti dice "fondi non disponibili")
# =============================================================================
SW_OK = 0x9000                    # Operazione riuscita — la cassaforte ha eseguito l'ordine
SW_WRONG_PIN = 0x6983             # PIN errato — come digitare il codice sbagliato al bancomat
SW_INSUFFICIENT_BALANCE = 0x6985  # Saldo insufficiente — non puoi spendere più di quel che hai
SW_MAX_BALANCE_EXCEEDED = 0x6984  # Saldo massimo superato — non puoi caricare oltre il limite
SW_CONDITIONS_NOT_SATISFIED = 0x6986  # Condizioni non soddisfatte — applet non selezionata
SW_WRONG_LENGTH = 0x6700         # Lunghezza dati errata — il bigliettino ha dimensioni sbagliate
SW_INS_NOT_SUPPORTED = 0x6D00   # Istruzione sconosciuta — la cassaforte non capisce la richiesta

# =============================================================================
# LIMITI
# =============================================================================
MAX_BALANCE = 1_000_000_00  # Saldo massimo: 10.000,00€ in centesimi

# =============================================================================
# CODICI ISTRUZIONE (INS bytes)
# Ogni comando APDU ha un "codice operazione" che dice alla cassaforte cosa fare.
# È come il numero del servizio allo sportello della banca:
#   "Sportello 0x10 = consulta saldo", "Sportello 0x20 = prelievo", ecc.
# =============================================================================
INS_SELECT = 0xA4          # Seleziona l'applet (come scegliere quale app aprire sulla carta)
INS_GET_BALANCE = 0x10     # Leggi il saldo — "Quanto ho nel portafoglio?"
INS_DEBIT = 0x20           # Addebito — "Togli questi soldi dal mio conto"
INS_CREDIT = 0x30          # Accredito — "Aggiungi questi soldi al mio conto"
INS_GET_COUNTER = 0x40     # Leggi contatore — "Quante transazioni ho fatto?"
INS_SIGN = 0x50            # Firma digitale — "Metti la tua firma su questo documento"
INS_GET_CERTIFICATE = 0x60  # Ottieni certificato — "Mostrami la tua carta d'identità digitale"
INS_MUTUAL_AUTH = 0x70     # Autenticazione reciproca — "Dimostriamo entrambi chi siamo"


class SecureElementSimulator(SecureElementInterface):
    """
    Simulatore di Secure Element per pagamenti offline AEGIS.

    Questa classe rappresenta un chip sicuro virtuale. Nel mondo reale,
    un Secure Element è un microprocessore tamper-resistant (resistente
    alle manomissioni) grande quanto un granello di riso, ma capace di:
      - Conservare segreti (chiavi private) anche sotto attacco fisico
      - Eseguire operazioni crittografiche senza mai esporre la chiave
      - Mantenere un contatore che non può essere riportato indietro

    È come una cassaforte con un notaio dentro: custodisce i tuoi soldi,
    firma i documenti per tuo conto, e tiene un registro inalterabile.
    """

    def __init__(self, initial_balance: int = 10000):
        """
        Inizializza il Secure Element.

        Parametri:
            initial_balance: saldo iniziale in CENTESIMI (10000 = 100.00€)
                            Come quando carichi una carta prepagata per la prima volta.

        Durante l'inizializzazione avvengono tre cose fondamentali:
        1. Si imposta il saldo iniziale (come caricare la carta dal tabaccaio)
        2. Si azzera il contatore monotònico (il "contachilometri" parte da zero)
        3. Si genera la coppia di chiavi ECDSA (come creare la tua firma digitale unica)
        """
        # --- SALDO: il denaro digitale dentro la cassaforte ---
        # Usiamo centesimi per evitare errori con i decimali.
        # 10000 centesimi = 100.00 euro, proprio come nella realtà
        # le macchinette contano in centesimi, non in euro.
        self._balance = initial_balance

        # --- CONTATORE MONOTÒNICO: il contachilometri delle transazioni ---
        # Come il contachilometri di un'auto: può solo salire.
        # Serve a impedire i "replay attack" (attacchi di ripetizione):
        # se qualcuno registra una transazione e prova a ri-inviarla,
        # il contatore sarà diverso e la frode verrà scoperta.
        self._counter = 0

        # --- CHIAVI CRITTOGRAFICHE: la firma autografa digitale ---
        # Generiamo una coppia di chiavi ECDSA sulla curva secp256r1
        # (detta anche P-256 o prime256v1). È lo standard mondiale
        # per le firme digitali nelle smart card.
        #
        # La chiave privata è come il tuo modo unico di fare la firma:
        # solo tu puoi firmare, ma tutti possono verificare che sia tua.
        # La chiave pubblica è come la tua firma depositata in banca:
        # chiunque può confrontarla per verificare l'autenticità.
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()

        # --- FLAG DI SELEZIONE: l'applet è stata attivata? ---
        # Prima di usare la carta, bisogna "selezionare" l'applicazione,
        # come quando scegli "Pagamento" sul POS invece di "Ricarica".
        self._selected = False

        # --- STATO DEL PROTOCOLLO v2 ---
        # Finché il chip non viene personalizzato dall'Emittente resta in
        # "modalità sviluppo" (protocollo v1, compatibile con i test esistenti).
        # Dopo la personalizzazione i comandi v1 DEBIT/CREDIT vengono bloccati:
        # il denaro si muove solo con ordini firmati o token di pagamento.
        self._chiave_emittente: bytes | None = None
        self._certificato: bytes | None = None
        self._limite_detenzione = MAX_BALANCE
        self._ultimo_contatore_visto: dict[bytes, int] = {}
        self._revocati: set[bytes] = set()
        self._versione_revoche = 0
        self._nonce_usati: set[bytes] = set()
        self._ultimo_pacchetto: bytes | None = None

    @property
    def personalizzato(self) -> bool:
        return self._certificato is not None

    @property
    def device_id(self) -> bytes:
        return v2.device_id_da_chiave(self.get_certificate())

    # =========================================================================
    # METODI APDU — La "fessura della cassaforte" per i bigliettini
    # =========================================================================

    def process_apdu(self, apdu_bytes: bytes) -> bytes:
        """
        Elabora un comando APDU e restituisce la risposta.

        Un APDU (Application Protocol Data Unit) è il "linguaggio" con cui
        il mondo esterno comunica con il Secure Element. È come un modulo
        da compilare allo sportello della banca:

        Struttura del comando APDU:
        ┌─────┬─────┬─────┬─────┬─────┬──────────┐
        │ CLA │ INS │ P1  │ P2  │ Lc  │  DATA    │
        └─────┴─────┴─────┴─────┴─────┴──────────┘
          │      │     │     │     │       │
          │      │     │     │     │       └─ I dati veri e propri (importo, messaggio da firmare...)
          │      │     │     │     └───────── Lunghezza dei dati (quanti byte seguono)
          │      │     │     └─────────────── Parametro 2 (dettagli aggiuntivi)
          │      │     └───────────────────── Parametro 1 (dettagli aggiuntivi)
          │      └─────────────────────────── Istruzione (cosa vuoi fare: prelevare, firmare...)
          └────────────────────────────────── Classe (0x00=standard ISO, 0x80=proprietario)

        Parametri:
            apdu_bytes: i byte del comando APDU (minimo 4: CLA, INS, P1, P2)

        Ritorna:
            bytes contenenti [dati_risposta] + [SW1, SW2] (status word a 2 byte)
        """
        # --- Controllo lunghezza minima ---
        # Un APDU valido ha almeno 4 byte (CLA + INS + P1 + P2).
        # È come controllare che il modulo della banca abbia almeno
        # i campi obbligatori compilati.
        if len(apdu_bytes) < 4:
            return self._make_response(b'', SW_WRONG_LENGTH)

        # --- Estrazione dei campi dell'APDU ---
        cla = apdu_bytes[0]   # Classe: "tipo di sportello"
        ins = apdu_bytes[1]   # Istruzione: "cosa vuoi fare"
        # p1 e p2 sono i parametri ausiliari (li usiamo solo in alcuni comandi)
        data = apdu_bytes[5:] if len(apdu_bytes) > 5 else b''  # Dati allegati

        # --- Smistamento comandi ---
        # Come lo smistamento allo sportello: in base al numero del servizio
        # richiesto, ti mando all'impiegato giusto.

        # SELEZIONE APPLET (CLA=0x00 è lo standard ISO 7816)
        if cla == 0x00 and ins == INS_SELECT:
            return self._handle_select()

        # Tutti gli altri comandi richiedono CLA=0x80 (comandi proprietari AEGIS)
        if cla != 0x80:
            return self._make_response(b'', SW_INS_NOT_SUPPORTED)

        # Tutti i comandi proprietari richiedono che l'applet sia stata selezionata
        if not self._selected:
            return self._make_response(b'', SW_CONDITIONS_NOT_SATISFIED)

        # --- Dispatch delle istruzioni proprietarie ---
        if ins == INS_GET_BALANCE:
            return self._handle_get_balance()
        elif ins == INS_DEBIT:
            return self._handle_debit(data)
        elif ins == INS_CREDIT:
            return self._handle_credit(data)
        elif ins == INS_GET_COUNTER:
            return self._handle_get_counter()
        elif ins == INS_SIGN:
            return self._handle_sign(data)
        elif ins == INS_GET_CERTIFICATE:
            return self._handle_get_certificate()
        elif ins == INS_MUTUAL_AUTH:
            return self._handle_mutual_auth(data)
        elif ins in self._comandi_v2():
            return self._comandi_v2()[ins](data)
        else:
            # Istruzione non riconosciuta — come chiedere "voglio un gelato"
            # allo sportello della banca: non è un servizio disponibile.
            return self._make_response(b'', SW_INS_NOT_SUPPORTED)

    # =========================================================================
    # METODI PUBBLICI DI ALTO LIVELLO
    # Questi metodi sono "scorciatoie" per chi non vuole costruire gli APDU a mano.
    # Sono come usare l'app della banca invece di andare allo sportello.
    # =========================================================================

    def get_balance(self) -> int:
        """
        Restituisce il saldo corrente in centesimi.

        Come guardare il saldo sul display del bancomat:
        se ritorna 7500, significa 75.00€.
        """
        return self._balance

    def get_certificate(self) -> bytes:
        """
        Restituisce la chiave pubblica in formato "uncompressed point".

        La chiave pubblica è come l'IBAN: puoi darla a chiunque in sicurezza,
        serve per verificare che le tue firme siano autentiche.

        Il formato è il punto non compresso sulla curva ellittica:
        0x04 || coordinata_X (32 byte) || coordinata_Y (32 byte) = 65 byte totali
        """
        return self._public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )

    def debit(self, amount: int) -> bool:
        """
        Sottrae 'amount' centesimi dal saldo.

        Come pagare in contanti: togli le monete dal portafoglio.
        Se provi a pagare 50€ ma ne hai solo 30€, l'operazione fallisce.

        Parametri:
            amount: importo da addebitare in centesimi (deve essere > 0)

        Ritorna:
            True se l'addebito è riuscito, False se saldo insufficiente
        """
        if self.personalizzato:
            return False  # v2: il denaro esce solo con PAY o UNLOAD
        if amount <= 0 or amount > self._balance:
            return False
        self._balance -= amount
        # Ogni addebito incrementa il contatore, come un timbro sul libretto
        self._counter += 1
        return True

    def credit(self, amount: int) -> bool:
        """
        Aggiunge 'amount' centesimi al saldo.

        Come ricevere un pagamento: le monete entrano nel portafoglio.
        A differenza del prelievo, qui non c'è un limite massimo
        (nel mondo reale ci sarebbero controlli antiriciclaggio).

        Parametri:
            amount: importo da accreditare in centesimi (deve essere > 0)

        Ritorna:
            True se l'accredito è riuscito, False se importo non valido
        """
        if self.personalizzato:
            return False  # v2: il denaro entra solo con LOAD o RECEIVE
        if amount <= 0:
            return False
        if self._balance + amount > MAX_BALANCE:
            return False
        self._balance += amount
        return True

    def get_counter(self) -> int:
        """
        Restituisce il valore corrente del contatore monotònico.

        Il contatore è come il numero di scontrino al supermercato:
        ogni transazione ne prende uno nuovo, e non puoi tornare indietro.
        Questo impedisce che qualcuno "ripeta" una transazione già fatta
        (cosiddetto "replay attack").
        """
        return self._counter

    def sign_transaction(self, data: bytes) -> bytes:
        """
        Firma digitalmente i dati con la chiave privata ECDSA.

        Immagina di firmare un assegno: la tua firma garantisce che
        SEI DAVVERO TU ad autorizzare quel pagamento. Nessun altro
        può replicare la tua firma, ma chiunque può verificarla
        confrontandola con quella depositata in banca.

        Parametri:
            data: i byte da firmare (tipicamente: importo + contatore + timestamp)

        Ritorna:
            La firma digitale in formato DER (byte grezzi)
        """
        if self._firma_riservata(data):
            raise PermissionError("prefisso riservato al protocollo v2: firma rifiutata")
        signature = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_signature(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verifica che una firma digitale sia autentica.

        Come quando la banca controlla la firma sull'assegno:
        confronta la firma apposta con quella depositata dal cliente.
        Se corrispondono, l'assegno è valido; altrimenti, è un falso.

        Parametri:
            data: i dati originali che erano stati firmati
            signature: la firma da verificare
            public_key: la chiave pubblica del firmatario (formato uncompressed point)

        Ritorna:
            True se la firma è valida, False se è falsa o corrotta
        """
        try:
            # Ricostruiamo l'oggetto chiave pubblica dai byte grezzi
            # È come recuperare la firma depositata dall'archivio della banca
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_key
            )
            pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, Exception):
            return False

    # =========================================================================
    # GESTORI INTERNI DEI COMANDI APDU
    # Questi metodi sono i veri "impiegati allo sportello":
    # ognuno gestisce un tipo specifico di richiesta.
    # =========================================================================

    def _handle_select(self) -> bytes:
        """
        Gestisce il comando SELECT (INS=0xA4).

        Come inserire la carta nel lettore e scegliere "Pagamento AEGIS":
        attiva l'applet di pagamento sul Secure Element.
        Fino a quando non fai SELECT, la cassaforte non risponde agli altri comandi.
        """
        self._selected = True
        return self._make_response(b'', SW_OK)

    def _handle_get_balance(self) -> bytes:
        """
        Gestisce il comando GET_BALANCE (INS=0x10).

        Restituisce il saldo come 4 byte big-endian (network byte order).
        Esempio: 10000 (= 100.00€) diventa 0x00 0x00 0x27 0x10

        È come premere "Visualizza saldo" al bancomat.
        """
        balance_bytes = struct.pack('>I', self._balance)
        return self._make_response(balance_bytes, SW_OK)

    def _handle_debit(self, data: bytes) -> bytes:
        """
        Gestisce il comando DEBIT (INS=0x20).

        Aspetta 4 byte big-endian che rappresentano l'importo in centesimi.
        Come dire al cassiere: "Preleva questa somma dal mio conto".

        Controlli:
        1. I dati devono essere esattamente 4 byte (altrimenti → WRONG_LENGTH)
        2. Il saldo deve essere sufficiente (altrimenti → INSUFFICIENT_BALANCE)
        """
        if self.personalizzato:
            return self._make_response(b'', v2.SW_SECURITY_STATUS_NOT_SATISFIED)

        if len(data) < 4:
            return self._make_response(b'', SW_WRONG_LENGTH)

        amount = struct.unpack('>I', data[:4])[0]

        if amount > self._balance:
            # Come quando provi a prelevare 200€ ma ne hai solo 150€:
            # il bancomat rifiuta l'operazione.
            return self._make_response(b'', SW_INSUFFICIENT_BALANCE)

        self._balance -= amount
        self._counter += 1  # Ogni prelievo fa scattare il contachilometri

        # Rispondiamo con il nuovo saldo, così il terminale può aggiornare il display
        new_balance_bytes = struct.pack('>I', self._balance)
        return self._make_response(new_balance_bytes, SW_OK)

    def _handle_credit(self, data: bytes) -> bytes:
        """
        Gestisce il comando CREDIT (INS=0x30).

        Come versare contanti al bancomat: i soldi entrano nel conto.
        Aspetta 4 byte big-endian con l'importo da accreditare.

        ATTENZIONE: nel protocollo v1 questo comando non è autenticato.
        Su un chip personalizzato (v2) è bloccato.
        """
        if self.personalizzato:
            return self._make_response(b'', v2.SW_SECURITY_STATUS_NOT_SATISFIED)

        if len(data) < 4:
            return self._make_response(b'', SW_WRONG_LENGTH)

        amount = struct.unpack('>I', data[:4])[0]
        if self._balance + amount > MAX_BALANCE:
            return self._make_response(b'', SW_MAX_BALANCE_EXCEEDED)
        self._balance += amount

        new_balance_bytes = struct.pack('>I', self._balance)
        return self._make_response(new_balance_bytes, SW_OK)

    def _handle_get_counter(self) -> bytes:
        """
        Gestisce il comando GET_COUNTER (INS=0x40).

        Restituisce il contatore monotònico come 4 byte big-endian.
        È come chiedere: "Quante transazioni ha fatto questa carta?"
        """
        counter_bytes = struct.pack('>I', self._counter)
        return self._make_response(counter_bytes, SW_OK)

    def _handle_sign(self, data: bytes) -> bytes:
        """
        Gestisce il comando SIGN (INS=0x50).

        Firma i dati ricevuti con la chiave privata ECDSA.
        È come quando il notaio mette il timbro e la firma su un atto:
        da quel momento, il documento è autenticato e non ripudiabile.

        La firma viene calcolata su SHA-256(data), usando la curva secp256r1.
        """
        if len(data) == 0:
            return self._make_response(b'', SW_WRONG_LENGTH)
        if self._firma_riservata(data):
            return self._make_response(b'', v2.SW_SECURITY_STATUS_NOT_SATISFIED)

        signature = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return self._make_response(signature, SW_OK)

    def _handle_get_certificate(self) -> bytes:
        """
        Gestisce il comando GET_CERTIFICATE (INS=0x60).

        Restituisce la chiave pubblica nel formato "uncompressed point" (65 byte):
        0x04 || X (32 byte) || Y (32 byte)

        È come mostrare la carta d'identità: prova chi sei senza rivelare
        i tuoi segreti (la chiave privata resta sempre dentro la cassaforte).
        """
        pub_bytes = self._public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )
        return self._make_response(pub_bytes, SW_OK)

    def _handle_mutual_auth(self, data: bytes) -> bytes:
        """
        Gestisce il comando MUTUAL_AUTH (INS=0x70).

        L'autenticazione reciproca è come quando due spie si incontrano
        e ognuna deve dimostrare all'altra di essere chi dice di essere.

        Flusso semplificato:
        1. Il terminale invia una "sfida" (challenge) — un numero casuale
        2. Il SE firma la sfida con la sua chiave privata
        3. Il terminale verifica la firma con la chiave pubblica del SE

        In questa versione simulata, il SE firma la sfida ricevuta
        e la restituisce come prova della propria identità.
        """
        if len(data) == 0:
            # Se non c'è una sfida, generiamo noi un challenge casuale
            # (nella realtà sarebbe un errore di protocollo)
            challenge = os.urandom(32)
        else:
            challenge = data
            if self._firma_riservata(challenge):
                return self._make_response(b'', v2.SW_SECURITY_STATUS_NOT_SATISFIED)

        # Firmiamo la sfida per dimostrare la nostra identità
        signature = self._private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))

        # Rispondiamo con la sfida originale + la firma
        response_data = challenge + signature
        return self._make_response(response_data, SW_OK)

    # =========================================================================
    # PROTOCOLLO v2 — Pagamenti offline sicuri
    # Vedi protocollo_v2.py e docs/05_PROTOCOLLO_V2.md per i formati.
    # Ogni gestore prima verifica TUTTO e solo alla fine modifica lo stato:
    # così un errore non lascia mai il chip "a metà" (come una transazione
    # atomica JavaCard).
    # =========================================================================

    def _comandi_v2(self) -> dict:
        return {
            v2.INS_PERSONALIZE: self._handle_personalize,
            v2.INS_GET_DEVICE_ID: self._handle_get_device_id,
            v2.INS_LOAD: self._handle_load,
            v2.INS_UNLOAD: self._handle_unload,
            v2.INS_PAY: self._handle_pay,
            v2.INS_RECEIVE: self._handle_receive,
            v2.INS_GET_LAST_PAYMENT: self._handle_get_last_payment,
            v2.INS_UPDATE_REVOCATIONS: self._handle_update_revocations,
        }

    def _firma_riservata(self, data: bytes) -> bool:
        """Un chip personalizzato non firma dati che imitano messaggi v2."""
        return self.personalizzato and data.startswith(v2.PREFISSO_RISERVATO)

    def _handle_personalize(self, data: bytes) -> bytes:
        """
        PERSONALIZE: chiave pubblica dell'Emittente (65) + certificato del chip (145).
        Si può fare una sola volta, come la personalizzazione in fabbrica.
        """
        if self.personalizzato:
            return self._make_response(b'', SW_CONDITIONS_NOT_SATISFIED)
        if len(data) != v2.PUB_LEN + v2.CERT_LEN:
            return self._make_response(b'', SW_WRONG_LENGTH)

        chiave_emittente, cert_bytes = data[:v2.PUB_LEN], data[v2.PUB_LEN:]
        try:
            cert = v2.Certificato.decode(cert_bytes)
        except ValueError:
            return self._make_response(b'', SW_WRONG_LENGTH)
        if cert.chiave_pubblica != self.get_certificate() or not cert.valido(chiave_emittente):
            return self._make_response(b'', v2.SW_SECURITY_STATUS_NOT_SATISFIED)

        self._chiave_emittente = chiave_emittente
        self._certificato = cert_bytes
        self._limite_detenzione = min(cert.limite, MAX_BALANCE)
        self._balance = 0  # in v2 il saldo nasce solo da ordini LOAD firmati
        return self._make_response(cert.device_id, SW_OK)

    def _handle_get_device_id(self, data: bytes) -> bytes:
        return self._make_response(self.device_id, SW_OK)

    def _verifica_ordine(self, tag: bytes, data: bytes):
        """Controlla un ordine LOAD/UNLOAD. Ritorna (importo, nonce) o una status word."""
        if not self.personalizzato:
            return SW_CONDITIONS_NOT_SATISFIED
        if len(data) != v2.ORDINE_LEN:
            return SW_WRONG_LENGTH
        corpo, firma = data[:v2.ORDINE_BODY_LEN], data[v2.ORDINE_BODY_LEN:]
        if not corpo.startswith(tag) or not v2.verifica_raw(self._chiave_emittente, corpo, firma):
            return v2.SW_SECURITY_STATUS_NOT_SATISFIED
        if corpo[4:12] != self.device_id:
            return v2.SW_WRONG_DATA
        nonce = corpo[16:24]
        if nonce in self._nonce_usati:
            return v2.SW_REPLAY
        return struct.unpack('>I', corpo[12:16])[0], nonce

    def _handle_load(self, data: bytes) -> bytes:
        """LOAD: l'Emittente trasferisce denaro dal conto al chip (online)."""
        esito = self._verifica_ordine(v2.TAG_LOAD, data)
        if isinstance(esito, int):
            return self._make_response(b'', esito)
        importo, nonce = esito
        if self._balance + importo > self._limite_detenzione:
            return self._make_response(b'', v2.SW_LIMIT_EXCEEDED)

        self._nonce_usati.add(nonce)
        self._balance += importo
        return self._make_response(struct.pack('>I', self._balance), SW_OK)

    def _handle_unload(self, data: bytes) -> bytes:
        """
        UNLOAD: il chip restituisce denaro all'Emittente (che lo versa sul conto).
        Risponde con una firma del chip: è la prova che il saldo è stato davvero scalato.
        """
        esito = self._verifica_ordine(v2.TAG_UNLOAD, data)
        if isinstance(esito, int):
            return self._make_response(b'', esito)
        importo, nonce = esito
        if importo > self._balance:
            return self._make_response(b'', SW_INSUFFICIENT_BALANCE)

        self._nonce_usati.add(nonce)
        self._balance -= importo
        conferma = v2.TAG_UNLOAD_OK + data[4:v2.ORDINE_BODY_LEN]
        return self._make_response(v2.firma_raw(self._private_key, conferma), SW_OK)

    def _handle_pay(self, data: bytes) -> bytes:
        """
        PAY: payee_id (8) + importo (4).
        Addebito, contatore e firma del token avvengono in un'unica operazione:
        non esiste un momento in cui il saldo è scalato ma il token non esiste.
        Il pacchetto resta salvato nel chip finché non se ne crea un altro,
        così può essere riletto se la connessione NFC si interrompe.
        """
        if not self.personalizzato:
            return self._make_response(b'', SW_CONDITIONS_NOT_SATISFIED)
        if len(data) != v2.ID_LEN + 4:
            return self._make_response(b'', SW_WRONG_LENGTH)
        payee_id = data[:v2.ID_LEN]
        importo = struct.unpack('>I', data[v2.ID_LEN:])[0]
        if importo == 0 or payee_id == self.device_id:
            return self._make_response(b'', v2.SW_WRONG_DATA)
        if importo > self._balance:
            return self._make_response(b'', SW_INSUFFICIENT_BALANCE)

        token = v2.Token(self.device_id, payee_id, importo, self._counter + 1)
        firma = v2.firma_raw(self._private_key, token.encode())
        pacchetto = token.encode() + firma + self._certificato

        self._balance -= importo
        self._counter += 1
        self._ultimo_pacchetto = pacchetto
        return self._make_response(pacchetto, SW_OK)

    def _handle_receive(self, data: bytes) -> bytes:
        """
        RECEIVE: il pacchetto di pagamento (237 byte).
        Il chip del beneficiario verifica da solo, offline:
          1. certificato del pagatore firmato dall'Emittente
          2. pagatore non revocato
          3. firma del token fatta dalla chiave del certificato
          4. il token è destinato a QUESTO chip
          5. contatore mai visto prima (anti-replay)
          6. limite di detenzione rispettato
        """
        if not self.personalizzato:
            return self._make_response(b'', SW_CONDITIONS_NOT_SATISFIED)
        try:
            pacchetto = v2.Pacchetto.decode(data)
        except ValueError:
            return self._make_response(b'', SW_WRONG_LENGTH)
        token = pacchetto.token

        if not pacchetto.certificato.valido(self._chiave_emittente):
            return self._make_response(b'', v2.SW_SECURITY_STATUS_NOT_SATISFIED)
        if token.payer_id in self._revocati:
            return self._make_response(b'', v2.SW_REVOKED)
        if not pacchetto.firma_valida():
            return self._make_response(b'', v2.SW_SECURITY_STATUS_NOT_SATISFIED)
        if token.payee_id != self.device_id:
            return self._make_response(b'', v2.SW_WRONG_DATA)
        if token.contatore <= self._ultimo_contatore_visto.get(token.payer_id, 0):
            return self._make_response(b'', v2.SW_REPLAY)
        if self._balance + token.importo > self._limite_detenzione:
            return self._make_response(b'', v2.SW_LIMIT_EXCEEDED)

        self._ultimo_contatore_visto[token.payer_id] = token.contatore
        self._balance += token.importo
        return self._make_response(struct.pack('>I', self._balance), SW_OK)

    def _handle_get_last_payment(self, data: bytes) -> bytes:
        if self._ultimo_pacchetto is None:
            return self._make_response(b'', SW_CONDITIONS_NOT_SATISFIED)
        return self._make_response(self._ultimo_pacchetto, SW_OK)

    def _handle_update_revocations(self, data: bytes) -> bytes:
        """UPDATE_REVOCATIONS: lista firmata dall'Emittente, accettata solo se più recente."""
        if not self.personalizzato:
            return self._make_response(b'', SW_CONDITIONS_NOT_SATISFIED)
        if len(data) < 9 + v2.SIG_LEN:
            return self._make_response(b'', SW_WRONG_LENGTH)
        corpo, firma = data[:-v2.SIG_LEN], data[-v2.SIG_LEN:]
        versione, n = struct.unpack('>IB', corpo[4:9])
        if (not corpo.startswith(v2.TAG_REVOCHE) or len(corpo) != 9 + n * v2.ID_LEN
                or not v2.verifica_raw(self._chiave_emittente, corpo, firma)):
            return self._make_response(b'', v2.SW_SECURITY_STATUS_NOT_SATISFIED)
        if versione <= self._versione_revoche:
            return self._make_response(b'', v2.SW_REPLAY)

        self._versione_revoche = versione
        self._revocati = {corpo[9 + i * v2.ID_LEN: 9 + (i + 1) * v2.ID_LEN] for i in range(n)}
        return self._make_response(struct.pack('>I', versione), SW_OK)

    # =========================================================================
    # UTILITÀ INTERNE
    # =========================================================================

    @staticmethod
    def _make_response(data: bytes, status_word: int) -> bytes:
        """
        Costruisce la risposta APDU: dati + status word (2 byte).

        La status word è come il codice di risposta HTTP:
          0x9000 = "200 OK, tutto bene"
          0x6985 = "402 Payment Required, saldo insufficiente"
          0x6D00 = "404 Not Found, comando sconosciuto"

        Formato risposta: [DATI...] [SW1] [SW2]
        """
        sw1 = (status_word >> 8) & 0xFF
        sw2 = status_word & 0xFF
        return data + bytes([sw1, sw2])

    # =========================================================================
    # UTILITÀ PER COSTRUIRE COMANDI APDU
    # Metodi statici di comodità, come avere un "compilatore di moduli"
    # che prepara i bigliettini nel formato corretto per la cassaforte.
    # =========================================================================

    @staticmethod
    def build_apdu(cla: int, ins: int, p1: int = 0x00, p2: int = 0x00,
                   data: bytes = b'') -> bytes:
        """
        Costruisce un comando APDU dai suoi componenti.

        Parametri:
            cla: classe del comando (0x00=ISO, 0x80=proprietario)
            ins: codice istruzione
            p1, p2: parametri ausiliari
            data: dati opzionali da allegare

        Ritorna:
            bytes pronti per process_apdu()

        Esempio:
            # Comando DEBIT di 25.00€ (2500 centesimi)
            apdu = SecureElementSimulator.build_apdu(0x80, 0x20, data=struct.pack('>I', 2500))
        """
        lc = len(data)
        return bytes([cla, ins, p1, p2, lc]) + data
