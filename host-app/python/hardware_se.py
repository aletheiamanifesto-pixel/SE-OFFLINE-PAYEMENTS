"""
hardware_se.py — Adapter per Secure Element hardware reale via PC/SC (pyscard)

Questo modulo implementa l'interfaccia SecureElementInterface comunicando
con una smart card Java Card fisica tramite un lettore NFC/PC/SC (es. ACR122U).

Richiede la libreria `pyscard` (pip install pyscard) e un lettore PC/SC
compatibile (quasi tutti i lettori USB NFC lo sono).

FLUSSO DI COMUNICAZIONE:
  Python → pyscard → driver PC/SC → lettore ACR122U → (NFC RF) → chip Java Card
  
Ogni metodo dell'interfaccia si traduce in uno o più comandi APDU inviati
al chip fisico, e la risposta viene parsata e restituita al chiamante.

GESTIONE ERRORI:
  - NFCTimeoutError: la carta non risponde entro il timeout configurato
  - CardNotFoundError: nessuna carta nel campo RF del lettore
  - CardCommunicationError: errore di protocollo o risposta malformata
  - AppletNotFoundError: l'applet AEGIS non è installato sulla carta
"""

import struct
import time
import logging
from typing import Optional, List

from .se_interface import SecureElementInterface
from .hardware_errors import (
    CardNotFoundError, NFCTimeoutError, CardCommunicationError, AppletNotFoundError
)

# Logger per debug e diagnostica
logger = logging.getLogger(__name__)

# AID di default dell'applet AEGIS (7 byte)
DEFAULT_AID = bytes.fromhex("D2760000604101")

# Status words APDU
SW_OK = 0x9000
SW_INSUFFICIENT_BALANCE = 0x6985
SW_WRONG_LENGTH = 0x6700
SW_INS_NOT_SUPPORTED = 0x6D00
SW_FILE_NOT_FOUND = 0x6A82  # Applet non trovato durante SELECT

# Codici istruzione APDU (devono corrispondere all'applet Java Card)
INS_SELECT = 0xA4
INS_GET_BALANCE = 0x10
INS_DEBIT = 0x20
INS_CREDIT = 0x30
INS_GET_COUNTER = 0x40
INS_SIGN = 0x50
INS_GET_CERTIFICATE = 0x60
INS_MUTUAL_AUTH = 0x70


class HardwareSecureElement(SecureElementInterface):
    """
    Implementazione hardware del Secure Element tramite PC/SC.

    Comunica con una smart card Java Card fisica usando il protocollo
    PC/SC (Personal Computer/Smart Card) tramite la libreria pyscard.

    Compatibile con qualsiasi lettore NFC che supporti PC/SC:
    - ACR122U (il più comune per sviluppo)
    - SCL3711
    - Altri lettori certificati PC/SC

    UTILIZZO:
        se = HardwareSecureElement(reader_index=0)
        balance = se.get_balance()
        print(f"Saldo: {balance / 100:.2f}€")

    UTILIZZO CON CONTEXT MANAGER:
        with HardwareSecureElement() as se:
            balance = se.get_balance()
    """

    def __init__(
        self,
        reader_index: int = 0,
        reader_name: Optional[str] = None,
        aid: bytes = DEFAULT_AID,
        timeout_ms: int = 5000,
        retries: int = 3
    ):
        """
        Inizializza la connessione con il lettore NFC e seleziona l'applet.

        Parametri:
            reader_index: indice del lettore da usare (0 = primo disponibile)
            reader_name: nome parziale del lettore (es. "ACR122U") — se fornito,
                        ha precedenza su reader_index
            aid: AID dell'applet da selezionare (default: D2760000604101)
            timeout_ms: timeout in millisecondi per le operazioni NFC
            retries: numero massimo di tentativi per errori transienti

        Eccezioni:
            CardNotFoundError: nessun lettore disponibile o nessuna carta
            AppletNotFoundError: applet non trovato sulla carta
            ImportError: libreria pyscard non installata
        """
        # Verifica che pyscard sia disponibile
        try:
            from smartcard.System import readers as get_readers
            from smartcard.CardConnection import CardConnection
            from smartcard.Exceptions import (
                CardRequestTimeoutException, NoCardException, CardConnectionException
            )
        except ImportError as e:
            raise ImportError(
                "La libreria pyscard non è installata. "
                "Installala con: pip install pyscard"
            ) from e

        self._aid = aid
        self._timeout_ms = timeout_ms
        self._retries = retries
        self._connection = None

        # Importa le eccezioni pyscard per il riuso nei metodi
        self._CardRequestTimeoutException = CardRequestTimeoutException
        self._NoCardException = NoCardException
        self._CardConnectionException = CardConnectionException

        # Ottieni la lista dei lettori disponibili
        available_readers = get_readers()
        if not available_readers:
            raise CardNotFoundError(
                "Nessun lettore PC/SC trovato. "
                "Verifica che il lettore ACR122U sia collegato."
            )

        logger.debug(f"Lettori disponibili: {[str(r) for r in available_readers]}")

        # Seleziona il lettore in base al nome o all'indice
        if reader_name:
            matching = [r for r in available_readers if reader_name.lower() in str(r).lower()]
            if not matching:
                raise CardNotFoundError(
                    f"Lettore '{reader_name}' non trovato. "
                    f"Lettori disponibili: {[str(r) for r in available_readers]}"
                )
            selected_reader = matching[0]
        else:
            if reader_index >= len(available_readers):
                raise CardNotFoundError(
                    f"Indice lettore {reader_index} non valido. "
                    f"Lettori disponibili: {len(available_readers)}"
                )
            selected_reader = available_readers[reader_index]

        logger.info(f"Connessione al lettore: {selected_reader}")

        # Crea e apri la connessione con la carta
        try:
            self._connection = selected_reader.createConnection()
            self._connection.connect()
            logger.info("Connessione stabilita con la smart card")
        except self._NoCardException as e:
            raise CardNotFoundError(
                f"Nessuna smart card nel lettore '{selected_reader}'. "
                "Inserisci la carta e riprova."
            ) from e
        except self._CardConnectionException as e:
            raise CardCommunicationError(
                f"Errore di comunicazione con il lettore: {e}"
            ) from e

        # Seleziona l'applet AEGIS sulla carta
        self.select_applet(aid)

    def select_applet(self, aid: bytes = DEFAULT_AID) -> None:
        """
        Seleziona l'applet AEGIS sulla smart card tramite il suo AID.

        L'AID (Application IDentifier) identifica univocamente un'applicazione
        su una smart card, come un URL identifica un sito web.

        Parametri:
            aid: l'AID dell'applet da selezionare

        Eccezioni:
            AppletNotFoundError: l'applet non è installato sulla carta
            CardCommunicationError: errore di comunicazione
        """
        # Costruisci il comando SELECT (ISO 7816-4)
        # CLA=0x00, INS=0xA4, P1=0x04 (per AID), P2=0x00
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid)
        logger.debug(f"SELECT applet AID: {aid.hex().upper()}")

        try:
            data, sw1, sw2 = self._connection.transmit(apdu)
            sw = (sw1 << 8) | sw2
        except Exception as e:
            raise CardCommunicationError(f"Errore durante SELECT: {e}") from e

        if sw == SW_FILE_NOT_FOUND or sw == 0x6999:
            # 0x6999 = condizioni di esecuzione non soddisfatte (es. applet bloccato)
            raise AppletNotFoundError(
                f"Applet con AID {aid.hex().upper()} non trovato sulla carta. "
                "Installa l'applet con GlobalPlatformPro prima di procedere.",
                aid=aid
            )
        if sw != SW_OK:
            raise CardCommunicationError(
                f"SELECT fallito con SW=0x{sw:04X}. "
                "La carta potrebbe non essere compatibile."
            )

        self._aid = aid
        logger.info(f"Applet {aid.hex().upper()} selezionato con successo")

    def process_apdu(self, apdu_bytes: bytes) -> bytes:
        """
        Invia un comando APDU alla smart card e restituisce la risposta.

        Gestisce automaticamente i retry per errori transienti (timeout NFC).
        La risposta include i dati (se presenti) e la status word finale.

        Parametri:
            apdu_bytes: il comando APDU come sequenza di byte

        Ritorna:
            bytes: [dati_risposta...] + [SW1, SW2]

        Eccezioni:
            NFCTimeoutError: la carta non risponde entro il timeout
            CardNotFoundError: la carta è stata rimossa
            CardCommunicationError: errore di protocollo
        """
        last_error = None
        apdu_list = list(apdu_bytes)

        for tentativo in range(1, self._retries + 1):
            try:
                logger.debug(
                    f"APDU inviato (tentativo {tentativo}/{self._retries}): "
                    f"{bytes(apdu_list).hex().upper()}"
                )
                data, sw1, sw2 = self._connection.transmit(apdu_list)
                response = bytes(data) + bytes([sw1, sw2])
                logger.debug(
                    f"Risposta APDU: {response.hex().upper()} "
                    f"(SW=0x{(sw1<<8)|sw2:04X})"
                )
                return response

            except self._CardRequestTimeoutException as e:
                last_error = NFCTimeoutError(
                    f"Timeout NFC dopo {self._timeout_ms}ms "
                    f"(tentativo {tentativo}/{self._retries})"
                )
                logger.warning(str(last_error))
                if tentativo < self._retries:
                    time.sleep(0.1 * tentativo)  # backoff progressivo

            except self._NoCardException as e:
                raise CardNotFoundError(
                    "Carta rimossa durante la comunicazione"
                ) from e

            except self._CardConnectionException as e:
                last_error = CardCommunicationError(f"Errore di comunicazione: {e}")
                logger.warning(str(last_error))
                if tentativo < self._retries:
                    time.sleep(0.1 * tentativo)

        # Tutti i tentativi esauriti
        raise last_error

    def get_balance(self) -> int:
        """
        Legge il saldo corrente dalla smart card.

        Invia il comando GET_BALANCE (INS=0x10) e converte la risposta
        da 4 byte big-endian al valore intero in centesimi.

        Ritorna:
            Il saldo in centesimi (es. 10000 = 100.00€)

        Eccezioni:
            CardCommunicationError: la risposta non è nel formato atteso
        """
        apdu = bytes([0x80, INS_GET_BALANCE, 0x00, 0x00, 0x00])
        risposta = self.process_apdu(apdu)

        sw = (risposta[-2] << 8) | risposta[-1]
        if sw != SW_OK:
            raise CardCommunicationError(
                f"GET_BALANCE fallito con SW=0x{sw:04X}"
            )

        dati = risposta[:-2]
        if len(dati) < 4:
            raise CardCommunicationError(
                f"GET_BALANCE: risposta troppo corta ({len(dati)} byte, attesi 4)"
            )

        return struct.unpack('>I', dati[:4])[0]

    def debit(self, amount: int) -> bool:
        """
        Addebita un importo dalla smart card.

        Invia il comando DEBIT (INS=0x20) con l'importo in centesimi
        codificato come 4 byte big-endian.

        Parametri:
            amount: importo da addebitare in centesimi (deve essere > 0)

        Ritorna:
            True se l'addebito è riuscito, False se saldo insufficiente

        Eccezioni:
            CardCommunicationError: errore di comunicazione o risposta inattesa
        """
        if amount <= 0:
            return False

        data = struct.pack('>I', amount)
        apdu = bytes([0x80, INS_DEBIT, 0x00, 0x00, len(data)]) + data
        risposta = self.process_apdu(apdu)

        sw = (risposta[-2] << 8) | risposta[-1]
        if sw == SW_OK:
            logger.info(f"Debit di {amount} centesimi riuscito")
            return True
        elif sw == SW_INSUFFICIENT_BALANCE:
            logger.warning(f"Debit di {amount} centesimi: saldo insufficiente")
            return False
        else:
            raise CardCommunicationError(
                f"DEBIT fallito con SW inatteso: 0x{sw:04X}"
            )

    def credit(self, amount: int) -> bool:
        """
        Accredita un importo alla smart card.

        Invia il comando CREDIT (INS=0x30) con l'importo in centesimi.

        Parametri:
            amount: importo da accreditare in centesimi (deve essere > 0)

        Ritorna:
            True se l'accredito è riuscito, False se l'importo non è valido

        Eccezioni:
            CardCommunicationError: errore di comunicazione
        """
        if amount <= 0:
            return False

        data = struct.pack('>I', amount)
        apdu = bytes([0x80, INS_CREDIT, 0x00, 0x00, len(data)]) + data
        risposta = self.process_apdu(apdu)

        sw = (risposta[-2] << 8) | risposta[-1]
        if sw == SW_OK:
            logger.info(f"Credit di {amount} centesimi riuscito")
            return True
        else:
            raise CardCommunicationError(
                f"CREDIT fallito con SW inatteso: 0x{sw:04X}"
            )

    def get_counter(self) -> int:
        """
        Legge il contatore monotònico dalla smart card.

        Invia il comando GET_COUNTER (INS=0x40) e converte la risposta
        da 4 byte big-endian al valore intero.

        Ritorna:
            Il valore corrente del contatore
        """
        apdu = bytes([0x80, INS_GET_COUNTER, 0x00, 0x00, 0x00])
        risposta = self.process_apdu(apdu)

        sw = (risposta[-2] << 8) | risposta[-1]
        if sw != SW_OK:
            raise CardCommunicationError(
                f"GET_COUNTER fallito con SW=0x{sw:04X}"
            )

        dati = risposta[:-2]
        if len(dati) < 4:
            raise CardCommunicationError(
                f"GET_COUNTER: risposta troppo corta ({len(dati)} byte, attesi 4)"
            )

        return struct.unpack('>I', dati[:4])[0]

    def sign_transaction(self, data: bytes) -> bytes:
        """
        Firma i dati della transazione con la chiave privata del chip.

        Invia il comando SIGN (INS=0x50) con i dati da firmare.
        La chiave privata non lascia mai il chip.

        Parametri:
            data: i byte da firmare (importo + contatore + timestamp)

        Ritorna:
            La firma ECDSA in formato DER

        Eccezioni:
            CardCommunicationError: errore di comunicazione o firma fallita
        """
        if not data:
            raise CardCommunicationError("SIGN: dati vuoti, impossibile firmare")

        apdu = bytes([0x80, INS_SIGN, 0x00, 0x00, len(data)]) + data
        risposta = self.process_apdu(apdu)

        sw = (risposta[-2] << 8) | risposta[-1]
        if sw != SW_OK:
            raise CardCommunicationError(
                f"SIGN fallito con SW=0x{sw:04X}"
            )

        firma = risposta[:-2]
        if not firma:
            raise CardCommunicationError("SIGN: la carta ha restituito una firma vuota")

        return firma

    def verify_signature(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verifica una firma digitale usando la libreria cryptography locale.

        Nota: La verifica avviene lato host (non sulla carta) per semplicità.
        In un sistema ad alta sicurezza, si potrebbe delegare la verifica
        a un secondo SE usando un comando APDU dedicato.

        Parametri:
            data: i dati originali che erano stati firmati
            signature: la firma da verificare (formato DER)
            public_key: la chiave pubblica del firmatario (65 byte, uncompressed)

        Ritorna:
            True se la firma è valida, False altrimenti
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            from cryptography.exceptions import InvalidSignature

            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_key
            )
            pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def get_certificate(self) -> bytes:
        """
        Recupera la chiave pubblica dal chip.

        Invia il comando GET_CERTIFICATE (INS=0x60) e restituisce
        la chiave pubblica in formato uncompressed point (65 byte).

        Ritorna:
            La chiave pubblica: 0x04 || X (32 byte) || Y (32 byte)

        Eccezioni:
            CardCommunicationError: errore di comunicazione
        """
        apdu = bytes([0x80, INS_GET_CERTIFICATE, 0x00, 0x00, 0x00])
        risposta = self.process_apdu(apdu)

        sw = (risposta[-2] << 8) | risposta[-1]
        if sw != SW_OK:
            raise CardCommunicationError(
                f"GET_CERTIFICATE fallito con SW=0x{sw:04X}"
            )

        chiave = risposta[:-2]
        if len(chiave) != 65 or chiave[0] != 0x04:
            raise CardCommunicationError(
                f"GET_CERTIFICATE: formato chiave non valido "
                f"({len(chiave)} byte, attesi 65)"
            )

        return chiave

    def disconnect(self) -> None:
        """
        Chiude la connessione con la smart card.

        Chiamare questo metodo quando si ha finito di usare il SE
        per rilasciare le risorse del lettore.
        """
        if self._connection:
            try:
                self._connection.disconnect()
                logger.info("Connessione con la smart card chiusa")
            except Exception as e:
                logger.warning(f"Errore durante la disconnessione: {e}")
            finally:
                self._connection = None

    def __enter__(self):
        """Supporto per il context manager (with statement)."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Chiude automaticamente la connessione al termine del blocco with."""
        self.disconnect()
        return False
