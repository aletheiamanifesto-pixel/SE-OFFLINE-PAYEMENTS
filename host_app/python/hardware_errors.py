"""
hardware_errors.py — Eccezioni personalizzate per errori hardware NFC/Smart Card

Quando si lavora con hardware reale (lettori NFC, smart card), possono
verificarsi molti tipi di errori che non esistono nella simulazione:
  - La carta viene allontanata durante una transazione
  - Il lettore non risponde entro il timeout
  - La comunicazione si corrompe per interferenze RF

Queste eccezioni permettono di gestire ogni tipo di errore in modo
specifico, dando al codice di alto livello le informazioni necessarie
per decidere se riprovare, fare rollback, o segnalare l'errore all'utente.

ANALOGIA: Come i codici di errore di un POS fisico — ciascuno descrive
con precisione cosa è andato storto, così l'operatore sa come intervenire.
"""


class HardwareError(Exception):
    """
    Eccezione base per tutti gli errori hardware del Secure Element.

    Tutte le eccezioni specifiche ereditano da questa classe, permettendo
    di catturare qualsiasi errore hardware con un unico except.

    Esempio:
        try:
            se.process_apdu(apdu)
        except HardwareError as e:
            logger.error(f"Errore hardware: {e}")
    """
    pass


class CardNotFoundError(HardwareError):
    """
    La smart card non è presente nel campo RF del lettore.

    Si verifica quando:
    - Il lettore è connesso ma non c'è nessuna carta
    - La carta è stata rimossa prima che il comando fosse completato
    - La carta è fuori dall'area di lettura

    ANALOGIA: Come inserire la carta nel bancomat e il bancomat
    dice "carta non rilevata" — qualcosa non ha fatto contatto.
    """
    pass


class NFCTimeoutError(HardwareError):
    """
    La comunicazione NFC non ha ricevuto risposta entro il timeout.

    Si verifica quando:
    - La carta impiega troppo tempo a rispondere
    - Interferenze RF rallentano la comunicazione
    - Il chip è occupato con un'operazione lunga

    ATTENZIONE: Questo errore indica uno stato INCERTO della transazione.
    Non si sa se il comando è stato ricevuto dal chip o no. Bisogna
    verificare lo stato prima di riprovare.

    ANALOGIA: Come una chiamata che squilla ma nessuno risponde —
    non sai se il destinatario ha sentito o se c'era un problema di rete.
    """
    pass


class CardCommunicationError(HardwareError):
    """
    Errore durante la comunicazione con la smart card.

    Si verifica quando:
    - Il protocollo APDU riceve una risposta malformata
    - Errori di parità o CRC nella trasmissione RF
    - La carta restituisce uno status word inatteso

    Di solito è sicuro riprovare dopo questo errore, a meno che
    non si tratti di un errore di protocollo sistematico.

    ANALOGIA: Come un messaggio corrotto durante una chiamata —
    il destinatario ha ricevuto qualcosa, ma incomprensibile.
    """
    pass


class TornTransactionError(HardwareError):
    """
    La transazione è stata interrotta a metà (torn transaction).

    Questo è il caso più critico: il debit è avvenuto ma il credit
    potrebbe non essere completato, o viceversa. Lo stato del sistema
    è INCONSISTENTE e richiede un processo di riconciliazione.

    Si verifica quando:
    - Il campo NFC viene interrotto durante una sequenza critica
    - Il telefono si scarica a metà pagamento
    - La carta viene allontanata tra debit e credit

    IMPORTANTE: Questo errore deve essere sempre loggato e il sistema
    deve tentare un rollback o avviare il processo di riconciliazione.

    ANALOGIA: Come un bonifico che parte dal tuo conto ma non arriva
    a destinazione — i soldi sembrano spariti nel nulla.
    """

    def __init__(self, message: str, amount: int = 0, payer_debited: bool = False,
                 receiver_credited: bool = False):
        """
        Inizializza l'eccezione con informazioni sulla transazione parziale.

        Parametri:
            message: descrizione dell'errore
            amount: importo coinvolto nella transazione (centesimi)
            payer_debited: True se il debit sul pagatore è avvenuto
            receiver_credited: True se il credit al ricevente è avvenuto
        """
        super().__init__(message)
        self.amount = amount
        self.payer_debited = payer_debited
        self.receiver_credited = receiver_credited


class AppletNotFoundError(HardwareError):
    """
    L'applet con l'AID specificato non è presente sulla smart card.

    Si verifica quando:
    - L'applet non è stato installato sulla carta
    - L'AID usato per la selezione è sbagliato
    - La carta è di tipo diverso (non Java Card AEGIS)

    ANALOGIA: Come cercare un'app sul telefono che non hai installato —
    il sistema risponde "app non trovata".
    """

    def __init__(self, message: str, aid: bytes = b''):
        """
        Inizializza l'eccezione con l'AID che non è stato trovato.

        Parametri:
            message: descrizione dell'errore
            aid: l'AID dell'applet che non è stato trovato
        """
        super().__init__(message)
        self.aid = aid
        self.aid_hex = aid.hex().upper() if aid else ''
