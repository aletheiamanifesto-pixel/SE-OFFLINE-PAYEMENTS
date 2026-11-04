"""
se_interface.py — Interfaccia astratta per il Secure Element

Definisce il contratto comune che sia il simulatore che l'hardware reale
devono rispettare. È come un "capitolato d'appalto" che specifica esattamente
quali operazioni ogni implementazione deve saper fare, indipendentemente
da come le realizza internamente.

Usando questa interfaccia, il codice di pagamento può lavorare con:
  - Il simulatore Python (per sviluppo e test)
  - Un chip Java Card reale via NFC (in produzione)
  - Qualsiasi altra implementazione futura

È il principio di "dependency inversion": dipendi dall'interfaccia,
non dall'implementazione concreta.
"""

from abc import ABC, abstractmethod


class SecureElementInterface(ABC):
    """
    Interfaccia astratta per un Secure Element (SE).

    Ogni implementazione concreta (simulatore, hardware reale, ecc.)
    deve fornire tutti i metodi qui definiti. Questo garantisce
    l'intercambiabilità tra simulatore e hardware fisico senza
    modificare il codice che usa il Secure Element.

    ANALOGIA: È come la presa elettrica standard. Qualunque dispositivo
    (asciugacapelli, lampada, caricatore) può collegarsi perché rispetta
    lo stesso standard. Chi progetta il dispositivo non deve sapere come
    funziona la rete elettrica, solo che la tensione è 230V.
    """

    @abstractmethod
    def process_apdu(self, apdu_bytes: bytes) -> bytes:
        """
        Elabora un comando APDU e restituisce la risposta.

        È il metodo fondamentale: tutto il resto si basa su questo.
        L'APDU (Application Protocol Data Unit) è il linguaggio universale
        delle smart card.

        Parametri:
            apdu_bytes: il comando APDU come sequenza di byte

        Ritorna:
            La risposta APDU: [dati...] + [SW1, SW2]
        """
        ...

    @abstractmethod
    def get_balance(self) -> int:
        """
        Restituisce il saldo corrente in centesimi.

        Ritorna:
            Il saldo in centesimi (es. 10000 = 100.00€)
        """
        ...

    @abstractmethod
    def debit(self, amount: int) -> bool:
        """
        Addebita un importo dal saldo.

        Parametri:
            amount: importo da sottrarre in centesimi

        Ritorna:
            True se l'operazione è riuscita, False altrimenti
        """
        ...

    @abstractmethod
    def credit(self, amount: int) -> bool:
        """
        Accredita un importo al saldo.

        Parametri:
            amount: importo da aggiungere in centesimi

        Ritorna:
            True se l'operazione è riuscita, False altrimenti
        """
        ...

    @abstractmethod
    def get_counter(self) -> int:
        """
        Restituisce il valore del contatore monotònico.

        Il contatore può solo salire: impedisce i "replay attack"
        (tentativi di riutilizzare una transazione già eseguita).

        Ritorna:
            Il valore corrente del contatore (intero non negativo)
        """
        ...

    @abstractmethod
    def sign_transaction(self, data: bytes) -> bytes:
        """
        Firma digitalmente i dati con la chiave privata del SE.

        La chiave privata non lascia mai il chip. Solo la firma esce.
        Questo garantisce che solo il proprietario del chip può autorizzare
        transazioni, anche se qualcuno intercetta le comunicazioni.

        Parametri:
            data: i byte da firmare (importo + contatore + timestamp)

        Ritorna:
            La firma digitale in formato DER
        """
        ...

    @abstractmethod
    def verify_signature(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verifica l'autenticità di una firma digitale.

        Parametri:
            data: i dati originali su cui è stata calcolata la firma
            signature: la firma da verificare (formato DER)
            public_key: la chiave pubblica del firmatario (65 byte, formato uncompressed)

        Ritorna:
            True se la firma è valida, False altrimenti
        """
        ...

    @abstractmethod
    def get_certificate(self) -> bytes:
        """
        Restituisce la chiave pubblica del Secure Element.

        La chiave pubblica può essere condivisa liberamente: serve
        agli altri partecipanti per verificare le firme di questo SE.

        Ritorna:
            La chiave pubblica in formato uncompressed point (65 byte):
            0x04 || X (32 byte) || Y (32 byte)
        """
        ...
