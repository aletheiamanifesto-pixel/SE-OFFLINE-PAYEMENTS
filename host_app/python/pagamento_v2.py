"""
pagamento_v2.py — Lato "terminale" del protocollo v2 (telefono o POS)

Il terminale non tocca mai il denaro: fa solo da POSTINO tra i chip.
  1. Chiede al chip del pagatore un pacchetto di pagamento (PAY)
  2. Lo consegna al chip del beneficiario (RECEIVE)
  3. Lo conserva nel registro, da inviare all'Emittente quando torna la rete

Se la connessione NFC si interrompe tra il punto 1 e il punto 2 il denaro
NON va perso: il pacchetto resta nel chip del pagatore e si rilegge con
GET_LAST_PAYMENT. Il beneficiario non può incassarlo due volte grazie al contatore.

Tutte le funzioni accettano qualsiasi SecureElementInterface che parli APDU.
"""

import struct

from .se_interface import SecureElementInterface
from . import protocollo_v2 as v2

APDU_SELECT = bytes([0x00, 0xA4, 0x00, 0x00, 0x00])


class ErroreProtocollo(Exception):
    """Il chip ha risposto con una status word diversa da 0x9000."""

    def __init__(self, sw: int, operazione: str):
        self.sw = sw
        self.operazione = operazione
        super().__init__(f"{operazione}: {v2.descrivi_sw(sw)} (SW=0x{sw:04X})")


class ConnessioneInterrotta(Exception):
    """Simula il distacco del telefono dal POS a metà pagamento."""


def invia(se: SecureElementInterface, ins: int, data: bytes = b"", operazione: str = "") -> bytes:
    """SELECT + comando v2. Ritorna i dati di risposta o solleva ErroreProtocollo."""
    se.process_apdu(APDU_SELECT)
    risposta = se.process_apdu(bytes([0x80, ins, 0x00, 0x00, len(data)]) + data)
    sw = (risposta[-2] << 8) | risposta[-1]
    if sw != 0x9000:
        raise ErroreProtocollo(sw, operazione or f"INS 0x{ins:02X}")
    return risposta[:-2]


def leggi_device_id(se: SecureElementInterface) -> bytes:
    return invia(se, v2.INS_GET_DEVICE_ID, operazione="GET_DEVICE_ID")


def richiedi_pagamento(pagatore: SecureElementInterface, payee_id: bytes, importo: int) -> v2.Pacchetto:
    """Il chip del pagatore scala il saldo e firma il token (PAY)."""
    dati = invia(pagatore, v2.INS_PAY, payee_id + struct.pack(">I", importo), "PAY")
    return v2.Pacchetto.decode(dati)


def consegna_pagamento(ricevente: SecureElementInterface, pacchetto: v2.Pacchetto) -> int:
    """Il chip del beneficiario verifica e accredita (RECEIVE). Ritorna il nuovo saldo."""
    dati = invia(ricevente, v2.INS_RECEIVE, pacchetto.encode(), "RECEIVE")
    return struct.unpack(">I", dati)[0]


def recupera_ultimo_pagamento(pagatore: SecureElementInterface) -> v2.Pacchetto:
    """Rilegge l'ultimo pacchetto emesso dal pagatore (dopo un'interruzione NFC)."""
    return v2.Pacchetto.decode(invia(pagatore, v2.INS_GET_LAST_PAYMENT, operazione="GET_LAST_PAYMENT"))


class TerminalePOS:
    """
    Il POS del negoziante: incassa pagamenti offline e tiene il registro
    dei pacchetti ricevuti per la sincronizzazione con l'Emittente.
    """

    def __init__(self, chip: SecureElementInterface, nome: str = "POS"):
        self.chip = chip
        self.nome = nome
        self.registro: list[v2.Pacchetto] = []

    @property
    def device_id(self) -> bytes:
        return leggi_device_id(self.chip)

    def incassa(self, pagatore: SecureElementInterface, importo: int,
                interrompi_dopo_pay: bool = False) -> v2.Pacchetto:
        """Pagamento completo con un "tap": PAY sul pagatore, RECEIVE sul POS."""
        pacchetto = richiedi_pagamento(pagatore, self.device_id, importo)
        if interrompi_dopo_pay:
            raise ConnessioneInterrotta("telefono allontanato prima della consegna del token")
        return self.ricevi(pacchetto)

    def ricevi(self, pacchetto: v2.Pacchetto) -> v2.Pacchetto:
        consegna_pagamento(self.chip, pacchetto)
        self.registro.append(pacchetto)
        return pacchetto

    def riprendi_pagamento_interrotto(self, pagatore: SecureElementInterface) -> v2.Pacchetto:
        """Secondo "tap": rilegge il token rimasto nel chip del pagatore e lo incassa."""
        return self.ricevi(recupera_ultimo_pagamento(pagatore))

    def svuota_registro(self) -> list[v2.Pacchetto]:
        pacchetti, self.registro = self.registro, []
        return pacchetti
