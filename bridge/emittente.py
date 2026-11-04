"""
emittente.py — L'Emittente della moneta offline (banca / istituto di moneta elettronica)

È l'unico attore che deve essere ONLINE. Fa quattro cose:
  1. PERSONALIZZA i chip: firma la loro chiave pubblica (certificato)
  2. CARICA e SCARICA: sposta denaro tra il conto bancario e il chip
  3. RICONCILIA: riceve i registri dei POS e scopre le doppie spese
  4. REVOCA: pubblica la lista dei chip compromessi, che i POS scaricano

Il denaro offline in circolazione è sempre:
    totale caricato − totale scaricato
Se un chip viene clonato, la riconciliazione scopre lo stesso contatore
usato due volte: il chip viene revocato e la perdita contabilizzata.

In questa simulazione i conti sono in memoria. In un sistema reale questo
modulo vivrebbe sui server dell'Emittente, dietro API autenticate.
"""

import logging
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec

from host_app.python import protocollo_v2 as v2
from host_app.python.pagamento_v2 import ErroreProtocollo, invia, leggi_device_id
from host_app.python.se_interface import SecureElementInterface

logger = logging.getLogger(__name__)

LIMITE_DETENZIONE_DEFAULT = 300_00  # 300,00€ per chip, come i limiti discussi per l'euro digitale


class OperazioneRifiutata(Exception):
    """L'Emittente rifiuta un'operazione (conto senza fondi, chip revocato, ...)."""


@dataclass
class DoppiaSpesa:
    payer_id: bytes
    contatore: int
    beneficiari: tuple[bytes, bytes]
    importo: int


@dataclass
class RapportoSincronizzazione:
    accettati: int = 0
    duplicati: int = 0
    non_validi: int = 0
    doppie_spese: list[DoppiaSpesa] = field(default_factory=list)
    da_revocati: int = 0  # pagamenti di chip già revocati, accettati da POS non aggiornati


class Emittente:

    def __init__(self, nome: str = "Emittente AEGIS"):
        self.nome = nome
        self._chiave = ec.generate_private_key(ec.SECP256R1())
        self.chiave_pubblica = v2.chiave_pubblica_bytes(self._chiave.public_key())
        self.conti: dict[str, int] = {}
        self.chip: dict[bytes, dict] = {}
        self.revocati: set[bytes] = set()
        self.versione_revoche = 0
        self._pagamenti_visti: dict[tuple[bytes, int], v2.Pacchetto] = {}
        self.totale_caricato = 0
        self.totale_scaricato = 0
        self.perdite = 0

    # -------------------------------------------------------------- conti
    def apri_conto(self, iban: str, saldo: int = 0) -> None:
        self.conti[iban] = saldo

    # -------------------------------------------------------------- chip
    def personalizza(self, se: SecureElementInterface, titolare: str,
                     limite: int = LIMITE_DETENZIONE_DEFAULT) -> bytes:
        """Certifica un chip nuovo. Ritorna il suo device_id."""
        chiave_chip = se.get_certificate()
        device_id = v2.device_id_da_chiave(chiave_chip)
        corpo = v2.Certificato(device_id, chiave_chip, limite, b"").corpo()
        cert = v2.Certificato(device_id, chiave_chip, limite, v2.firma_raw(self._chiave, corpo))
        invia(se, v2.INS_PERSONALIZE, self.chiave_pubblica + cert.encode(), "PERSONALIZE")
        self.chip[device_id] = {"titolare": titolare, "chiave": chiave_chip, "limite": limite}
        logger.info("Chip %s personalizzato per %s", device_id.hex(), titolare)
        return device_id

    def titolare(self, device_id: bytes) -> str:
        return self.chip.get(device_id, {}).get("titolare", device_id.hex())

    def _ordine(self, tag: bytes, device_id: bytes, importo: int) -> bytes:
        corpo = v2.corpo_ordine(tag, device_id, importo, os.urandom(8))
        return corpo + v2.firma_raw(self._chiave, corpo)

    def _controlla_chip(self, se: SecureElementInterface) -> bytes:
        device_id = leggi_device_id(se)
        if device_id not in self.chip:
            raise OperazioneRifiutata("chip sconosciuto all'Emittente")
        if device_id in self.revocati:
            raise OperazioneRifiutata("chip revocato: operazione bloccata")
        return device_id

    def carica(self, iban: str, se: SecureElementInterface, importo: int) -> None:
        """Dal conto al chip (online)."""
        device_id = self._controlla_chip(se)
        if self.conti.get(iban, 0) < importo:
            raise OperazioneRifiutata("fondi insufficienti sul conto")
        try:
            invia(se, v2.INS_LOAD, self._ordine(v2.TAG_LOAD, device_id, importo), "LOAD")
        except ErroreProtocollo as e:
            raise OperazioneRifiutata(str(e)) from e
        self.conti[iban] -= importo
        self.totale_caricato += importo

    def scarica(self, se: SecureElementInterface, iban: str, importo: int) -> None:
        """Dal chip al conto (online). Il chip conferma con la propria firma."""
        device_id = self._controlla_chip(se)
        ordine = self._ordine(v2.TAG_UNLOAD, device_id, importo)
        try:
            conferma = invia(se, v2.INS_UNLOAD, ordine, "UNLOAD")
        except ErroreProtocollo as e:
            raise OperazioneRifiutata(str(e)) from e
        attesa = v2.TAG_UNLOAD_OK + ordine[4:v2.ORDINE_BODY_LEN]
        if not v2.verifica_raw(self.chip[device_id]["chiave"], attesa, conferma):
            raise OperazioneRifiutata("conferma di scarico non valida")
        self.conti[iban] = self.conti.get(iban, 0) + importo
        self.totale_scaricato += importo

    # -------------------------------------------------------------- riconciliazione
    def sincronizza(self, pacchetti: list[v2.Pacchetto]) -> RapportoSincronizzazione:
        """
        Riceve i pacchetti incassati da un POS. Per ogni coppia
        (chip pagatore, contatore) deve esistere UN SOLO token:
        se ne arrivano due diversi, il chip del pagatore è stato clonato.
        """
        rapporto = RapportoSincronizzazione()
        for p in pacchetti:
            if not (p.certificato.valido(self.chiave_pubblica) and p.firma_valida()):
                rapporto.non_validi += 1
                continue
            chiave = (p.token.payer_id, p.token.contatore)
            precedente = self._pagamenti_visti.get(chiave)
            if precedente is None:
                self._pagamenti_visti[chiave] = p
                rapporto.accettati += 1
                if p.token.payer_id in self.revocati:
                    # Il denaro del chip revocato non è più garantito: è una perdita
                    rapporto.da_revocati += 1
                    self.perdite += p.token.importo
            elif precedente.token == p.token:
                rapporto.duplicati += 1
            else:
                rapporto.doppie_spese.append(DoppiaSpesa(
                    p.token.payer_id, p.token.contatore,
                    (precedente.token.payee_id, p.token.payee_id), p.token.importo))
                self.perdite += p.token.importo
                self.revoca(p.token.payer_id)
        return rapporto

    # -------------------------------------------------------------- revoche
    def revoca(self, device_id: bytes) -> None:
        if device_id not in self.revocati:
            self.revocati.add(device_id)
            self.versione_revoche += 1
            logger.info("Chip %s revocato", device_id.hex())

    def lista_revoche(self) -> bytes:
        corpo = v2.corpo_revoche(self.versione_revoche, sorted(self.revocati))
        return corpo + v2.firma_raw(self._chiave, corpo)

    def distribuisci_revoche(self, se: SecureElementInterface) -> bool:
        """Aggiorna la lista revoche su un chip. Ritorna False se era già aggiornata."""
        if self.versione_revoche == 0:
            return False
        try:
            invia(se, v2.INS_UPDATE_REVOCATIONS, self.lista_revoche(), "UPDATE_REVOCATIONS")
            return True
        except ErroreProtocollo as e:
            if e.sw == v2.SW_REPLAY:
                return False
            raise

    # -------------------------------------------------------------- contabilità
    def in_circolazione(self) -> int:
        """Denaro offline garantito dall'Emittente (escluse le perdite da frode)."""
        return self.totale_caricato - self.totale_scaricato
