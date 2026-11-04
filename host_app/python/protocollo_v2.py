"""
protocollo_v2.py — Formati binari del protocollo di pagamento offline v2

PERCHÉ UN PROTOCOLLO v2?
Nel protocollo v1 (DEBIT / CREDIT / SIGN separati) il comando CREDIT non è
autenticato: chiunque può mandarlo al proprio chip e "stampare" denaro.
Inoltre la firma arriva DOPO il trasferimento e non dice a chi sono destinati
i soldi, quindi una ricevuta può essere riusata verso un altro chip.

Il v2 risolve questi problemi con tre regole:
  1. Il denaro ENTRA in un chip solo con un ordine firmato dall'Emittente (LOAD)
     oppure con un TOKEN DI PAGAMENTO firmato da un altro chip certificato (RECEIVE).
  2. Il pagatore scala il saldo, incrementa il contatore e firma il token in
     UN'UNICA operazione atomica (PAY). Il token indica pagatore, beneficiario,
     importo e contatore: non può essere dirottato né riusato.
  3. Ogni chip ha un CERTIFICATO firmato dall'Emittente: il beneficiario
     verifica offline che il pagatore sia un chip autentico e non revocato.

Tutti i formati sono a lunghezza fissa e stanno in un APDU "short" (≤ 255 byte),
così lo stesso protocollo può girare su una JavaCard reale.

FORMATI (big-endian):
  Token        "AGP2" | payer_id(8) | payee_id(8) | importo(4) | contatore(4)   = 28 byte
  Certificato  "AGC2" | device_id(8) | chiave_pubblica(65) | limite(4)          = 81 byte + firma(64)
  Pacchetto    token(28) | firma_pagatore(64) | certificato(145)                = 237 byte
  Ordine       "AGL2"/"AGU2" | device_id(8) | importo(4) | nonce(8)             = 24 byte + firma(64)
  Revoche      "AGR2" | versione(4) | n(1) | n × device_id(8)                    + firma(64)

Le firme sono ECDSA P-256 / SHA-256 in formato grezzo r||s (64 byte),
più compatto del DER e a lunghezza fissa.
"""

import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)

# =============================================================================
# ETICHETTE DI DOMINIO
# Ogni messaggio firmato inizia con un'etichetta diversa, così una firma valida
# per un tipo di messaggio non può essere spacciata per un altro.
# =============================================================================
TAG_TOKEN = b"AGP2"
TAG_CERT = b"AGC2"
TAG_LOAD = b"AGL2"
TAG_UNLOAD = b"AGU2"
TAG_UNLOAD_OK = b"AGK2"
TAG_REVOCHE = b"AGR2"

# Prefisso riservato: i comandi generici SIGN / MUTUAL_AUTH lo rifiutano,
# altrimenti il chip potrebbe essere usato come "oracolo" per firmare token falsi.
PREFISSO_RISERVATO = b"AG"

ID_LEN = 8
PUB_LEN = 65
SIG_LEN = 64

TOKEN_LEN = 4 + ID_LEN + ID_LEN + 4 + 4
CERT_BODY_LEN = 4 + ID_LEN + PUB_LEN + 4
CERT_LEN = CERT_BODY_LEN + SIG_LEN
PACCHETTO_LEN = TOKEN_LEN + SIG_LEN + CERT_LEN
ORDINE_BODY_LEN = 4 + ID_LEN + 4 + 8
ORDINE_LEN = ORDINE_BODY_LEN + SIG_LEN
MAX_REVOCHE = (255 - 4 - 4 - 1 - SIG_LEN) // ID_LEN

# =============================================================================
# CODICI ISTRUZIONE v2 (CLA = 0x80)
# =============================================================================
INS_PAY = 0x82                # Paga: addebito + contatore + firma token, atomico
INS_RECEIVE = 0x84            # Incassa: verifica pacchetto e accredita
INS_GET_LAST_PAYMENT = 0x86   # Rilegge l'ultimo pacchetto emesso (recupero NFC interrotto)
INS_LOAD = 0x88               # Carica: ordine firmato dall'Emittente
INS_UNLOAD = 0x8A             # Scarica: ordine firmato dall'Emittente, risposta firmata dal chip
INS_UPDATE_REVOCATIONS = 0x8C # Aggiorna la lista dei chip revocati
INS_GET_DEVICE_ID = 0x8E      # Identificativo del chip (8 byte)
INS_PERSONALIZE = 0x90        # Personalizzazione in fabbrica: chiave Emittente + certificato

# =============================================================================
# STATUS WORD v2
# =============================================================================
SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982  # Firma/certificato non validi o comando legacy bloccato
SW_WRONG_DATA = 0x6A80                     # Dati incoerenti (es. pagamento per un altro chip)
SW_REVOKED = 0x6A81                        # Chip del pagatore revocato
SW_REPLAY = 0x6A89                         # Token o ordine già usato
SW_LIMIT_EXCEEDED = 0x6984                 # Supererebbe il limite di detenzione

DESCRIZIONE_SW = {
    0x9000: "OK",
    0x6700: "lunghezza dati errata",
    0x6982: "firma o certificato non validi (o comando non consentito)",
    0x6984: "supererebbe il limite di detenzione del chip",
    0x6985: "saldo insufficiente",
    0x6986: "chip non personalizzato o applet non selezionata",
    0x6A80: "pagamento destinato a un altro chip",
    0x6A81: "chip del pagatore REVOCATO",
    0x6A89: "token già usato (replay bloccato)",
    0x6D00: "istruzione non supportata",
}


def descrivi_sw(sw: int) -> str:
    return DESCRIZIONE_SW.get(sw, f"errore 0x{sw:04X}")


# =============================================================================
# CRITTOGRAFIA
# =============================================================================

def device_id_da_chiave(chiave_pubblica: bytes) -> bytes:
    """L'identificativo del chip è l'impronta della sua chiave pubblica."""
    return hashlib.sha256(chiave_pubblica).digest()[:ID_LEN]


def chiave_pubblica_bytes(chiave: ec.EllipticCurvePublicKey) -> bytes:
    return chiave.public_bytes(serialization.Encoding.X962,
                               serialization.PublicFormat.UncompressedPoint)


def firma_raw(chiave_privata: ec.EllipticCurvePrivateKey, messaggio: bytes) -> bytes:
    der = chiave_privata.sign(messaggio, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verifica_raw(chiave_pubblica: bytes, messaggio: bytes, firma: bytes) -> bool:
    if len(firma) != SIG_LEN:
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), chiave_pubblica)
        der = encode_dss_signature(int.from_bytes(firma[:32], "big"),
                                   int.from_bytes(firma[32:], "big"))
        pub.verify(der, messaggio, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# =============================================================================
# STRUTTURE DATI
# =============================================================================

@dataclass(frozen=True)
class Token:
    payer_id: bytes
    payee_id: bytes
    importo: int
    contatore: int

    def encode(self) -> bytes:
        return (TAG_TOKEN + self.payer_id + self.payee_id
                + struct.pack(">II", self.importo, self.contatore))

    @classmethod
    def decode(cls, dati: bytes) -> "Token":
        if len(dati) != TOKEN_LEN or not dati.startswith(TAG_TOKEN):
            raise ValueError("token malformato")
        importo, contatore = struct.unpack(">II", dati[20:28])
        return cls(dati[4:12], dati[12:20], importo, contatore)


@dataclass(frozen=True)
class Certificato:
    device_id: bytes
    chiave_pubblica: bytes
    limite: int
    firma_emittente: bytes

    def corpo(self) -> bytes:
        return TAG_CERT + self.device_id + self.chiave_pubblica + struct.pack(">I", self.limite)

    def encode(self) -> bytes:
        return self.corpo() + self.firma_emittente

    def valido(self, chiave_emittente: bytes) -> bool:
        return (device_id_da_chiave(self.chiave_pubblica) == self.device_id
                and verifica_raw(chiave_emittente, self.corpo(), self.firma_emittente))

    @classmethod
    def decode(cls, dati: bytes) -> "Certificato":
        if len(dati) != CERT_LEN or not dati.startswith(TAG_CERT):
            raise ValueError("certificato malformato")
        limite = struct.unpack(">I", dati[77:81])[0]
        return cls(dati[4:12], dati[12:77], limite, dati[81:])


@dataclass(frozen=True)
class Pacchetto:
    """Ciò che viaggia via NFC dal pagatore al beneficiario."""
    token: Token
    firma: bytes
    certificato: Certificato

    def encode(self) -> bytes:
        return self.token.encode() + self.firma + self.certificato.encode()

    @classmethod
    def decode(cls, dati: bytes) -> "Pacchetto":
        if len(dati) != PACCHETTO_LEN:
            raise ValueError("pacchetto malformato")
        return cls(Token.decode(dati[:TOKEN_LEN]),
                   dati[TOKEN_LEN:TOKEN_LEN + SIG_LEN],
                   Certificato.decode(dati[TOKEN_LEN + SIG_LEN:]))

    def firma_valida(self) -> bool:
        return (self.token.payer_id == self.certificato.device_id
                and verifica_raw(self.certificato.chiave_pubblica,
                                 self.token.encode(), self.firma))


def corpo_ordine(tag: bytes, device_id: bytes, importo: int, nonce: bytes) -> bytes:
    return tag + device_id + struct.pack(">I", importo) + nonce


def corpo_revoche(versione: int, revocati: list[bytes]) -> bytes:
    if len(revocati) > MAX_REVOCHE:
        raise ValueError(f"al massimo {MAX_REVOCHE} chip revocati per lista")
    return TAG_REVOCHE + struct.pack(">IB", versione, len(revocati)) + b"".join(revocati)
