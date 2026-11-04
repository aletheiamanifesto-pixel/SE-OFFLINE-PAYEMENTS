"""
ecash.py — Modalità privacy: monete digitali con firma cieca (e-cash alla Chaum)

DIFFERENZA CON IL PROTOCOLLO v2
Nel v2 il saldo è un numero dentro il chip e ogni pagamento riconciliato dice
all'Emittente chi ha pagato chi. Qui invece il denaro sono MONETE: ognuna ha
un numero di serie casuale e la firma dell'Emittente per il suo taglio.

FIRMA CIECA (blind signature, David Chaum, 1982)
Al prelievo il portafoglio "nasconde" il numero di serie moltiplicandolo per
un fattore casuale. L'Emittente firma il valore nascosto senza vederlo e scala
il conto del cliente. Il portafoglio poi toglie il fattore e ottiene una firma
valida sul numero di serie vero. Quando la moneta torna al deposito
l'Emittente riconosce la propria firma, ma non può sapere a chi l'aveva data.

PRIVACY REVOCABILE SOLO PER CHI FRODA
Ogni volta che una moneta viene spesa, il chip allega una "busta sigillata":
l'identità del chip cifrata con la chiave del GARANTE, un soggetto separato
dall'Emittente (per esempio un'autorità giudiziaria). Le buste di chi spende
onestamente non vengono mai aperte. Solo se la stessa moneta viene depositata
due volte il Garante apre le DUE buste di quella moneta e identifica il chip.

LIMITI (didattici, vedi docs/06_PRIVACY_ECASH.md)
- RSA "da manuale" con hash full-domain: va bene per una demo, non per produzione
  (in produzione: RSA blind signatures RFC 9474 o schemi su curve ellittiche).
- La busta per il Garante è affidabile solo se scritta da un chip sicuro: chi
  estrae la chiave dal chip può scriverci dentro quello che vuole.
"""

import hashlib
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

TAGLI = (200, 100, 50, 20, 10, 5)  # centesimi: 2 €, 1 €, 50, 20, 10, 5 cent
TAG_MONETA = b"AGE1"
SERIALE_LEN = 32
RSA_BITS = 2048


def euro(cent: int) -> str:
    return f"{cent / 100:.2f} €".replace(".", ",")


def hash_su_modulo(dati: bytes, n: int) -> int:
    """Hash "full-domain": SHA-256 esteso fino alla lunghezza del modulo RSA."""
    k = (n.bit_length() + 7) // 8
    flusso = b"".join(hashlib.sha256(dati + i.to_bytes(4, "big")).digest()
                      for i in range(k // 32 + 1))
    return int.from_bytes(flusso[:k], "big") % n


def messaggio_moneta(taglio: int, seriale: bytes) -> bytes:
    return TAG_MONETA + taglio.to_bytes(4, "big") + seriale


@dataclass(frozen=True)
class Moneta:
    taglio: int
    seriale: bytes
    firma: int

    @property
    def id_breve(self) -> str:
        return self.seriale[:4].hex()


@dataclass(frozen=True)
class Spesa:
    """Ciò che passa via NFC per ogni moneta: la moneta + la busta per il Garante."""
    moneta: Moneta
    beneficiario: str
    busta: bytes


class ChiavePubblicaTaglio:
    """La chiave pubblica di un taglio: chiunque può verificare le monete offline."""

    def __init__(self, n: int, e: int):
        self.n, self.e = n, e

    def verifica(self, moneta: Moneta) -> bool:
        m = hash_su_modulo(messaggio_moneta(moneta.taglio, moneta.seriale), self.n)
        return 0 < moneta.firma < self.n and pow(moneta.firma, self.e, self.n) == m


class Garante:
    """Custodisce la chiave che apre le buste. Non vede i pagamenti onesti."""

    def __init__(self):
        self._chiave = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
        self.chiave_pubblica = self._chiave.public_key()
        self.buste_aperte = 0

    def apri(self, busta: bytes) -> tuple[str, bytes]:
        """Ritorna (identità del chip, seriale della moneta) contenuti nella busta."""
        self.buste_aperte += 1
        chiaro = self._chiave.decrypt(busta, _OAEP)
        return chiaro[SERIALE_LEN:].decode(), chiaro[:SERIALE_LEN]


_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


@dataclass
class EsitoDeposito:
    accreditato: int = 0
    rifiutate_false: int = 0
    doppie_spese: list[tuple[Spesa, Spesa]] = field(default_factory=list)


class EmittentePrivato:
    """
    Emette monete con firma cieca e le riaccetta al deposito.
    Sa QUANTO preleva ogni cliente e QUANTO deposita ogni negozio,
    ma non può collegare un prelievo a un pagamento.
    """

    def __init__(self, garante: Garante):
        self.garante = garante
        self._chiavi = {t: rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
                        for t in TAGLI}
        self.chiavi_pubbliche = {t: ChiavePubblicaTaglio(k.public_key().public_numbers().n,
                                                         k.public_key().public_numbers().e)
                                 for t, k in self._chiavi.items()}
        self.conti: dict[str, int] = {}
        self.valori_firmati: list[int] = []   # tutto ciò che l'Emittente ha visto al prelievo
        self._spese_depositate: dict[bytes, Spesa] = {}
        self.doppie_spese_bloccate = 0

    def apri_conto(self, iban: str, saldo: int = 0) -> None:
        self.conti[iban] = saldo

    def firma_cieca(self, iban: str, taglio: int, valore_nascosto: int) -> int:
        """Scala il taglio dal conto e firma un valore che non può leggere."""
        if self.conti.get(iban, 0) < taglio:
            raise ValueError("fondi insufficienti sul conto")
        self.conti[iban] -= taglio
        self.valori_firmati.append(valore_nascosto)
        k = self._chiavi[taglio].private_numbers()
        return pow(valore_nascosto, k.d, k.public_numbers.n)

    def deposita(self, iban: str, spese: list[Spesa]) -> EsitoDeposito:
        esito = EsitoDeposito()
        for spesa in spese:
            moneta = spesa.moneta
            chiave = self.chiavi_pubbliche.get(moneta.taglio)
            if chiave is None or not chiave.verifica(moneta):
                esito.rifiutate_false += 1
                continue
            precedente = self._spese_depositate.get(moneta.seriale)
            if precedente is not None:
                # La moneta è già stata pagata una volta: non si paga di nuovo.
                # Chi l'ha incassata per secondo può rivalersi sul colpevole,
                # che il Garante identifica aprendo le due buste.
                esito.doppie_spese.append((precedente, spesa))
                self.doppie_spese_bloccate += moneta.taglio
                continue
            self._spese_depositate[moneta.seriale] = spesa
            self.conti[iban] = self.conti.get(iban, 0) + moneta.taglio
            esito.accreditato += moneta.taglio
        return esito

    def collega_al_prelievo(self, moneta: Moneta) -> bool:
        """
        L'Emittente prova a capire chi ha prelevato una moneta confrontando
        il suo seriale con i valori che ha firmato. Con la firma cieca fallisce sempre.
        """
        n = self.chiavi_pubbliche[moneta.taglio].n
        m = hash_su_modulo(messaggio_moneta(moneta.taglio, moneta.seriale), n)
        return m in self.valori_firmati or moneta.firma in self.valori_firmati


class PortafoglioPrivato:
    """
    L'applet "monete" dentro il Secure Element del telefono.
    Il chip cancella le monete quando le spende: è l'hardware, non la
    crittografia, a impedire la doppia spesa offline.
    """

    def __init__(self, identita: str, chiavi_pubbliche: dict[int, ChiavePubblicaTaglio],
                 garante_pub):
        self.identita = identita
        self._chiavi = chiavi_pubbliche
        self._garante_pub = garante_pub
        self.monete: list[Moneta] = []
        self._seriali_ricevuti: set[bytes] = set()

    @property
    def saldo(self) -> int:
        return sum(m.taglio for m in self.monete)

    def preleva(self, emittente: EmittentePrivato, iban: str, importo: int) -> int:
        """Prelievo online: genera seriali, li nasconde, li fa firmare, li "svela"."""
        da_prelevare = componi_prelievo(importo)
        for taglio in da_prelevare:
            pub = self._chiavi[taglio]
            seriale = os.urandom(SERIALE_LEN)
            m = hash_su_modulo(messaggio_moneta(taglio, seriale), pub.n)
            while True:
                r = int.from_bytes(os.urandom(RSA_BITS // 8), "big") % pub.n
                if r > 1 and _mcd(r, pub.n) == 1:
                    break
            nascosto = (m * pow(r, pub.e, pub.n)) % pub.n
            firma_nascosta = emittente.firma_cieca(iban, taglio, nascosto)
            firma = (firma_nascosta * pow(r, -1, pub.n)) % pub.n
            moneta = Moneta(taglio, seriale, firma)
            if not pub.verifica(moneta):
                raise ValueError("l'Emittente ha restituito una firma non valida")
            self.monete.append(moneta)
        return len(da_prelevare)

    def paga(self, beneficiario: str, importo: int) -> list[Spesa]:
        """Sceglie le monete, allega le buste sigillate e le CANCELLA dal chip."""
        scelte = scegli_monete(self.monete, importo)
        if scelte is None:
            raise ValueError("monete non sufficienti per l'importo esatto (niente resto offline)")
        spese = []
        for moneta in scelte:
            busta = self._garante_pub.encrypt(moneta.seriale + self.identita.encode(), _OAEP)
            spese.append(Spesa(moneta, beneficiario, busta))
            self.monete.remove(moneta)
        return spese

    def incassa(self, spese: list[Spesa]) -> int:
        """Il beneficiario verifica offline firma, destinatario e monete già viste."""
        for spesa in spese:
            m = spesa.moneta
            if spesa.beneficiario != self.identita:
                raise ValueError("moneta destinata a un altro beneficiario")
            if m.taglio not in self._chiavi or not self._chiavi[m.taglio].verifica(m):
                raise ValueError("moneta falsa: firma dell'Emittente non valida")
            if m.seriale in self._seriali_ricevuti:
                raise ValueError("moneta già ricevuta (copia bloccata)")
        for spesa in spese:
            self._seriali_ricevuti.add(spesa.moneta.seriale)
            self.monete.append(spesa.moneta)
        return sum(s.moneta.taglio for s in spese)


class NegozioPrivato(PortafoglioPrivato):
    """Il POS: tiene le Spese ricevute (con le buste) per depositarle."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._spese_da_depositare: list[Spesa] = []

    def incassa(self, spese: list[Spesa]) -> int:
        totale = super().incassa(spese)
        self._spese_da_depositare.extend(spese)
        return totale

    def deposita(self, emittente: EmittentePrivato, iban: str) -> EsitoDeposito:
        spese, self._spese_da_depositare = self._spese_da_depositare, []
        esito = emittente.deposita(iban, spese)
        depositate = {s.moneta.seriale for s in spese}
        self.monete = [m for m in self.monete if m.seriale not in depositate]
        return esito


def componi_prelievo(importo: int) -> list[int]:
    """
    Come al bancomat: un po' di "spiccioli" per ogni taglio piccolo e il resto
    in monete grandi, così poi si può pagare l'importo esatto (offline niente resto).
    """
    quote = {5: 4, 10: 3, 20: 4, 50: 3, 100: 4}
    tagli, resto = [], importo
    for t in sorted(quote):
        k = min(quote[t], resto // t)
        tagli += [t] * k
        resto -= t * k
    for t in TAGLI:
        while resto >= t:
            tagli.append(t)
            resto -= t
    if resto:
        raise ValueError(f"importo non componibile con i tagli {TAGLI}")
    return tagli


def scegli_monete(monete: list[Moneta], importo: int) -> list[Moneta] | None:
    """Trova un sottoinsieme di monete che fa ESATTAMENTE l'importo, con poche monete."""
    raggiungibili: dict[int, list[Moneta]] = {0: []}
    for moneta in sorted(monete, key=lambda m: -m.taglio):
        for somma, insieme in list(raggiungibili.items()):
            nuova = somma + moneta.taglio
            if nuova <= importo and nuova not in raggiungibili:
                raggiungibili[nuova] = insieme + [moneta]
    return raggiungibili.get(importo)


def _mcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a
