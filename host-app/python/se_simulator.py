"""
se_simulator.py — Simulatore software del chip Secure Element

Emula il comportamento dell'applet JavaCard OfflineDigitalEuroApplet
interamente in Python, usando la libreria `cryptography` per ECDSA.

Uso:
    from se_simulator import SecureElementSimulator

    chip = SecureElementSimulator(balance_cents=10000)  # 100.00€
    chip.select()
    balance = chip.get_balance()
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature


# ─── Costanti APDU ────────────────────────────────────────────────────────────

CLA_AEGIS             = 0x80
INS_GET_BALANCE       = 0x20
INS_GET_PUBLIC_KEY    = 0x30
INS_INITIATE_PAYMENT  = 0x40
INS_PROCESS_PAYMENT   = 0x50
INS_CONFIRM_PAYMENT   = 0x60
INS_GET_COUNTER       = 0x70
INS_GET_TX_LOG        = 0x80
INS_LOAD_FUNDS        = 0xA0

SW_OK                      = 0x9000
SW_INSUFFICIENT_FUNDS      = 0x9110
SW_INVALID_COUNTER         = 0x9120
SW_INVALID_SIGNATURE       = 0x9130
SW_INVALID_AMOUNT          = 0x9140
SW_OFFLINE_LIMIT_EXCEEDED  = 0x9150

OFFLINE_SPEND_LIMIT_CENTS  = 50_000   # 500.00€
MAX_TX_LOG                 = 10

AID = bytes([0xA0, 0x00, 0x00, 0x08, 0x48, 0x41, 0x45, 0x47, 0x01, 0x00])


# ─── Eccezioni ────────────────────────────────────────────────────────────────

class APDUException(Exception):
    """Eccezione APDU con status word."""

    def __init__(self, sw: int, message: str = ""):
        super().__init__(message or f"APDU error: SW={sw:#06x}")
        self.sw = sw


# ─── Record transazione ───────────────────────────────────────────────────────

@dataclass
class TransactionRecord:
    """Singola transazione nel log del chip."""

    timestamp:     float
    amount_cents:  int
    counter:       int
    peer_pubkey:   bytes    # chiave pubblica della controparte (65 byte)
    direction:     str      # "OUT" (pagato) o "IN" (ricevuto)

    @property
    def amount_euro(self) -> float:
        return self.amount_cents / 100


# ─── Simulatore principale ────────────────────────────────────────────────────

class SecureElementSimulator:
    """
    Simulatore software del chip Secure Element AEGIS.

    Emula fedelmente il comportamento dell'applet JavaCard, incluse:
    - Gestione saldo e debiti/crediti
    - Contatore monotonico anti-replay
    - Firma ECDSA P-256
    - Verifica firme di altri chip
    - Log transazioni circolare
    - Limiti di spesa offline
    """

    def __init__(
        self,
        balance_cents: int = 0,
        name: str = "chip",
        offline_limit_cents: int = OFFLINE_SPEND_LIMIT_CENTS,
    ) -> None:
        """
        Inizializza il simulatore.

        Args:
            balance_cents:        Saldo iniziale in centesimi.
            name:                 Nome del chip (per i log).
            offline_limit_cents:  Limite di spesa offline in centesimi.
        """
        self.name = name
        self._balance_cents: int = balance_cents
        self._offline_spent: int = 0
        self._counter: int = 0
        self._offline_limit: int = offline_limit_cents
        self._selected: bool = False

        # Genera coppia di chiavi ECDSA P-256
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key  = self._private_key.public_key()

        # Log transazioni (max MAX_TX_LOG)
        self._tx_log: list[TransactionRecord] = []

        # Dizionario per tracciare l'ultimo contatore noto per ogni peer (anti-replay)
        # chiave: peer_pubkey (bytes), valore: ultimo counter_peer ricevuto
        self._peer_counters: dict[bytes, int] = {}

        # Buffer transazione in corso (INITIATE → CONFIRM)
        self._pending_amount: Optional[int]   = None
        self._pending_peer_pk: Optional[bytes] = None

    # ─── SELECT ───────────────────────────────────────────────────────────────

    def select(self) -> bytes:
        """Seleziona l'applet. Restituisce il nome della versione."""
        self._selected = True
        return b"AEGIS-EURO-v1.0"

    def _check_selected(self) -> None:
        if not self._selected:
            raise APDUException(0x6A82, "Applet non selezionata")

    # ─── GET_BALANCE ──────────────────────────────────────────────────────────

    def get_balance(self) -> int:
        """Restituisce il saldo in centesimi."""
        self._check_selected()
        return self._balance_cents

    def get_balance_euro(self) -> float:
        """Restituisce il saldo in euro (float)."""
        return self.get_balance() / 100

    def get_balance_bytes(self) -> bytes:
        """Restituisce il saldo come 8 byte big-endian (formato APDU)."""
        return self._balance_cents.to_bytes(8, "big")

    # ─── GET_PUBLIC_KEY ───────────────────────────────────────────────────────

    def get_public_key(self) -> bytes:
        """Restituisce la chiave pubblica (65 byte, formato non compresso)."""
        self._check_selected()
        return self._public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    # ─── GET_COUNTER ──────────────────────────────────────────────────────────

    def get_counter(self) -> int:
        """Restituisce il valore del contatore monotonico."""
        self._check_selected()
        return self._counter

    def get_counter_bytes(self) -> bytes:
        """Restituisce il contatore come 4 byte big-endian."""
        return self._counter.to_bytes(4, "big")

    # ─── INITIATE_PAYMENT ─────────────────────────────────────────────────────

    def initiate_payment(
        self,
        amount_cents: int,
        peer_pubkey_bytes: bytes,
        peer_counter: int,
    ) -> dict:
        """
        Avvia un pagamento (chiamato sul chip del PAGANTE).

        Args:
            amount_cents:      Importo da pagare in centesimi.
            peer_pubkey_bytes: Chiave pubblica del destinatario (65 byte).
            peer_counter:      Contatore corrente del destinatario.

        Returns:
            dict con:
                'pubkey_alice': bytes (65B) — chiave pubblica di questo chip
                'counter_alice': int — contatore di questo chip
                'signature': bytes — firma ECDSA del payload

        Raises:
            APDUException: se saldo insufficiente o limiti superati.
        """
        self._check_selected()

        if amount_cents <= 0:
            raise APDUException(SW_INVALID_AMOUNT, f"Importo non valido: {amount_cents}")

        if self._balance_cents < amount_cents:
            raise APDUException(
                SW_INSUFFICIENT_FUNDS,
                f"Saldo insufficiente: {self._balance_cents} < {amount_cents}",
            )

        if self._offline_spent + amount_cents > self._offline_limit:
            raise APDUException(
                SW_OFFLINE_LIMIT_EXCEEDED,
                f"Limite offline superato: {self._offline_spent + amount_cents} > {self._offline_limit}",
            )

        my_pubkey = self.get_public_key()

        # Payload da firmare:
        # amount(8B) + pubkey_alice(65B) + cnt_alice(4B) + pubkey_bob(65B) + cnt_bob(4B)
        payload = self._build_payload(
            amount_cents, my_pubkey, self._counter, peer_pubkey_bytes, peer_counter
        )

        signature = self._sign(payload)

        # Salva stato pendente (per CONFIRM_PAYMENT)
        self._pending_amount   = amount_cents
        self._pending_peer_pk  = peer_pubkey_bytes

        return {
            "pubkey_alice":   my_pubkey,
            "counter_alice":  self._counter,
            "signature":      signature,
            "payload":        payload,
        }

    # ─── PROCESS_PAYMENT ──────────────────────────────────────────────────────

    def process_payment(
        self,
        amount_cents:    int,
        pubkey_alice:    bytes,
        counter_alice:   int,
        signature:       bytes,
    ) -> int:
        """
        Elabora un pagamento ricevuto (chiamato sul chip del DESTINATARIO).

        Args:
            amount_cents:   Importo in centesimi.
            pubkey_alice:   Chiave pubblica del pagante (65 byte).
            counter_alice:  Contatore del pagante al momento del pagamento.
            signature:      Firma ECDSA del pagante.

        Returns:
            Nuovo saldo in centesimi.

        Raises:
            APDUException: se la firma è invalida o il contatore non valido.
        """
        self._check_selected()

        # Anti-replay: il contatore di Alice deve essere maggiore dell'ultimo noto
        if counter_alice <= self._last_known_counter_for(pubkey_alice):
            raise APDUException(
                SW_INVALID_COUNTER,
                f"Contatore non valido (possibile replay): {counter_alice}",
            )

        my_pubkey = self.get_public_key()

        # Ricostruisce il payload che Alice ha firmato
        payload = self._build_payload(
            amount_cents, pubkey_alice, counter_alice, my_pubkey, self._counter
        )

        # Verifica firma ECDSA di Alice
        if not self._verify(payload, signature, pubkey_alice):
            raise APDUException(SW_INVALID_SIGNATURE, "Firma ECDSA non valida")

        # Accredita il saldo
        self._balance_cents += amount_cents
        self._counter += 1

        # Aggiorna il tracking del contatore del peer (anti-replay)
        self._peer_counters[pubkey_alice] = counter_alice

        # Registra nel log
        self._log_tx(amount_cents, pubkey_alice, "IN")

        return self._balance_cents

    # ─── CONFIRM_PAYMENT ──────────────────────────────────────────────────────

    def confirm_payment(self) -> int:
        """
        Conferma il pagamento (chiamato sul chip del PAGANTE dopo conferma Bob).

        Returns:
            Nuovo saldo in centesimi dopo il debito.

        Raises:
            APDUException: se non c'è un pagamento pendente.
        """
        self._check_selected()

        if self._pending_amount is None:
            raise APDUException(
                0x6985, "Nessun pagamento pendente da confermare"
            )

        amount = self._pending_amount
        peer_pk = self._pending_peer_pk

        # Deduce il saldo
        self._balance_cents -= amount
        self._offline_spent += amount
        self._counter += 1

        # Registra nel log
        self._log_tx(amount, peer_pk, "OUT")

        # Azzera lo stato pendente
        self._pending_amount  = None
        self._pending_peer_pk = None

        return self._balance_cents

    # ─── LOAD_FUNDS ───────────────────────────────────────────────────────────

    def load_funds(self, amount_cents: int) -> int:
        """
        Carica fondi nel portafoglio (solo per sviluppo/test).
        In produzione richiederebbe la firma della CA.

        Returns:
            Nuovo saldo in centesimi.
        """
        self._check_selected()

        if amount_cents <= 0:
            raise APDUException(SW_INVALID_AMOUNT)

        self._balance_cents += amount_cents
        self._offline_spent  = 0
        return self._balance_cents

    # ─── GET_TRANSACTION_LOG ──────────────────────────────────────────────────

    def get_transaction_log(self) -> list[TransactionRecord]:
        """Restituisce il log delle transazioni (più recente per primo)."""
        self._check_selected()
        return list(reversed(self._tx_log))

    # ─── Crittografia (privata) ───────────────────────────────────────────────

    def _build_payload(
        self,
        amount_cents:  int,
        pubkey_a:      bytes,
        counter_a:     int,
        pubkey_b:      bytes,
        counter_b:     int,
    ) -> bytes:
        """
        Costruisce il payload da firmare/verificare.
        Formato: amount(8B) + pk_a(65B) + cnt_a(4B) + pk_b(65B) + cnt_b(4B)
        """
        return (
            amount_cents.to_bytes(8, "big")
            + pubkey_a
            + counter_a.to_bytes(4, "big")
            + pubkey_b
            + counter_b.to_bytes(4, "big")
        )

    def _sign(self, data: bytes) -> bytes:
        """Firma i dati con la chiave privata ECDSA P-256."""
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def _verify(self, data: bytes, signature: bytes, peer_pubkey_bytes: bytes) -> bool:
        """Verifica una firma ECDSA usando la chiave pubblica della controparte."""
        try:
            peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), peer_pubkey_bytes
            )
            peer_pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False

    # ─── Helper privati ───────────────────────────────────────────────────────

    def _log_tx(self, amount_cents: int, peer_pubkey: bytes, direction: str) -> None:
        record = TransactionRecord(
            timestamp=time.time(),
            amount_cents=amount_cents,
            counter=self._counter,
            peer_pubkey=peer_pubkey,
            direction=direction,
        )
        self._tx_log.append(record)
        if len(self._tx_log) > MAX_TX_LOG:
            self._tx_log.pop(0)

    def _last_known_counter_for(self, pubkey: bytes) -> int:
        """
        Restituisce l'ultimo contatore noto per una chiave pubblica.
        Usato per il controllo anti-replay.
        """
        return self._peer_counters.get(pubkey, -1)

    # ─── Rappresentazione ─────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"SecureElementSimulator("
            f"name={self.name!r}, "
            f"balance={self.get_balance_euro():.2f}€, "
            f"counter={self._counter})"
        )

    def status(self) -> str:
        """Stringa di stato leggibile."""
        return (
            f"[{self.name}] "
            f"Saldo: {self.get_balance_euro():.2f}€ | "
            f"Contatore: {self._counter} | "
            f"Speso offline: {self._offline_spent / 100:.2f}€"
        )
