"""
AEGIS Offline Payments — Secure Element Communication Layer
=============================================================

Provides an abstract interface and concrete implementations for
communicating with the AEGIS applet on a Secure Element.

Transports:
    • SimulatedTransport  — talks to the Python SE simulator
    • NFCTransport        — placeholder for real NFC (pyscard/nfcpy)
"""

from __future__ import annotations

import abc
from typing import Optional

from . import apdu
from .apdu import APDUResponse
from .exceptions import APDUError, CommunicationError


class SETransport(abc.ABC):
    """Abstract NFC / contact transport."""

    @abc.abstractmethod
    def transmit(self, command: bytes) -> bytes:
        """
        Send an APDU command and return the raw response bytes
        (data || SW1 || SW2).
        """

    @abc.abstractmethod
    def connect(self) -> None:
        """Establish the physical connection."""

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Release the physical connection."""


class SecureElement:
    """
    High-level wrapper around an SE transport.

    Translates raw byte responses into Python objects and raises
    typed exceptions on error status words.
    """

    def __init__(self, transport: SETransport):
        self._transport = transport

    # ── Low-level ────────────────────────────────────────────────

    def send(self, command: bytes) -> APDUResponse:
        """Send command and parse response, raising on error."""
        try:
            raw = self._transport.transmit(command)
        except Exception as e:
            raise CommunicationError(f"Transport error: {e}") from e

        resp = apdu.parse_response(raw)
        if not resp.is_ok:
            raise APDUError(resp.sw1, resp.sw2)
        return resp

    def connect(self) -> None:
        self._transport.connect()

    def disconnect(self) -> None:
        self._transport.disconnect()

    # ── High-level commands ──────────────────────────────────────

    def get_version(self) -> tuple[int, int, int]:
        """Return (major, minor, patch) version of the SE applet."""
        resp = self.send(apdu.get_version())
        return apdu.parse_version(resp.data)

    def get_balance(self) -> int:
        """Return wallet balance in euro-cents."""
        resp = self.send(apdu.get_balance())
        return apdu.parse_balance(resp.data)

    def get_balance_euro(self) -> float:
        """Return wallet balance in euros."""
        return self.get_balance() / 100.0

    def get_counter(self) -> int:
        """Return monotonic transaction counter."""
        resp = self.send(apdu.get_counter())
        return apdu.parse_counter(resp.data)

    def get_public_key(self) -> bytes:
        """Return compressed public key (33 bytes)."""
        resp = self.send(apdu.get_public_key())
        return resp.data

    def initiate_payment(self, receiver_pubkey: bytes,
                         amount_cents: int,
                         timestamp_ms: int) -> bytes:
        """
        Initiate a debit payment.

        Returns the signed receipt blob.
        """
        cmd = apdu.initiate_payment(receiver_pubkey, amount_cents,
                                     timestamp_ms)
        resp = self.send(cmd)
        return resp.data

    def receive_payment(self, sender_pubkey_uncompressed: bytes,
                        signed_receipt: bytes) -> None:
        """
        Receive and credit an incoming payment.

        Verifies the sender's signature inside the SE.
        """
        cmd = apdu.receive_payment(sender_pubkey_uncompressed,
                                    signed_receipt)
        self.send(cmd)

    def get_last_receipt(self) -> Optional[bytes]:
        """Return the last stored receipt, or None."""
        resp = self.send(apdu.get_last_receipt())
        return resp.data if resp.data else None

    def load_balance(self, amount_cents: int) -> None:
        """Load balance (issuer). Requires prior verify_pin()."""
        self.send(apdu.load_balance(amount_cents))

    def verify_pin(self, pin: str) -> None:
        """Verify the 6-digit PIN."""
        self.send(apdu.verify_pin(pin))

    def generate_keys(self) -> bytes:
        """Generate a new key pair. Returns compressed public key."""
        resp = self.send(apdu.generate_keys())
        return resp.data
