"""
AEGIS Offline Payments — APDU Command Builders & Parsers
=========================================================

Implements the ISO 7816-4 APDU encoding for all commands supported
by the AegisPaymentApplet running on the Secure Element.

Each function returns a ``bytes`` object representing the full
command APDU that can be transmitted over NFC / contact interface.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

# ── Class byte ──────────────────────────────────────────────────
CLA_AEGIS: int = 0x80

# ── Instruction codes (must match Constants.java) ──────────────
INS_GET_VERSION = 0x02
INS_GET_BALANCE = 0x10
INS_GET_COUNTER = 0x12
INS_GET_PUBLIC_KEY = 0x14
INS_INITIATE_PAYMENT = 0x20
INS_RECEIVE_PAYMENT = 0x22
INS_VERIFY_SIGNATURE = 0x30
INS_GET_LAST_RECEIPT = 0x40
INS_LOAD_BALANCE = 0x50
INS_VERIFY_PIN = 0x60
INS_GENERATE_KEYS = 0x70

# ── Status Words ────────────────────────────────────────────────
SW_OK = 0x9000


# ── APDU Response container ─────────────────────────────────────
@dataclass
class APDUResponse:
    """Parsed response from the Secure Element."""

    data: bytes
    sw1: int
    sw2: int

    @property
    def sw(self) -> int:
        return (self.sw1 << 8) | self.sw2

    @property
    def is_ok(self) -> bool:
        return self.sw == SW_OK


# ── Builder helpers ─────────────────────────────────────────────
def _build(ins: int, p1: int = 0, p2: int = 0,
           data: Optional[bytes] = None, le: Optional[int] = None) -> bytes:
    """Build a complete APDU command."""
    header = bytes([CLA_AEGIS, ins, p1, p2])
    if data is not None:
        lc = len(data)
        if lc > 255:
            raise ValueError(f"APDU data too long: {lc} bytes (max 255)")
        cmd = header + bytes([lc]) + data
    else:
        cmd = header
    if le is not None:
        cmd += bytes([le])
    return cmd


# ── Command builders ────────────────────────────────────────────

def get_version() -> bytes:
    """GET_VERSION → 3 bytes (major, minor, patch)."""
    return _build(INS_GET_VERSION, le=3)


def get_balance() -> bytes:
    """GET_BALANCE → 4 bytes (big-endian euro-cents)."""
    return _build(INS_GET_BALANCE, le=4)


def get_counter() -> bytes:
    """GET_COUNTER → 4 bytes (big-endian counter)."""
    return _build(INS_GET_COUNTER, le=4)


def get_public_key() -> bytes:
    """GET_PUBLIC_KEY → 33 bytes (compressed secp256k1 key)."""
    return _build(INS_GET_PUBLIC_KEY, le=33)


def initiate_payment(receiver_pubkey: bytes, amount_cents: int,
                     timestamp_ms: int) -> bytes:
    """
    INITIATE_PAYMENT

    Parameters
    ----------
    receiver_pubkey : bytes
        33-byte compressed public key of the receiver.
    amount_cents : int
        Amount in euro-cents (1–50000).
    timestamp_ms : int
        Unix timestamp in milliseconds (8 bytes big-endian).

    Returns
    -------
    bytes
        Full APDU command (Lc = 45).
    """
    if len(receiver_pubkey) != 33:
        raise ValueError("receiver_pubkey must be 33 bytes (compressed)")
    if not (0 < amount_cents <= 50000):
        raise ValueError("amount_cents must be 1..50000")
    data = (
        receiver_pubkey
        + struct.pack(">I", amount_cents)
        + struct.pack(">Q", timestamp_ms)
    )
    return _build(INS_INITIATE_PAYMENT, data=data, le=0)


def receive_payment(sender_pubkey_uncompressed: bytes,
                    signed_receipt: bytes) -> bytes:
    """
    RECEIVE_PAYMENT

    Parameters
    ----------
    sender_pubkey_uncompressed : bytes
        65-byte uncompressed public key of the sender.
    signed_receipt : bytes
        Signed receipt blob from the sender's INITIATE_PAYMENT response.

    Returns
    -------
    bytes
        Full APDU command.
    """
    if len(sender_pubkey_uncompressed) != 65:
        raise ValueError("sender_pubkey must be 65 bytes (uncompressed)")
    data = sender_pubkey_uncompressed + signed_receipt
    return _build(INS_RECEIVE_PAYMENT, data=data)


def get_last_receipt() -> bytes:
    """GET_LAST_RECEIPT → variable-length receipt."""
    return _build(INS_GET_LAST_RECEIPT, le=0)


def load_balance(amount_cents: int) -> bytes:
    """
    LOAD_BALANCE (requires prior PIN verification).

    Parameters
    ----------
    amount_cents : int
        Amount to load in euro-cents.
    """
    data = struct.pack(">I", amount_cents)
    return _build(INS_LOAD_BALANCE, data=data)


def verify_pin(pin: str) -> bytes:
    """
    VERIFY_PIN

    Parameters
    ----------
    pin : str
        6-digit PIN as ASCII string.
    """
    pin_bytes = pin.encode("ascii")
    if len(pin_bytes) != 6:
        raise ValueError("PIN must be exactly 6 digits")
    return _build(INS_VERIFY_PIN, data=pin_bytes)


def generate_keys() -> bytes:
    """GENERATE_KEYS → generates a new key pair, returns compressed pubkey."""
    return _build(INS_GENERATE_KEYS, le=33)


# ── Response parsers ────────────────────────────────────────────

def parse_response(raw: bytes) -> APDUResponse:
    """
    Parse a raw response (data || SW1 || SW2) into an APDUResponse.

    Parameters
    ----------
    raw : bytes
        At least 2 bytes (SW1, SW2).

    Returns
    -------
    APDUResponse
    """
    if len(raw) < 2:
        raise ValueError("Response too short")
    return APDUResponse(
        data=raw[:-2],
        sw1=raw[-2],
        sw2=raw[-1],
    )


def parse_balance(data: bytes) -> int:
    """Parse 4-byte big-endian balance into euro-cents."""
    return struct.unpack(">I", data[:4])[0]


def parse_counter(data: bytes) -> int:
    """Parse 4-byte big-endian counter."""
    return struct.unpack(">I", data[:4])[0]


def parse_version(data: bytes) -> tuple[int, int, int]:
    """Parse 3-byte version → (major, minor, patch)."""
    return (data[0], data[1], data[2])
