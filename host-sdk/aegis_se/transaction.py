"""
AEGIS Offline Payments — Transaction / Receipt Model
======================================================

Parses and represents transaction receipts produced by the
Secure Element.

Receipt binary layout (v1):
    [0]       version        1 byte  (0x01)
    [1..33]   sender pubkey  33 bytes (compressed)
    [34..66]  receiver pubkey 33 bytes (compressed)
    [67..70]  amount         4 bytes (big-endian, euro-cents)
    [71..74]  counter        4 bytes (big-endian)
    [75..82]  timestamp      8 bytes (big-endian, unix millis)
    [83..N]   ECDSA signature (DER-encoded, variable length)
"""

from __future__ import annotations

import struct
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


# Header field offsets
_VERSION_OFF = 0
_SENDER_OFF = 1
_RECEIVER_OFF = 34
_AMOUNT_OFF = 67
_COUNTER_OFF = 71
_TIMESTAMP_OFF = 75
_SIG_OFF = 83
_HEADER_LEN = 83


@dataclass(frozen=True)
class TransactionReceipt:
    """Parsed transaction receipt from the Secure Element."""

    version: int
    sender_pubkey: bytes        # 33 bytes compressed
    receiver_pubkey: bytes      # 33 bytes compressed
    amount_cents: int           # euro-cents
    counter: int                # sender's counter at tx time
    timestamp_ms: int           # unix millis
    signature: bytes            # DER-encoded ECDSA
    raw: bytes                  # full receipt bytes

    @property
    def amount_euro(self) -> float:
        return self.amount_cents / 100.0

    @property
    def timestamp(self) -> datetime:
        return datetime.fromtimestamp(
            self.timestamp_ms / 1000.0, tz=timezone.utc
        )

    @property
    def header(self) -> bytes:
        """The signed portion of the receipt (everything except signature)."""
        return self.raw[:_HEADER_LEN]

    @property
    def receipt_hash(self) -> str:
        """SHA-256 hex digest of the full receipt (used as tx ID)."""
        return hashlib.sha256(self.raw).hexdigest()

    def __str__(self) -> str:
        return (
            f"TxReceipt(v{self.version}  "
            f"{self.amount_euro:.2f}€  "
            f"cnt={self.counter}  "
            f"time={self.timestamp.isoformat()}  "
            f"hash={self.receipt_hash[:12]}…)"
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TransactionReceipt":
        """Parse a receipt from its binary representation."""
        if len(data) < _HEADER_LEN + 8:  # min sig ~8 bytes
            raise ValueError(
                f"Receipt too short: {len(data)} bytes (min {_HEADER_LEN + 8})"
            )

        version = data[_VERSION_OFF]
        if version != 1:
            raise ValueError(f"Unsupported receipt version: {version}")

        sender = data[_SENDER_OFF : _SENDER_OFF + 33]
        receiver = data[_RECEIVER_OFF : _RECEIVER_OFF + 33]
        amount = struct.unpack_from(">I", data, _AMOUNT_OFF)[0]
        counter = struct.unpack_from(">I", data, _COUNTER_OFF)[0]
        timestamp = struct.unpack_from(">Q", data, _TIMESTAMP_OFF)[0]
        signature = data[_SIG_OFF:]

        return cls(
            version=version,
            sender_pubkey=sender,
            receiver_pubkey=receiver,
            amount_cents=amount,
            counter=counter,
            timestamp_ms=timestamp,
            signature=signature,
            raw=bytes(data),
        )

    def to_dict(self) -> dict:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "version": self.version,
            "sender_pubkey": self.sender_pubkey.hex(),
            "receiver_pubkey": self.receiver_pubkey.hex(),
            "amount_cents": self.amount_cents,
            "amount_euro": self.amount_euro,
            "counter": self.counter,
            "timestamp_ms": self.timestamp_ms,
            "timestamp_iso": self.timestamp.isoformat(),
            "signature": self.signature.hex(),
            "receipt_hash": self.receipt_hash,
        }
