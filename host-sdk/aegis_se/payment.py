"""
AEGIS Offline Payments — High-Level Payment Protocol
=====================================================

Orchestrates the full P2P offline payment flow between two
SecureElement instances (sender and receiver), handling the
multi-step NFC communication.

Flow:
    1. Sender SE:  INITIATE_PAYMENT  →  signed receipt
    2. Receipt transferred via NFC to receiver's host
    3. Receiver SE: RECEIVE_PAYMENT  →  validates & credits
    4. Both sides store the receipt for later sync
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from .secure_element import SecureElement
from .transaction import TransactionReceipt
from .exceptions import AegisError


@dataclass
class PaymentResult:
    """Result of a completed P2P payment."""

    success: bool
    receipt: Optional[TransactionReceipt] = None
    sender_new_balance: Optional[int] = None
    receiver_new_balance: Optional[int] = None
    error: Optional[str] = None

    @property
    def amount_euro(self) -> float:
        if self.receipt:
            return self.receipt.amount_euro
        return 0.0


class PaymentProtocol:
    """
    Executes the AEGIS offline P2P payment protocol.

    Usage::

        protocol = PaymentProtocol(sender_se, receiver_se)
        result = protocol.pay(amount_cents=2500)  # 25.00 €
        print(result)
    """

    def __init__(self, sender: SecureElement, receiver: SecureElement):
        self.sender = sender
        self.receiver = receiver

    def pay(self, amount_cents: int,
            timestamp_ms: Optional[int] = None) -> PaymentResult:
        """
        Execute a full P2P payment.

        Parameters
        ----------
        amount_cents : int
            Amount in euro-cents (e.g. 2500 = 25.00 €).
        timestamp_ms : int, optional
            Unix timestamp in milliseconds.  Defaults to now.

        Returns
        -------
        PaymentResult
        """
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000)

        try:
            # Step 1 — Get receiver's public key
            receiver_pubkey = self.receiver.get_public_key()

            # Step 2 — Sender initiates payment (debit + sign)
            receipt_bytes = self.sender.initiate_payment(
                receiver_pubkey=receiver_pubkey,
                amount_cents=amount_cents,
                timestamp_ms=timestamp_ms,
            )

            # Step 3 — Get sender's uncompressed public key for verification
            # In a real implementation, the sender's host would provide this
            # from the SE or derive it.  For the protocol, we need the
            # uncompressed key.  The sender transmits it alongside the receipt.
            sender_pubkey_compressed = self.sender.get_public_key()

            # The receiver needs the uncompressed key for ECDSA verification.
            # In the simulator, we handle this internally.
            # For real hardware, the sender host reads the uncompressed key
            # from its SE and transmits it via NFC.
            sender_pubkey_uncompressed = self._get_uncompressed_key(
                sender_pubkey_compressed
            )

            # Step 4 — Receiver validates and credits
            self.receiver.receive_payment(
                sender_pubkey_uncompressed=sender_pubkey_uncompressed,
                signed_receipt=receipt_bytes,
            )

            # Step 5 — Parse the receipt
            receipt = TransactionReceipt.from_bytes(receipt_bytes)

            return PaymentResult(
                success=True,
                receipt=receipt,
                sender_new_balance=self.sender.get_balance(),
                receiver_new_balance=self.receiver.get_balance(),
            )

        except AegisError as e:
            return PaymentResult(success=False, error=str(e))
        except Exception as e:
            return PaymentResult(success=False, error=f"Unexpected: {e}")

    def _get_uncompressed_key(self, compressed: bytes) -> bytes:
        """
        Decompress a secp256k1 compressed public key.

        In production this would use the SE itself or a crypto library.
        For the simulator, this is handled by the simulated SE transport.
        """
        # Attempt using the ecdsa library if available
        try:
            from ecdsa import SECP256k1, VerifyingKey
            from ecdsa.util import sigdecode_der

            # Compressed key: 02/03 + 32 bytes X
            prefix = compressed[0]
            x = int.from_bytes(compressed[1:33], "big")

            # Compute y from curve equation: y² = x³ + 7  (mod p)
            p = SECP256k1.curve.p()
            y_sq = (pow(x, 3, p) + 7) % p
            y = pow(y_sq, (p + 1) // 4, p)

            if (y % 2 == 0) != (prefix == 0x02):
                y = p - y

            # Build uncompressed: 04 || x || y
            return (
                b"\x04"
                + x.to_bytes(32, "big")
                + y.to_bytes(32, "big")
            )
        except ImportError:
            # Fallback: the simulator transport provides its own mechanism
            raise AegisError(
                "Cannot decompress key: 'ecdsa' library not installed. "
                "Install with: pip install ecdsa"
            )
