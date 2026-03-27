"""
AEGIS Offline Payments — Secure Element Simulator
===================================================

A pure-Python simulation of the Java Card Secure Element applet,
allowing development and testing without physical NFC hardware.

This simulator faithfully reproduces:
    • ECDSA key generation and signing (secp256k1)
    • Balance and counter management
    • PIN verification
    • Receipt generation and validation
    • All APDU command/response flows
"""

from __future__ import annotations

import struct
import hashlib
import time
from typing import Optional

try:
    from ecdsa import SECP256k1, SigningKey, VerifyingKey
    from ecdsa.util import sigencode_der, sigdecode_der
except ImportError:
    raise ImportError(
        "The 'ecdsa' library is required for the simulator.\n"
        "Install with: pip install ecdsa"
    )

import sys
import os

# Add host-sdk to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host-sdk"))

from aegis_se.apdu import (
    CLA_AEGIS,
    INS_GET_VERSION, INS_GET_BALANCE, INS_GET_COUNTER,
    INS_GET_PUBLIC_KEY, INS_INITIATE_PAYMENT, INS_RECEIVE_PAYMENT,
    INS_GET_LAST_RECEIPT, INS_LOAD_BALANCE, INS_VERIFY_PIN,
    INS_GENERATE_KEYS, SW_OK,
)
from aegis_se.secure_element import SETransport


# ── Status words ─────────────────────────────────────────────────
SW_OK_BYTES = struct.pack(">H", 0x9000)
SW_INSUFFICIENT_FUNDS = struct.pack(">H", 0x6985)
SW_INVALID_AMOUNT = struct.pack(">H", 0x6A80)
SW_PIN_REQUIRED = struct.pack(">H", 0x6982)
SW_WRONG_LENGTH = struct.pack(">H", 0x6700)
SW_COUNTER_OVERFLOW = struct.pack(">H", 0x6A84)
SW_SIGNATURE_INVALID = struct.pack(">H", 0x6988)
SW_CLA_NOT_SUPPORTED = struct.pack(">H", 0x6E00)
SW_INS_NOT_SUPPORTED = struct.pack(">H", 0x6D00)
SW_CONDITIONS_NOT_MET = struct.pack(">H", 0x6985)
SW_KEYS_NOT_INIT = struct.pack(">H", 0x6985)

# ── Limits ───────────────────────────────────────────────────────
MAX_SINGLE_PAYMENT = 50000   # 500.00 €
MAX_BALANCE = 300000         # 3000.00 €
PIN_MAX_RETRIES = 3
PIN_LENGTH = 6
DEFAULT_PIN = b"000000"

# Receipt layout
RECEIPT_VERSION = 0x01
PUBKEY_COMPRESSED_LEN = 33
HEADER_LEN = 83  # 1 + 33 + 33 + 4 + 4 + 8


class SimulatedSE:
    """
    Pure-Python Secure Element simulator.

    Maintains all state that would live inside a real SE chip:
    key pair, balance, counter, PIN, and last receipt.
    """

    def __init__(self, name: str = "SE"):
        self.name = name
        self._signing_key: Optional[SigningKey] = None
        self._verifying_key: Optional[VerifyingKey] = None
        self._balance: int = 0          # euro-cents
        self._counter: int = 0          # monotonic
        self._pin: bytes = DEFAULT_PIN
        self._pin_retries: int = PIN_MAX_RETRIES
        self._pin_validated: bool = False
        self._last_receipt: bytes = b""

    # ── Key management ───────────────────────────────────────────

    def generate_keys(self) -> bytes:
        """Generate a fresh secp256k1 key pair. Returns compressed pubkey."""
        self._signing_key = SigningKey.generate(curve=SECP256k1)
        self._verifying_key = self._signing_key.get_verifying_key()
        return self.get_compressed_pubkey()

    @property
    def has_keys(self) -> bool:
        return self._signing_key is not None

    def get_compressed_pubkey(self) -> bytes:
        """Return 33-byte compressed public key."""
        if not self.has_keys:
            raise RuntimeError("Keys not initialized")
        # Uncompressed: 64 bytes (x || y)
        raw = self._verifying_key.to_string()
        x = raw[:32]
        y = raw[32:]
        prefix = b"\x02" if y[-1] % 2 == 0 else b"\x03"
        return prefix + x

    def get_uncompressed_pubkey(self) -> bytes:
        """Return 65-byte uncompressed public key (04 || x || y)."""
        if not self.has_keys:
            raise RuntimeError("Keys not initialized")
        return b"\x04" + self._verifying_key.to_string()

    # ── Balance / counter ────────────────────────────────────────

    @property
    def balance(self) -> int:
        return self._balance

    @property
    def counter(self) -> int:
        return self._counter

    # ── Signing ──────────────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        """Sign data with the SE private key (DER-encoded ECDSA)."""
        if not self.has_keys:
            raise RuntimeError("Keys not initialized")
        return self._signing_key.sign_deterministic(
            data, hashfunc=hashlib.sha256, sigencode=sigencode_der
        )

    def verify(self, pubkey_uncompressed: bytes, data: bytes,
               signature: bytes) -> bool:
        """Verify an ECDSA signature with an external public key."""
        try:
            # Remove the 0x04 prefix
            raw_key = pubkey_uncompressed[1:]
            vk = VerifyingKey.from_string(raw_key, curve=SECP256k1)
            vk.verify(signature, data, hashfunc=hashlib.sha256,
                      sigdecode=sigdecode_der)
            return True
        except Exception:
            return False

    # ── APDU command processing ──────────────────────────────────

    def process_apdu(self, command: bytes) -> bytes:
        """
        Process a single APDU command and return the response.

        Parameters
        ----------
        command : bytes
            Full APDU command bytes.

        Returns
        -------
        bytes
            Response data + SW1 + SW2.
        """
        if len(command) < 4:
            return SW_WRONG_LENGTH

        cla = command[0]
        ins = command[1]
        # p1 = command[2]
        # p2 = command[3]

        if cla != CLA_AEGIS:
            return SW_CLA_NOT_SUPPORTED

        # Extract data field if present
        data = b""
        if len(command) > 5:
            lc = command[4]
            data = command[5 : 5 + lc]

        handlers = {
            INS_GET_VERSION: self._cmd_get_version,
            INS_GET_BALANCE: self._cmd_get_balance,
            INS_GET_COUNTER: self._cmd_get_counter,
            INS_GET_PUBLIC_KEY: self._cmd_get_public_key,
            INS_INITIATE_PAYMENT: self._cmd_initiate_payment,
            INS_RECEIVE_PAYMENT: self._cmd_receive_payment,
            INS_GET_LAST_RECEIPT: self._cmd_get_last_receipt,
            INS_LOAD_BALANCE: self._cmd_load_balance,
            INS_VERIFY_PIN: self._cmd_verify_pin,
            INS_GENERATE_KEYS: self._cmd_generate_keys,
        }

        handler = handlers.get(ins)
        if handler is None:
            return SW_INS_NOT_SUPPORTED

        return handler(data)

    # ── Command implementations ──────────────────────────────────

    def _cmd_get_version(self, data: bytes) -> bytes:
        return bytes([1, 0, 0]) + SW_OK_BYTES

    def _cmd_get_balance(self, data: bytes) -> bytes:
        return struct.pack(">I", self._balance) + SW_OK_BYTES

    def _cmd_get_counter(self, data: bytes) -> bytes:
        return struct.pack(">I", self._counter) + SW_OK_BYTES

    def _cmd_get_public_key(self, data: bytes) -> bytes:
        if not self.has_keys:
            return SW_KEYS_NOT_INIT
        return self.get_compressed_pubkey() + SW_OK_BYTES

    def _cmd_initiate_payment(self, data: bytes) -> bytes:
        if not self.has_keys:
            return SW_KEYS_NOT_INIT
        if len(data) != 45:
            return SW_WRONG_LENGTH

        receiver_pubkey = data[0:33]
        amount = struct.unpack(">I", data[33:37])[0]
        timestamp = data[37:45]

        # Validate
        if amount <= 0 or amount > MAX_SINGLE_PAYMENT:
            return SW_INVALID_AMOUNT
        if self._balance < amount:
            return SW_INSUFFICIENT_FUNDS

        # Build receipt header
        next_counter = self._counter + 1
        header = (
            bytes([RECEIPT_VERSION])
            + self.get_compressed_pubkey()
            + receiver_pubkey
            + struct.pack(">I", amount)
            + struct.pack(">I", next_counter)
            + timestamp
        )
        assert len(header) == HEADER_LEN

        # Sign
        signature = self.sign(header)
        receipt = header + signature

        # Atomic state update
        self._balance -= amount
        self._counter = next_counter
        self._last_receipt = receipt

        return receipt + SW_OK_BYTES

    def _cmd_receive_payment(self, data: bytes) -> bytes:
        if len(data) < 65 + HEADER_LEN + 8:
            return SW_WRONG_LENGTH

        sender_pubkey_uncompressed = data[0:65]
        receipt = data[65:]

        header = receipt[:HEADER_LEN]
        signature = receipt[HEADER_LEN:]

        # Verify signature
        if not self.verify(sender_pubkey_uncompressed, header, signature):
            return SW_SIGNATURE_INVALID

        # Extract amount
        amount = struct.unpack_from(">I", receipt, 67)[0]

        if amount <= 0 or amount > MAX_SINGLE_PAYMENT:
            return SW_INVALID_AMOUNT

        new_balance = self._balance + amount
        if new_balance > MAX_BALANCE:
            return SW_CONDITIONS_NOT_MET

        # Credit
        self._balance += amount
        self._counter += 1
        self._last_receipt = receipt

        return SW_OK_BYTES

    def _cmd_get_last_receipt(self, data: bytes) -> bytes:
        return self._last_receipt + SW_OK_BYTES

    def _cmd_load_balance(self, data: bytes) -> bytes:
        if not self._pin_validated:
            return SW_PIN_REQUIRED
        if len(data) != 4:
            return SW_WRONG_LENGTH

        amount = struct.unpack(">I", data)[0]
        if amount <= 0:
            return SW_INVALID_AMOUNT

        new_balance = self._balance + amount
        if new_balance > MAX_BALANCE:
            return SW_CONDITIONS_NOT_MET

        self._balance += amount
        return SW_OK_BYTES

    def _cmd_verify_pin(self, data: bytes) -> bytes:
        if len(data) != PIN_LENGTH:
            return SW_WRONG_LENGTH

        if data == self._pin:
            self._pin_validated = True
            self._pin_retries = PIN_MAX_RETRIES
            return SW_OK_BYTES
        else:
            self._pin_retries -= 1
            sw = 0x63C0 | self._pin_retries
            return struct.pack(">H", sw)

    def _cmd_generate_keys(self, data: bytes) -> bytes:
        pubkey = self.generate_keys()
        return pubkey + SW_OK_BYTES


class SimulatedTransport(SETransport):
    """
    SETransport implementation that routes APDUs to a SimulatedSE.

    Usage::

        sim = SimulatedSE("Alice")
        transport = SimulatedTransport(sim)
        se = SecureElement(transport)
        se.connect()
        se.generate_keys()
    """

    def __init__(self, simulated_se: SimulatedSE):
        self._se = simulated_se
        self._connected = False

    @property
    def se(self) -> SimulatedSE:
        """Access the underlying SimulatedSE (for testing)."""
        return self._se

    def connect(self) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def transmit(self, command: bytes) -> bytes:
        if not self._connected:
            raise ConnectionError("Transport not connected")
        return self._se.process_apdu(command)
